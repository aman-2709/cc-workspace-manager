//! M3 over the HTTP API (in-process router, temp database, synthetic session files): the sessions
//! endpoint with on-demand prompts and resume commands, continuation links, privacy mode, the
//! Settings round trip, "Store prompt text" and clearing the session index (REQUIREMENTS.md §7,
//! §8, §10, §12).

mod common;

use cc_workspace_manager::claude::parse::{Aggregate, Checkpoint};
use cc_workspace_manager::db::writer::SessionStore;
use cc_workspace_manager::git::parse::Commit;
use cc_workspace_manager::git::{Info, State};
use common::{code, env, json, Env, START};
use std::path::Path;

const S1: &str = "aaaaaaaa-1111-4111-8111-111111111111";
const S2: &str = "bbbbbbbb-2222-4222-8222-222222222222";
const S3: &str = "cccccccc-3333-4333-8333-333333333333";

fn line(ty: &str, sid: &str, ts: &str, extra: &str) -> String {
    format!(r#"{{"type":"{ty}","sessionId":"{sid}","timestamp":"{ts}"{extra}}}"#)
}

fn prompt(sid: &str, ts: &str, text: &str) -> String {
    line(
        "user",
        sid,
        ts,
        &format!(
            r#","promptSource":"typed","message":{{"role":"user","content":{}}}"#,
            serde_json::to_string(text).unwrap()
        ),
    )
}

fn tool_result(sid: &str, ts: &str) -> String {
    line(
        "user",
        sid,
        ts,
        r#","toolUseResult":{"stdout":"CANARY-TOOL-OUTPUT"},"message":{"role":"user","content":[{"type":"tool_result","content":"CANARY-TOOL-OUTPUT"}]}"#,
    )
}

/// One session to add: its id, project, first cwd, optional title and continuation, and lines.
struct NewSession<'a> {
    id: &'a str,
    project: &'a str,
    cwd: &'a str,
    title: Option<&'a str>,
    continued_in: Option<&'a str>,
    lines: Vec<String>,
}

/// Write a session file and store its row (as the ingest would).
async fn add_session(e: &Env, dir: &Path, s: NewSession<'_>) {
    let file = dir.join(format!("{}.jsonl", s.id));
    std::fs::write(&file, s.lines.join("\n") + "\n").unwrap();
    e.writer
        .store_sessions(vec![SessionStore {
            id: s.id.into(),
            file_path: file.to_string_lossy().into_owned(),
            project_id: Some(s.project.into()),
            unassigned: None,
            aggregate: Aggregate {
                first_cwd: Some(s.cwd.into()),
                last_cwd: Some(format!("{}/sub", s.cwd)),
                started_at: Some(START - 600),
                last_activity_at: Some(START - 60),
                title: s.title.map(str::to_string),
                continued_in: s.continued_in.map(str::to_string),
                ..Aggregate::default()
            },
            checkpoint: Checkpoint::default(),
        }])
        .await
        .unwrap();
}

async fn project_id(e: &Env, token: &str, name: &str) -> String {
    let (_, v) = json(e.get("/api/v1/projects?sort=name", Some(token)).await).await;
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn the_last_prompt_is_read_on_demand_and_the_resume_command_uses_the_first_cwd() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app"]).await;
    let id = project_id(&e, &token, "app").await;
    let t = common::tempdir();
    let cwd_dir = t.path().join("it's a dir");
    std::fs::create_dir(&cwd_dir).unwrap();
    let cwd = cwd_dir.to_str().unwrap();
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &id,
            cwd,
            title: None,
            continued_in: None,
            lines: vec![
                prompt(S1, "2026-01-01T10:00:00.000Z", "CANARY first prompt"),
                tool_result(S1, "2026-01-01T10:01:00.000Z"),
                prompt(
                    S1,
                    "2026-01-01T10:02:00.000Z",
                    "CANARY last prompt with token=supersecret1",
                ),
                tool_result(S1, "2026-01-01T10:03:00.000Z"),
                line(
                    "last-prompt",
                    S1,
                    "2026-01-01T10:04:00.000Z",
                    r#","lastPrompt":"CANARY-LAST-PROMPT-RECORD""#,
                ),
            ],
        },
    )
    .await;

    let (s, v) = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), Some(&token))
            .await,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["total"], 1);
    let item = &v["items"][0];
    assert_eq!(item["id"], S1);
    assert_eq!(item["last_prompt"]["state"], "found");
    assert_eq!(
        item["last_prompt"]["text"], "CANARY last prompt with token=[REDACTED]",
        "redacted, taken from the user record and never from last-prompt"
    );
    assert_eq!(
        item["first_prompt"]["text"], "CANARY first prompt",
        "no title: first prompt"
    );
    assert_eq!(item["title"], serde_json::Value::Null);
    assert_eq!(item["duration_s"], 540);
    assert_eq!(item["cwd_changed"], true);
    let expected = format!(
        "cd -- '{}' && claude --resume {S1}",
        cwd.replace('\'', r"'\''")
    );
    assert_eq!(item["resume"]["command"], expected.as_str());
    assert_eq!(item["resume"]["cwd"], cwd);
    let warnings = item["resume"]["warnings"].as_array().unwrap();
    assert!(
        warnings.contains(&"claude_unverified".into()),
        "{warnings:?}"
    );
    assert!(!warnings.contains(&"cwd_missing".into()), "{warnings:?}");

    // Nothing of the prompts was stored ("Store prompt text" is off by default).
    let db = e.db_bytes();
    for canary in [
        "CANARY first prompt",
        "CANARY last prompt",
        "supersecret1",
        "CANARY-TOOL-OUTPUT",
    ] {
        assert!(
            !db.windows(canary.len()).any(|w| w == canary.as_bytes()),
            "{canary} reached the database"
        );
    }

    // The card summary.
    let (_, v) = json(e.get("/api/v1/projects", Some(&token)).await).await;
    let p = &v["items"][0];
    assert_eq!(p["sessions"]["count"], 1);
    assert_eq!(p["sessions"]["latest"]["last_activity_at"], START - 60);
    assert_eq!(
        p["sessions"]["latest"]["title_source"],
        serde_json::Value::Null
    );
    let (_, st) = json(e.get("/api/v1/stats", Some(&token)).await).await;
    assert_eq!(st["total_sessions"], 1);

    // Validation.
    for bad in ["limit=0", "limit=11", "limit=x", "privacy=maybe", "other=1"] {
        let (s, v) = json(
            e.get(
                &format!("/api/v1/projects/{id}/sessions?{bad}"),
                Some(&token),
            )
            .await,
        )
        .await;
        assert_eq!((s, code(&v)), (400, "invalid_argument"), "{bad}");
    }
    let (s, _) = json(
        e.get(
            &format!("/api/v1/projects/{}/sessions", "0".repeat(32)),
            Some(&token),
        )
        .await,
    )
    .await;
    assert_eq!(s, 404);
    let (s, _) = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), None)
            .await,
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn a_continued_session_resumes_its_latest_continuation_from_that_sessions_first_cwd() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app", "other"]).await;
    let app = project_id(&e, &token, "app").await;
    let other = project_id(&e, &token, "other").await;
    let t = common::tempdir();
    let (d1, d3) = (t.path().join("one"), t.path().join("three"));
    std::fs::create_dir(&d1).unwrap();
    std::fs::create_dir(&d3).unwrap();
    let p = |sid: &str| vec![prompt(sid, "2026-01-01T10:00:00.000Z", "x")];
    // S1 -> S2 -> S3 (S3 in another project), titles recorded.
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &app,
            cwd: d1.to_str().unwrap(),
            title: Some("One"),
            continued_in: Some(S2),
            lines: p(S1),
        },
    )
    .await;
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S2,
            project: &other,
            cwd: "/nonexistent/two",
            title: Some("Two"),
            continued_in: Some(S3),
            lines: p(S2),
        },
    )
    .await;
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S3,
            project: &other,
            cwd: d3.to_str().unwrap(),
            title: Some("Three"),
            continued_in: None,
            lines: p(S3),
        },
    )
    .await;
    let (_, v) = json(
        e.get(
            &format!("/api/v1/projects/{app}/sessions?limit=10"),
            Some(&token),
        )
        .await,
    )
    .await;
    let r = &v["items"][0]["resume"];
    assert_eq!(r["session_id"], S3);
    assert_eq!(r["via_continuation"], true);
    assert_eq!(r["cwd"], d3.to_str().unwrap());
    assert_eq!(v["items"][0]["title"], "One");
    assert_eq!(v["items"][0]["title_source"], "ai_title");
    assert_eq!(
        v["items"][0]["first_prompt"],
        serde_json::Value::Null,
        "titled: no first prompt"
    );

    // A continuation that is not in the index: resume the session itself, with a warning.
    let (_, v) = json(
        e.get(
            &format!("/api/v1/projects/{other}/sessions?limit=10"),
            Some(&token),
        )
        .await,
    )
    .await;
    let two = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == S2)
        .unwrap();
    assert_eq!(two["resume"]["session_id"], S3);
    let lone = "dddddddd-4444-4444-8444-444444444444";
    add_session(
        &e,
        t.path(),
        NewSession {
            id: lone,
            project: &other,
            cwd: "/nonexistent/lone",
            title: None,
            continued_in: Some("eeeeeeee-5555-4555-8555-555555555555"),
            lines: p(lone),
        },
    )
    .await;
    let (_, v) = json(
        e.get(
            &format!("/api/v1/projects/{other}/sessions?limit=10"),
            Some(&token),
        )
        .await,
    )
    .await;
    let l = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == lone)
        .unwrap();
    assert_eq!(l["resume"]["session_id"], lone);
    let w = l["resume"]["warnings"].as_array().unwrap();
    assert!(w.contains(&"continuation_not_indexed".into()), "{w:?}");
    assert!(w.contains(&"cwd_missing".into()), "{w:?}");
}

#[tokio::test]
async fn privacy_mode_removes_paths_names_urls_titles_prompts_and_commands_from_every_payload() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["CANARYNAME-proj"]).await;
    let id = project_id(&e, &token, "CANARYNAME-proj").await;
    let mut info = Info::only(State::Ok);
    info.branch = Some("main".into());
    info.remote_url = Some("https://example.invalid/CANARY-REMOTE.git".into());
    info.head = Some(Commit {
        hash: "a".repeat(40),
        subject: "Subject stays".into(),
        author: "CANARY Author Name".into(),
        time: START,
    });
    e.writer.store_git(&id, info, START).await.unwrap();
    let t = common::tempdir();
    let cwd = t.path().join("CANARY-CWD");
    std::fs::create_dir(&cwd).unwrap();
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &id,
            cwd: cwd.to_str().unwrap(),
            title: Some("CANARY TITLE"),
            continued_in: None,
            lines: vec![prompt(S1, "2026-01-01T10:00:00.000Z", "CANARY PROMPT")],
        },
    )
    .await;
    let canaries = [
        "/home/u",
        "~/CANARYNAME",
        "CANARY Author Name",
        "CANARY-REMOTE",
        "CANARY TITLE",
        "CANARY PROMPT",
        "CANARY-CWD",
        "claude --resume",
    ];
    let private_get = |path: String| {
        let e = &e;
        let token = token.clone();
        async move {
            let (s, v) = json(e.get(&path, Some(&token)).await).await;
            assert_eq!(s, 200, "{path}: {v}");
            v
        }
    };
    for path in [
        "/api/v1/projects?privacy=1".to_string(),
        format!("/api/v1/projects/{id}?privacy=1"),
        format!("/api/v1/projects/{id}/sessions?privacy=1"),
        "/api/v1/discovery/status?privacy=1".to_string(),
        "/api/v1/service/status?privacy=1".to_string(),
        "/api/v1/settings?privacy=1".to_string(),
    ] {
        let text = private_get(path.clone()).await.to_string();
        for c in canaries {
            assert!(!text.contains(c), "{path} leaks {c}: {text}");
        }
    }
    // The same fields are there without privacy mode (the test would prove nothing otherwise).
    let full = format!(
        "{}{}{}",
        private_get("/api/v1/projects".into()).await,
        private_get(format!("/api/v1/projects/{id}")).await,
        private_get(format!("/api/v1/projects/{id}/sessions")).await
    );
    for c in canaries.iter().filter(|c| !c.starts_with('~')) {
        assert!(full.contains(c), "{c} missing without privacy mode");
    }
    // The name is kept (anonymization is §18), the commit subject too.
    let v = private_get(format!("/api/v1/projects/{id}?privacy=1")).await;
    assert_eq!(v["name"], "CANARYNAME-proj");
    assert_eq!(v["git_detail"]["head"]["subject"], "Subject stays");
    assert!(v.get("path").is_none() && v.get("display_path").is_none());
    // Search does not match hidden fields (the path) in privacy mode.
    let (_, hit) = json(e.get("/api/v1/projects?q=home", Some(&token)).await).await;
    let (_, miss) = json(
        e.get("/api/v1/projects?q=home&privacy=1", Some(&token))
            .await,
    )
    .await;
    assert_eq!(
        (hit["total"].as_u64(), miss["total"].as_u64()),
        (Some(1), Some(0))
    );
    let (_, by_name) = json(
        e.get("/api/v1/projects?q=CANARYNAME&privacy=1", Some(&token))
            .await,
    )
    .await;
    assert_eq!(by_name["total"], 1);

    // Live updates: privacy-mode clients receive the redacted variant.
    let mut rx = e.service.hub.subscribe();
    let mut batch = cc_workspace_manager::events::Batch::default();
    batch.add(cc_workspace_manager::events::Change::Project(id.clone()));
    batch.add(cc_workspace_manager::events::Change::Status);
    e.service.publish(batch).await.unwrap();
    let mut seen = 0;
    while let Ok(msg) = rx.try_recv() {
        let private = msg.for_client(true);
        for c in canaries {
            assert!(!private.contains(c), "a live update leaks {c}: {private}");
        }
        seen += 1;
    }
    assert!(seen >= 2, "project and discovery events were published");
}

#[tokio::test]
async fn settings_round_trip_report_restarts_validate_and_apply_live_values() {
    let e = env().await;
    let token = e.login().await;
    let (s, v) = json(e.get("/api/v1/settings", Some(&token)).await).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["config"]["discovery"]["scan_interval_secs"], 600);
    assert_eq!(v["restart_required"], serde_json::json!([]));
    assert!(v["effective"]["default_exclusions"]
        .as_array()
        .unwrap()
        .contains(&"_build".into()));

    // A live value: saved, applied, no restart.
    let (s, v) = json(
        e.send_json(
            "PUT",
            "/api/v1/settings",
            &token,
            r#"{"discovery":{"scan_interval_secs":120,"full_scan":true},"ui":{"theme":"dark"}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["restart_required"], serde_json::json!([]));
    let saved = cc_workspace_manager::config::Config::parse(
        &std::fs::read_to_string(&e.config_path).unwrap(),
    )
    .unwrap();
    assert_eq!(saved.discovery.scan_interval_secs, 120);
    assert!(saved.discovery.full_scan);
    assert_eq!(saved.ui.theme, "dark");
    assert_eq!(
        saved.discovery.max_depth, 10,
        "untouched keys keep their values"
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&e.config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // Restart-only values are saved and listed until the daemon restarts.
    let (s, v) = json(
        e.send_json(
            "PUT",
            "/api/v1/settings",
            &token,
            r#"{"server":{"port":9999},"discovery":{"roots":["/srv/code"]}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v["restart_required"],
        serde_json::json!(["server.port", "discovery.roots"])
    );
    let (_, v) = json(e.get("/api/v1/settings", Some(&token)).await).await;
    assert_eq!(v["config"]["server"]["port"], 9999);

    // Invalid input changes nothing.
    let before = std::fs::read(&e.config_path).unwrap();
    for bad in [
        r#"{"discovery":{"scan_interval_secs":5}}"#,
        r#"{"discovery":{"roots":["relative"]}}"#,
        r#"{"bogus":1}"#,
        r#"{"discovery":{"follow_symlinks":true}}"#,
        r#"{"ui":{"theme":"blue"}}"#,
        r#"{"server":{"port":80}}"#,
        r#"[1,2]"#,
        r#""text""#,
    ] {
        let (s, v) = json(e.send_json("PUT", "/api/v1/settings", &token, bad).await).await;
        assert_eq!((s, code(&v)), (400, "invalid_argument"), "{bad}: {v}");
    }
    assert_eq!(std::fs::read(&e.config_path).unwrap(), before);

    // State-changing: Origin required.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("host", format!("127.0.0.1:{}", common::PORT))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from("{}"))
        .unwrap();
    assert_eq!(e.send(req).await.status(), 403);
}

#[tokio::test]
async fn store_prompt_text_caches_redacted_prompts_and_turning_it_off_deletes_them() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app"]).await;
    let id = project_id(&e, &token, "app").await;
    let t = common::tempdir();
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &id,
            cwd: "/nonexistent",
            title: Some("T"),
            continued_in: None,
            lines: vec![prompt(
                S1,
                "2026-01-01T10:00:00.000Z",
                "CANARY-CACHED password=pw123456",
            )],
        },
    )
    .await;
    let has = |e: &Env, s: &str| e.db_bytes().windows(s.len()).any(|w| w == s.as_bytes());
    let (s, _) = json(
        e.send_json(
            "PUT",
            "/api/v1/settings",
            &token,
            r#"{"sessions":{"store_prompt_text":true}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(s, 200);
    let _ = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), Some(&token))
            .await,
    )
    .await;
    e.writer.flush().await.unwrap();
    assert!(has(&e, "CANARY-CACHED"), "cached while the setting is on");
    assert!(!has(&e, "pw123456"), "only the redacted text is cached");
    // Served from the cache even when the file is gone.
    std::fs::remove_file(t.path().join(format!("{S1}.jsonl"))).unwrap();
    let (_, v) = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), Some(&token))
            .await,
    )
    .await;
    assert_eq!(
        v["items"][0]["last_prompt"]["text"],
        "CANARY-CACHED password=[REDACTED]"
    );
    let (s, _) = json(
        e.send_json(
            "PUT",
            "/api/v1/settings",
            &token,
            r#"{"sessions":{"store_prompt_text":false}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(s, 200);
    e.writer.flush().await.unwrap();
    let (_, v) = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), Some(&token))
            .await,
    )
    .await;
    assert_eq!(
        v["items"][0]["last_prompt"]["state"], "unreadable",
        "the file is gone, the cache too"
    );
    // The deleted text may linger in free pages until SQLite reuses them; it is never read.
    let n: i64 = rusqlite::Connection::open(&e.db)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sessions WHERE prompt_text IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn clearing_the_session_index_keeps_projects_and_needs_origin() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app"]).await;
    let id = project_id(&e, &token, "app").await;
    let t = common::tempdir();
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &id,
            cwd: "/x",
            title: None,
            continued_in: None,
            lines: vec![prompt(S1, "2026-01-01T10:00:00.000Z", "p")],
        },
    )
    .await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/session-index/clear")
        .header("host", format!("127.0.0.1:{}", common::PORT))
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(e.send(req).await.status(), 403, "no Origin");
    let (s, v) = json(
        e.post("/api/v1/session-index/clear", Some(&token), "")
            .await,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["projects_affected"], 1);
    let (_, v) = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), Some(&token))
            .await,
    )
    .await;
    assert_eq!(
        (v["total"].as_u64(), v["items"].as_array().unwrap().len()),
        (Some(0), 0)
    );
    let (_, v) = json(e.get("/api/v1/projects", Some(&token)).await).await;
    assert_eq!(v["total"], 1, "the project stays");
    assert_eq!(v["items"][0]["sessions"]["count"], 0);
    assert!(
        t.path().join(format!("{S1}.jsonl")).is_file(),
        "the session file is untouched"
    );
}

#[tokio::test]
async fn has_sessions_filters_and_sort_by_session_orders_with_unknown_last() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["a-none", "b-old", "c-new"]).await;
    let (b, c) = (
        project_id(&e, &token, "b-old").await,
        project_id(&e, &token, "c-new").await,
    );
    let t = common::tempdir();
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &b,
            cwd: "/x",
            title: None,
            continued_in: None,
            lines: vec![],
        },
    )
    .await;
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S2,
            project: &c,
            cwd: "/x",
            title: None,
            continued_in: None,
            lines: vec![],
        },
    )
    .await;
    // Make c's session the newest.
    let mut store = SessionStore {
        id: S2.into(),
        file_path: t
            .path()
            .join(format!("{S2}.jsonl"))
            .to_string_lossy()
            .into_owned(),
        project_id: Some(c.clone()),
        unassigned: None,
        aggregate: Aggregate {
            last_activity_at: Some(START + 100),
            ..Aggregate::default()
        },
        checkpoint: Checkpoint::default(),
    };
    e.writer.store_sessions(vec![store.clone()]).await.unwrap();
    let names = |v: &serde_json::Value| -> Vec<String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    };
    let (_, v) = json(
        e.get("/api/v1/projects?has_sessions=1&sort=name", Some(&token))
            .await,
    )
    .await;
    assert_eq!(names(&v), ["b-old", "c-new"]);
    let (_, v) = json(e.get("/api/v1/projects?sort=session", Some(&token)).await).await;
    assert_eq!(names(&v), ["c-new", "b-old", "a-none"]);
    let (_, v) = json(
        e.get("/api/v1/projects?sort=session&order=asc", Some(&token))
            .await,
    )
    .await;
    assert_eq!(
        names(&v),
        ["b-old", "c-new", "a-none"],
        "unknown last in both orders"
    );
    // Keyset pagination over the session sort.
    let (_, p1) = json(
        e.get("/api/v1/projects?sort=session&limit=2", Some(&token))
            .await,
    )
    .await;
    let cursor = p1["next_cursor"].as_str().unwrap();
    let (_, p2) = json(
        e.get(
            &format!("/api/v1/projects?sort=session&limit=2&cursor={cursor}"),
            Some(&token),
        )
        .await,
    )
    .await;
    assert_eq!(names(&p2), ["a-none"]);
    // Moving a session to another project updates both summaries.
    store.project_id = Some(b.clone());
    e.writer.store_sessions(vec![store]).await.unwrap();
    let (_, v) = json(e.get("/api/v1/projects?has_sessions=1", Some(&token)).await).await;
    assert_eq!(names(&v), ["b-old"]);
}
