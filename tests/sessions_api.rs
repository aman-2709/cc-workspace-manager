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
async fn a_continued_session_resumes_its_latest_continuation_in_the_same_project_only() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app", "other"]).await;
    let app = project_id(&e, &token, "app").await;
    let other = project_id(&e, &token, "other").await;
    let t = common::tempdir();
    let (d1, d2, d3) = (
        t.path().join("one"),
        t.path().join("two"),
        t.path().join("three"),
    );
    for d in [&d1, &d2, &d3] {
        std::fs::create_dir(d).unwrap();
    }
    let p = |sid: &str| vec![prompt(sid, "2026-01-01T10:00:00.000Z", "x")];
    // S1 -> S2 (both in app) -> S3 (in another project), titles recorded.
    for (id, project, cwd, title, next) in [
        (S1, &app, &d1, "One", Some(S2)),
        (S2, &app, &d2, "Two", Some(S3)),
        (S3, &other, &d3, "Three", None),
    ] {
        add_session(
            &e,
            t.path(),
            NewSession {
                id,
                project,
                cwd: cwd.to_str().unwrap(),
                title: Some(title),
                continued_in: next,
                lines: p(id),
            },
        )
        .await;
    }
    let sessions = |project: String| {
        let (e, token) = (&e, token.clone());
        async move {
            let (_, v) = json(
                e.get(
                    &format!("/api/v1/projects/{project}/sessions?limit=10"),
                    Some(&token),
                )
                .await,
            )
            .await;
            v
        }
    };
    let v = sessions(app.clone()).await;
    let one = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == S1)
        .unwrap()
        .clone();
    let r = &one["resume"];
    assert_eq!(r["session_id"], S2, "followed within app, not into other");
    assert_eq!(r["via_continuation"], true);
    assert_eq!(
        r["cwd"],
        d2.to_str().unwrap(),
        "the continuation's first cwd"
    );
    assert_eq!(r["continuation_cwd"], d3.to_str().unwrap());
    let w = r["warnings"].as_array().unwrap();
    assert!(w.contains(&"continuation_other_project".into()), "{w:?}");
    assert_eq!(one["title"], "One");
    assert_eq!(one["title_source"], "ai_title");
    assert_eq!(
        one["first_prompt"],
        serde_json::Value::Null,
        "titled: no first prompt"
    );

    // A continuation into an unassigned session is not followed either.
    let unassigned = "ffffffff-6666-4666-8666-666666666666";
    let file = t.path().join(format!("{unassigned}.jsonl"));
    std::fs::write(&file, p(unassigned).join("\n") + "\n").unwrap();
    e.writer
        .store_sessions(vec![SessionStore {
            id: unassigned.into(),
            file_path: file.to_string_lossy().into_owned(),
            project_id: None,
            unassigned: Some("temporary"),
            aggregate: Aggregate {
                first_cwd: Some("/tmp/CANARY-PLANTED".into()),
                ..Aggregate::default()
            },
            checkpoint: Checkpoint::default(),
        }])
        .await
        .unwrap();
    let lone = "dddddddd-4444-4444-8444-444444444444";
    for (id, next) in [
        (lone, "eeeeeeee-5555-4555-8555-555555555555"),
        ("99999999-7777-4777-8777-777777777777", unassigned),
    ] {
        add_session(
            &e,
            t.path(),
            NewSession {
                id,
                project: &other,
                cwd: "/nonexistent/lone",
                title: None,
                continued_in: Some(next),
                lines: p(id),
            },
        )
        .await;
    }
    let v = sessions(other.clone()).await;
    let item = |id: &str| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == id)
            .unwrap()["resume"]
            .clone()
    };
    let l = item(lone);
    assert_eq!(l["session_id"], lone);
    let w = l["warnings"].as_array().unwrap();
    assert!(w.contains(&"continuation_not_indexed".into()), "{w:?}");
    assert!(w.contains(&"cwd_missing".into()), "{w:?}");
    let planted = item("99999999-7777-4777-8777-777777777777");
    assert_eq!(
        planted["session_id"],
        "99999999-7777-4777-8777-777777777777"
    );
    assert_eq!(planted["continuation_cwd"], "/tmp/CANARY-PLANTED");
    assert!(planted["warnings"]
        .as_array()
        .unwrap()
        .contains(&"continuation_unassigned".into()));
    let (_, private) = json(
        e.get(
            &format!("/api/v1/projects/{other}/sessions?limit=10&privacy=1"),
            Some(&token),
        )
        .await,
    )
    .await;
    assert!(!private.to_string().contains("CANARY-PLANTED"));
}

/// M3 security review, M1: a recorded cwd with terminal control characters gets no resume
/// command, a warning, and is shown escaped.
#[tokio::test]
async fn a_cwd_with_control_characters_gets_no_command_and_is_shown_escaped() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app"]).await;
    let id = project_id(&e, &token, "app").await;
    let t = common::tempdir();
    let hostile = "/home/u/x\u{15}touch /tmp/pwned\n";
    add_session(
        &e,
        t.path(),
        NewSession {
            id: S1,
            project: &id,
            cwd: hostile,
            title: None,
            continued_in: None,
            lines: vec![prompt(S1, "2026-01-01T10:00:00.000Z", "x")],
        },
    )
    .await;
    let (_, v) = json(
        e.get(&format!("/api/v1/projects/{id}/sessions"), Some(&token))
            .await,
    )
    .await;
    let item = &v["items"][0];
    let r = &item["resume"];
    assert!(r.get("command").is_none(), "{r}");
    assert!(r["warnings"]
        .as_array()
        .unwrap()
        .contains(&"cwd_unsafe_characters".into()));
    assert_eq!(r["cwd"], r"/home/u/x\x15touch /tmp/pwned\x0a");
    assert_eq!(item["first_cwd"], r"/home/u/x\x15touch /tmp/pwned\x0a");
    assert!(!v.to_string().contains('\u{15}'));
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
    // Deleted for real (secure_delete + a truncating WAL checkpoint, M3 review L6): not in the
    // database, WAL or SHM bytes either.
    assert!(
        !has(&e, "CANARY-CACHED"),
        "the deleted text lingers on disk"
    );
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
            cwd: "/x/CANARY-INDEXED-CWD",
            title: Some("CANARY-INDEXED-TITLE"),
            continued_in: None,
            lines: vec![prompt(S1, "2026-01-01T10:00:00.000Z", "p")],
        },
    )
    .await;
    let has = |e: &Env, s: &str| e.db_bytes().windows(s.len()).any(|w| w == s.as_bytes());
    assert!(
        has(&e, "CANARY-INDEXED-TITLE") && has(&e, "CANARY-INDEXED-CWD"),
        "indexed before the clear (the check below would prove nothing otherwise)"
    );
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
    for c in ["CANARY-INDEXED-TITLE", "CANARY-INDEXED-CWD"] {
        assert!(
            !has(&e, c),
            "{c} lingers in the database files after the clear"
        );
    }
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

async fn put_settings(e: &Env, token: &str, query: &str, body: &str) -> (u16, serde_json::Value) {
    json(
        e.send_json("PUT", &format!("/api/v1/settings{query}"), token, body)
            .await,
    )
    .await
}

/// M3 security review, M2: a save from a Settings form rendered earlier (it sends only what the
/// user changed there) cannot turn "Store prompt text" back on or revert other fields; saves
/// never lose each other.
#[tokio::test]
async fn a_stale_settings_form_cannot_re_enable_prompt_storage_or_revert_other_fields() {
    let e = env().await;
    let token = e.login().await;
    let (s, _) = put_settings(
        &e,
        &token,
        "",
        r#"{"sessions":{"store_prompt_text":true},"discovery":{"scan_interval_secs":120}}"#,
    )
    .await;
    assert_eq!(s, 200);
    // Tab A renders the form now (store on, 120 s). Tab B turns storage off and changes the
    // interval. Tab A then saves only the theme the user changed there.
    let (_, tab_a) = json(e.get("/api/v1/settings", Some(&token)).await).await;
    assert_eq!(tab_a["config"]["sessions"]["store_prompt_text"], true);
    let (s, _) = put_settings(
        &e,
        &token,
        "",
        r#"{"sessions":{"store_prompt_text":false},"discovery":{"scan_interval_secs":300}}"#,
    )
    .await;
    assert_eq!(s, 200);
    let (s, v) = put_settings(&e, &token, "", r#"{"ui":{"theme":"dark"}}"#).await;
    assert_eq!(s, 200, "{v}");
    let saved = cc_workspace_manager::config::Config::parse(
        &std::fs::read_to_string(&e.config_path).unwrap(),
    )
    .unwrap();
    assert!(!saved.sessions.store_prompt_text, "storage stays off");
    assert_eq!(
        saved.discovery.scan_interval_secs, 300,
        "tab B's value stays"
    );
    assert_eq!(saved.ui.theme, "dark");

    // Concurrent saves of different fields both survive (one lock from merge to apply).
    let mut tasks = Vec::new();
    for (i, body) in [
        r#"{"activity":{"inactive_after_days":8}}"#,
        r#"{"discovery":{"missing_retention_days":45}}"#,
        r#"{"ui":{"default_view":"table"}}"#,
        r#"{"discovery":{"full_scan":true}}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let svc = e.service.clone();
        let patch: serde_json::Value = serde_json::from_str(body).unwrap();
        tasks.push(tokio::spawn(async move {
            (
                i,
                svc.update_settings(patch, cc_workspace_manager::view::Privacy::Off)
                    .await
                    .is_ok(),
            )
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap().1);
    }
    let saved = cc_workspace_manager::config::Config::parse(
        &std::fs::read_to_string(&e.config_path).unwrap(),
    )
    .unwrap();
    assert_eq!(saved.activity.inactive_after_days, 8);
    assert_eq!(saved.discovery.missing_retention_days, 45);
    assert_eq!(saved.ui.default_view, "table");
    assert!(saved.discovery.full_scan);
    assert_eq!(saved.ui.theme, "dark");
}

/// M3 security review, M2: a prompt read that is still in flight when "Store prompt text" is
/// turned off stores nothing (the writer checks the setting itself).
#[tokio::test]
async fn a_prompt_read_in_flight_while_storage_turns_off_stores_nothing() {
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
            lines: vec![prompt(S1, "2026-01-01T10:00:00.000Z", "CANARY-IN-FLIGHT")],
        },
    )
    .await;
    let (s, _) = put_settings(&e, &token, "", r#"{"sessions":{"store_prompt_text":true}}"#).await;
    assert_eq!(s, 200);
    e.service
        .set_prompt_read_delay(std::time::Duration::from_millis(600));
    let read = {
        let router = e.router.clone();
        let req = axum::http::Request::builder()
            .uri(format!("/api/v1/projects/{id}/sessions"))
            .header("host", format!("127.0.0.1:{}", common::PORT))
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        tokio::spawn(async move {
            use tower::ServiceExt;
            router.oneshot(req).await.unwrap()
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let (s, _) = put_settings(
        &e,
        &token,
        "",
        r#"{"sessions":{"store_prompt_text":false}}"#,
    )
    .await;
    assert_eq!(s, 200);
    let (s, v) = json(read.await.unwrap()).await;
    assert_eq!(s, 200);
    assert_eq!(
        v["items"][0]["last_prompt"]["text"], "CANARY-IN-FLIGHT",
        "the read itself succeeded (and was in flight)"
    );
    e.writer.flush().await.unwrap();
    let n: i64 = rusqlite::Connection::open(&e.db)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sessions WHERE prompt_text IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "a prompt was cached after storage was turned off");
    let bytes = e.db_bytes();
    assert!(!bytes
        .windows("CANARY-IN-FLIGHT".len())
        .any(|w| w == b"CANARY-IN-FLIGHT"));
}

/// M3 security review, L7: the browser API changes only the Settings page's keys, never port 0
/// or a session directory that would open the whole disk to reads.
#[tokio::test]
async fn settings_puts_accept_only_the_settings_page_keys_and_safe_values() {
    let e = env().await;
    let token = e.login().await;
    let (s, _) = put_settings(&e, &token, "", r#"{"ui":{"theme":"light"}}"#).await;
    assert_eq!(s, 200);
    let before = std::fs::read(&e.config_path).unwrap();
    for bad in [
        r#"{"git":{"allow_unhardened_status":true}}"#,
        r#"{"watch":{"debounce_ms":10}}"#,
        r#"{"activity":{"events_per_project":5}}"#,
        r#"{"server":{"port":0}}"#,
        r#"{"server":{"port":"8765"}}"#,
        r#"{"sessions":{"dir":"/"}}"#,
        r#"{"sessions":{"dir":"/home"}}"#,
        r#"{"sessions":{"dir":"/home/u/../.."}}"#,
        r#"{"sessions":{"dir":"relative"}}"#,
        r#"{"ui":"dark"}"#,
    ] {
        let (s, v) = put_settings(&e, &token, "", bad).await;
        assert_eq!((s, code(&v)), (400, "invalid_argument"), "{bad}: {v}");
    }
    assert_eq!(std::fs::read(&e.config_path).unwrap(), before);
    let (s, v) = put_settings(
        &e,
        &token,
        "",
        r#"{"sessions":{"dir":"/srv/claude-config"},"server":{"port":9000}}"#,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v["restart_required"],
        serde_json::json!(["server.port", "sessions.dir"])
    );
}

/// M3 security review, L1: privacy mode also covers the ignore and settings-save responses, and
/// the settings check uses roots, exclusions and a session directory that hold canaries.
#[tokio::test]
async fn privacy_mode_covers_the_ignore_and_settings_save_responses() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["app"]).await;
    let id = project_id(&e, &token, "app").await;
    let body = r#"{"discovery":{"roots":["/srv/CANARY-ROOT"],"exclude":["CANARY-EXCL/"]},"sessions":{"dir":"/srv/CANARY-SESSIONS"}}"#;
    let canaries = ["CANARY-ROOT", "CANARY-EXCL", "CANARY-SESSIONS", "/home/u"];
    let (s, private) = put_settings(&e, &token, "?privacy=1", body).await;
    assert_eq!(s, 200, "{private}");
    let (_, private_get) = json(e.get("/api/v1/settings?privacy=1", Some(&token)).await).await;
    let (_, full) = json(e.get("/api/v1/settings", Some(&token)).await).await;
    for c in canaries {
        assert!(!private.to_string().contains(c), "PUT response leaks {c}");
        assert!(!private_get.to_string().contains(c), "GET leaks {c}");
        if c != "/home/u" {
            assert!(full.to_string().contains(c), "{c} missing without privacy");
        }
    }
    for (method, path) in [
        ("PUT", format!("/api/v1/projects/{id}/ignore")),
        ("DELETE", format!("/api/v1/projects/{id}/ignore")),
    ] {
        let (s, v) = json(
            e.send_json(method, &format!("{path}?privacy=1"), &token, "")
                .await,
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert!(
            v.get("path").is_none() && v.get("display_path").is_none(),
            "{v}"
        );
        let (_, v) = json(e.send_json(method, &path, &token, "").await).await;
        assert_eq!(v["path"], "/home/u/app", "without privacy");
    }
    // Discovery status: the folders of unassigned sessions are hidden too.
    e.service.discovery.update(|d| {
        d.sessions.unassigned_folders =
            vec![cc_workspace_manager::discovery::status::UnassignedFolder {
                reason: "excluded",
                folder: Some("~/CANARY-FOLDER".into()),
                sessions: 3,
            }];
    });
    let (_, v) = json(
        e.get("/api/v1/discovery/status?privacy=1", Some(&token))
            .await,
    )
    .await;
    assert!(!v.to_string().contains("CANARY-FOLDER"), "{v}");
    assert_eq!(v["sessions"]["unassigned_folders"][0]["sessions"], 3);
    let (_, v) = json(e.get("/api/v1/discovery/status", Some(&token)).await).await;
    assert!(v.to_string().contains("CANARY-FOLDER"));
}

/// "Forget" removes a missing project from ccwm's database only; "Missing only" lists them.
#[tokio::test]
async fn missing_projects_can_be_listed_alone_and_forgotten() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["gone", "here"]).await;
    let gone = project_id(&e, &token, "gone").await;
    let here = project_id(&e, &token, "here").await;
    e.writer
        .mark_missing(vec![gone.clone()], START)
        .await
        .unwrap();
    let names = |v: &serde_json::Value| -> Vec<String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    };
    let (_, v) = json(e.get("/api/v1/projects?missing_only=1", Some(&token)).await).await;
    assert_eq!(names(&v), ["gone"]);
    assert_eq!(v["total"], 1);
    let (s, v) = json(
        e.get("/api/v1/projects?missing_only=yes", Some(&token))
            .await,
    )
    .await;
    assert_eq!((s, code(&v)), (400, "invalid_argument"));

    let (s, v) = json(
        e.send_json("DELETE", &format!("/api/v1/projects/{here}"), &token, "")
            .await,
    )
    .await;
    assert_eq!(
        (s, code(&v)),
        (400, "invalid_argument"),
        "a present project stays"
    );
    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/projects/{gone}"))
        .header("host", format!("127.0.0.1:{}", common::PORT))
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(e.send(req).await.status(), 403, "no Origin");
    let resp = e
        .send_json("DELETE", &format!("/api/v1/projects/{gone}"), &token, "")
        .await;
    assert_eq!(resp.status(), 204);
    let (_, v) = json(
        e.get("/api/v1/projects?include_missing=1", Some(&token))
            .await,
    )
    .await;
    assert_eq!(names(&v), ["here"]);
    let resp = e
        .send_json("DELETE", &format!("/api/v1/projects/{gone}"), &token, "")
        .await;
    assert_eq!(resp.status(), 404, "already forgotten");
}

/// v0.1.0 review L3: in privacy mode the service status keeps no sandbox note (they repeat the
/// broad read rules, and a rule that could not be added names its path), only their number;
/// and a failed settings save does not name the configuration file. Both are there without
/// privacy mode (the control).
#[tokio::test]
async fn privacy_mode_hides_sandbox_notes_and_the_path_in_a_failed_settings_save() {
    use cc_workspace_manager::sandbox::SandboxReport;
    use std::path::PathBuf;
    let mut report = SandboxReport::disabled("landlock: allow /srv/CANARY-RULE: refused");
    report.flag_broad_reads(
        &[PathBuf::from("/home/CANARY-BROAD"), PathBuf::from("/usr")],
        Path::new("/home/CANARY-BROAD/u"),
    );
    let e = common::env_with_sandbox(report).await;
    let token = e.login().await;
    let status = |query: &'static str| {
        let (e, token) = (&e, token.clone());
        async move {
            let path = format!("/api/v1/service/status{query}");
            let (s, v) = json(e.get(&path, Some(&token)).await).await;
            assert_eq!(s, 200, "{v}");
            v
        }
    };
    let private = status("?privacy=1").await;
    assert!(!private.to_string().contains("CANARY"), "{private}");
    assert_eq!(private["sandbox"]["notes"], serde_json::json!([]));
    assert_eq!(private["sandbox"]["notes_hidden"], 2);
    assert_eq!(
        private["sandbox"]["broad_read_rules"],
        serde_json::json!([])
    );
    let full = status("").await;
    let notes = full["sandbox"]["notes"].to_string();
    assert!(
        notes.contains("/srv/CANARY-RULE") && notes.contains("/home/CANARY-BROAD"),
        "{full}"
    );
    assert_eq!(
        full["sandbox"]["broad_read_rules"],
        serde_json::json!(["/home/CANARY-BROAD"])
    );
    assert!(full["sandbox"].get("notes_hidden").is_none(), "{full}");

    // A save that fails: the temporary file's name is taken by a directory.
    let mut blocked = e.config_path.clone().into_os_string();
    blocked.push(".tmp");
    std::fs::create_dir(&blocked).unwrap();
    let dir = e.config_path.parent().unwrap().to_str().unwrap();
    let body = r#"{"ui":{"default_view":"table"}}"#;
    let (s, private) = put_settings(&e, &token, "?privacy=1", body).await;
    assert_eq!(s, 400, "{private}");
    assert!(
        private.to_string().contains("could not be written;") && !private.to_string().contains(dir),
        "{private}"
    );
    let (s, full) = put_settings(&e, &token, "", body).await;
    assert_eq!(s, 400, "{full}");
    assert!(full.to_string().contains(dir), "{full}");
}
