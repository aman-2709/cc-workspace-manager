//! v0.2: the session activity indicator over the API (REQUIREMENTS.md §21.6, §21.8, §21.10;
//! ARCHITECTURE.md §15 "Contracts"), with the real service and database and a fake `/proc` for the
//! process walk. Hook events go in where the socket hands them over (`Service::hook_event`); the
//! project of each session is set the way the tracker sets it (`Presence::assign`; the tracker's
//! own resolution is covered at process level in `tests/hooks.rs`).

mod common;

use cc_workspace_manager::claude::hook::{Event, Notice, Report, Source};
use cc_workspace_manager::events::Change;
use common::{json, FakeProc, START};
use serde_json::Value;

const A: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
const B: &str = "1b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
const P1: &str = "9a8b7c6d-5e4f-4a3b-8c2d-000000000001";

/// Apply a project resolution started now (the latest one, so it is never dropped as older).
fn assign(
    p: &cc_workspace_manager::presence::Presence,
    results: Vec<(String, Result<String, &'static str>)>,
) {
    let (seq, _) = p.cwds();
    p.assign(seq, results);
}

/// An interactive claude (100 → sh 200 → hook 300) and a `-p` one (400 → sh 410 → hook 420).
fn fake_proc() -> FakeProc {
    let fake = FakeProc::new();
    fake.process(50, 1, 10, &["systemd", "--user"]);
    fake.process(100, 50, 20, &["claude"]);
    fake.process(200, 100, 30, &["sh", "-c", "x"]);
    fake.process(300, 200, 31, &["ccwm", "hook", "Stop"]);
    fake.process(400, 50, 40, &["claude", "-p", "x"]);
    fake.process(410, 400, 41, &["sh", "-c", "x"]);
    fake.process(420, 410, 42, &["ccwm", "hook", "Stop"]);
    fake
}

fn report(event: Event, sid: &str) -> Report {
    Report {
        event,
        session_id: sid.into(),
        cwd: "/home/u/dev/alpha".into(),
        prompt_id: Some(P1.into()),
        claude_pid: None,
    }
}

struct T {
    e: common::Env,
    token: String,
    _proc: FakeProc,
}

impl T {
    async fn new() -> Self {
        let proc = fake_proc();
        let e = common::env_with_proc(proc.root()).await;
        e.seed(&["alpha", "beta"]).await;
        let token = e.login().await;
        Self {
            e,
            token,
            _proc: proc,
        }
    }

    async fn get(&self, path: &str) -> Value {
        let (status, v) = json(self.e.get(path, Some(&self.token)).await).await;
        assert_eq!(status, 200, "{path}: {v}");
        v
    }

    async fn projects(&self, query: &str) -> Vec<Value> {
        self.get(&format!("/api/v1/projects?sort=name{query}"))
            .await["items"]
            .as_array()
            .unwrap()
            .clone()
    }

    async fn id(&self, name: &str) -> String {
        self.projects("")
            .await
            .iter()
            .find(|p| p["name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn live(&self, name: &str) -> Value {
        self.projects("")
            .await
            .iter()
            .find(|p| p["name"] == name)
            .unwrap()["live"]
            .clone()
    }

    async fn names(&self, query: &str) -> Vec<String> {
        self.projects(query)
            .await
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    }

    fn hook(&self, peer: i32, r: Report) {
        self.e.service.hook_event(Some(peer), Ok(r)).unwrap();
    }

    /// The projects published since the last call.
    fn published(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let rx = self.e.changes.as_mut().unwrap();
        while let Ok(c) = rx.try_recv() {
            if let Change::Project(id) = c {
                out.push(id);
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

#[tokio::test]
async fn project_objects_carry_the_live_state_and_the_filters_select_by_it() {
    let mut t = T::new().await;
    let (alpha, beta) = (t.id("alpha").await, t.id("beta").await);
    // No open session: `live` is null everywhere, every filter is empty.
    assert_eq!(t.live("alpha").await, Value::Null);
    for f in ["waiting", "working", "open"] {
        assert!(t.names(&format!("&live={f}")).await.is_empty(), "{f}");
    }
    let stats = t.get("/api/v1/stats").await;
    assert_eq!(
        stats["live"],
        serde_json::json!({"waiting_for_me": 0, "working": 0, "open": 0})
    );

    // A prompt: working.
    t.hook(300, report(Event::UserPromptSubmit, A));
    assign(&t.e.presence, vec![(A.into(), Ok(alpha.clone()))]);
    assert_eq!(t.published(), std::slice::from_ref(&alpha));
    assert_eq!(
        t.live("alpha").await,
        serde_json::json!({"state": "working", "sessions": 1, "needs_approval": 0, "working": 1, "waiting": 0, "unknown": 0, "since": START, "needs_approval_since": null})
    );
    assert_eq!(t.live("beta").await, Value::Null);
    assert_eq!(t.names("&live=working").await, ["alpha"]);
    assert!(t.names("&live=waiting").await.is_empty());
    assert_eq!(t.names("&live=open").await, ["alpha"]);
    // The live filter combines with the others.
    assert!(t.names("&live=open&q=beta").await.is_empty());
    assert_eq!(t.names("&live=open&q=alp").await, ["alpha"]);
    let (status, err) = json(
        t.e.get("/api/v1/projects?live=needs_approval", Some(&t.token))
            .await,
    )
    .await;
    assert_eq!((status, common::code(&err)), (400, "invalid_argument"));

    // A permission dialog, two minutes later: needs approval, since then.
    t.e.clock.advance(5);
    t.hook(
        300,
        report(Event::Notification(Notice::PermissionPrompt), A),
    );
    t.e.clock.advance(120);
    let live = t.live("alpha").await;
    assert_eq!(
        (
            live["state"].as_str(),
            live["since"].as_i64(),
            live["needs_approval_since"].as_i64()
        ),
        (Some("needs_approval"), Some(START + 5), Some(START + 5))
    );
    assert_eq!(
        t.names("&live=waiting").await,
        ["alpha"],
        "Waiting for me includes needs approval"
    );
    assert!(t.names("&live=working").await.is_empty());
    let stats = t.get("/api/v1/stats").await;
    assert_eq!(
        stats["live"],
        serde_json::json!({"waiting_for_me": 1, "working": 0, "open": 1})
    );

    // A second session in the same project, working: the aggregate says needs approval, with
    // the counts and no single `since`.
    t.hook(
        300,
        Report {
            prompt_id: None,
            ..report(Event::UserPromptSubmit, B)
        },
    );
    assign(&t.e.presence, vec![(B.into(), Ok(alpha.clone()))]);
    let live = t.live("alpha").await;
    assert_eq!(live["state"], "needs_approval");
    assert_eq!(
        (
            live["sessions"].as_u64(),
            live["needs_approval"].as_u64(),
            live["working"].as_u64()
        ),
        (Some(2), Some(1), Some(1))
    );
    assert_eq!(live["since"], Value::Null);
    assert_eq!(
        t.names("&live=working").await,
        ["alpha"],
        "at least one working session"
    );

    // The tool ran, the turn ended; B's session ended.
    t.hook(300, report(Event::PostToolUse, A));
    t.hook(300, report(Event::Stop, A));
    t.hook(300, report(Event::SessionEnd, B));
    assert_eq!(t.live("alpha").await["state"], "waiting");
    t.published();

    // A non-interactive session in beta: hidden until the Settings toggle is on.
    t.hook(
        420,
        Report {
            cwd: "/home/u/dev/beta".into(),
            ..report(Event::UserPromptSubmit, B)
        },
    );
    assign(&t.e.presence, vec![(B.into(), Ok(beta.clone()))]);
    assert_eq!(t.live("beta").await, Value::Null);
    assert!(t.names("&live=working").await.is_empty());
    let hooks = t.get("/api/v1/service/status").await["hooks"].clone();
    assert_eq!(
        (
            hooks["open"].as_u64(),
            hooks["hidden_noninteractive"].as_u64()
        ),
        (Some(1), Some(1))
    );
    let r =
        t.e.send_json(
            "PUT",
            "/api/v1/settings",
            &t.token,
            r#"{"indicator":{"show_noninteractive":true}}"#,
        )
        .await;
    let (status, settings) = json(r).await;
    assert_eq!(status, 200, "{settings}");
    assert_eq!(settings["config"]["indicator"]["show_noninteractive"], true);
    assert!(
        settings["restart_required"].as_array().unwrap().is_empty(),
        "live: no restart"
    );
    assert!(std::fs::read_to_string(&t.e.config_path)
        .unwrap()
        .contains("[indicator]\nshow_noninteractive = true"));
    assert_eq!(
        t.published(),
        std::slice::from_ref(&beta),
        "the toggle republishes the hidden session's project"
    );
    assert_eq!(t.live("beta").await["state"], "working");
    assert_eq!(t.names("&live=working").await, ["beta"]);
    let r =
        t.e.send_json(
            "PUT",
            "/api/v1/settings",
            &t.token,
            r#"{"indicator":{"show_noninteractive":false}}"#,
        )
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(t.live("beta").await, Value::Null);
    let r =
        t.e.send_json(
            "PUT",
            "/api/v1/settings",
            &t.token,
            r#"{"indicator":{"show_noninteractive":"yes"}}"#,
        )
        .await;
    assert_eq!(r.status(), 400, "a boolean only");
    let r =
        t.e.send_json(
            "PUT",
            "/api/v1/settings",
            &t.token,
            r#"{"indicator":{"other":true}}"#,
        )
        .await;
    assert_eq!(r.status(), 400, "no other indicator key");
}

/// "Show live sessions first" (§21.8): on by default, a project with an open session leads the
/// listing in every sort and across cursor pages; the Settings toggle turns it off live and
/// republishes the projects with an open session.
#[tokio::test]
async fn live_sessions_come_first_until_the_toggle_turns_it_off() {
    let mut t = T::new().await;
    let beta = t.id("beta").await;
    assert_eq!(t.names("").await, ["alpha", "beta"]);
    let settings = t.get("/api/v1/settings").await;
    assert_eq!(settings["config"]["indicator"]["live_first"], true);
    t.hook(300, report(Event::Stop, A));
    assign(&t.e.presence, vec![(A.into(), Ok(beta.clone()))]);
    t.published();
    assert_eq!(t.names("").await, ["beta", "alpha"]);
    assert_eq!(t.names("&order=desc").await, ["beta", "alpha"]);
    assert_eq!(t.names("&live=open").await, ["beta"]);
    // Cursor pages carry the rank.
    let first = t.get("/api/v1/projects?sort=name&limit=1").await;
    assert_eq!(first["items"][0]["name"], "beta");
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    let second = t
        .get(&format!(
            "/api/v1/projects?sort=name&limit=1&cursor={cursor}"
        ))
        .await;
    assert_eq!(second["items"][0]["name"], "alpha");
    assert_eq!(second["next_cursor"], Value::Null);
    let r =
        t.e.send_json(
            "PUT",
            "/api/v1/settings",
            &t.token,
            r#"{"indicator":{"live_first":false}}"#,
        )
        .await;
    let (status, settings) = json(r).await;
    assert_eq!(status, 200, "{settings}");
    assert!(
        settings["restart_required"].as_array().unwrap().is_empty(),
        "live: no restart"
    );
    assert!(std::fs::read_to_string(&t.e.config_path)
        .unwrap()
        .contains("live_first = false"));
    assert_eq!(t.published(), std::slice::from_ref(&beta));
    assert_eq!(t.names("").await, ["alpha", "beta"]);
    assert_eq!(t.live("beta").await["state"], "waiting", "still shown");
    let r =
        t.e.send_json(
            "PUT",
            "/api/v1/settings",
            &t.token,
            r#"{"indicator":{"live_first":1}}"#,
        )
        .await;
    assert_eq!(r.status(), 400, "a boolean only");
}

/// Privacy mode changes nothing in the indicator's payload (states, counts and times only:
/// REQUIREMENTS.md §21.10), and the payload holds no path, pid or session text.
#[tokio::test]
async fn the_indicator_is_the_same_in_privacy_mode_and_holds_no_path_or_pid() {
    let t = T::new().await;
    let alpha = t.id("alpha").await;
    t.hook(
        300,
        Report {
            cwd: "/home/u/SYNTHETIC-CWD-CANARY".into(),
            ..report(Event::UserPromptSubmit, A)
        },
    );
    assign(&t.e.presence, vec![(A.into(), Ok(alpha))]);
    let plain = t.live("alpha").await;
    let private = t.get("/api/v1/projects?sort=name&privacy=1").await["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "alpha")
        .unwrap()["live"]
        .clone();
    assert_eq!(plain, private);
    assert_eq!(plain["state"], "working");
    let status = t.get("/api/v1/service/status?privacy=1").await;
    assert_eq!(
        status["hooks"],
        t.get("/api/v1/service/status").await["hooks"]
    );
    let all = format!(
        "{} {} {}",
        t.get("/api/v1/projects").await,
        status,
        t.get("/api/v1/stats").await
    );
    for leak in ["SYNTHETIC-CWD-CANARY", "\"pid\"", "\"300\"", "\"100\"", A] {
        assert!(!all.contains(leak), "{leak} in {all}");
    }
}

#[tokio::test]
async fn service_status_counts_states_refusals_and_unassigned_sessions() {
    let t = T::new().await;
    let alpha = t.id("alpha").await;
    t.hook(300, report(Event::SessionStart(Source::Startup), A));
    assign(&t.e.presence, vec![(A.into(), Ok(alpha))]);
    t.hook(
        300,
        Report {
            cwd: "/tmp/x".into(),
            ..report(Event::Stop, B)
        },
    );
    assign(&t.e.presence, vec![(B.into(), Err("temporary"))]);
    // A stale event (an older prompt) and a refusal.
    t.hook(300, report(Event::UserPromptSubmit, A));
    t.hook(
        300,
        Report {
            prompt_id: Some("9a8b7c6d-5e4f-4a3b-8c2d-000000000009".into()),
            ..report(Event::Stop, A)
        },
    );
    assert!(t
        .e
        .service
        .hook_event(Some(999), Ok(report(Event::Stop, A)))
        .is_err());
    let h = t.get("/api/v1/service/status").await["hooks"].clone();
    assert_eq!(h["open"], 2);
    assert_eq!(
        (h["working"].as_u64(), h["waiting"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(h["unassigned"], serde_json::json!({"temporary": 1}));
    assert_eq!(
        (h["received"].as_u64(), h["stale"].as_u64()),
        (Some(5), Some(1))
    );
    assert_eq!(h["refused"]["client_gone"], 1, "pid 999 is no process");
    assert_eq!(h["refused"]["no_claude_ancestor"], 0);
    assert_eq!(h["last_event_at"], START);
    // `ccwm status` shows the same.
    let text = cc_workspace_manager::cli::format_hooks(&h);
    assert!(text.contains("hooks: 2 open session(s) (0 needs approval, 1 working, 1 waiting, 0 unknown; not in a project: 1 temporary)"), "{text}");
    assert!(
        text.contains("5 received, 1 stale, 0 from session files, refused: 1 client_gone"),
        "{text}"
    );
    assert_eq!(
        cc_workspace_manager::cli::format_hooks(
            &serde_json::json!({"received": 0, "open": 0, "refused": {}})
        ),
        "  hooks: no hook event since the daemon started (opt-in: `ccwm hooks print`)\n"
    );
    assert_eq!(
        cc_workspace_manager::cli::format_hooks(&Value::Null),
        "",
        "an older daemon: no line"
    );
    // The doctor's line is information, never a failure.
    let c = cc_workspace_manager::doctor::hooks(Some(&h));
    assert_eq!(c.level, cc_workspace_manager::doctor::Level::Info);
    assert!(
        c.detail
            .contains("5 received, 1 refused; 2 open session(s)"),
        "{}",
        c.detail
    );
    let none =
        cc_workspace_manager::doctor::hooks(Some(&serde_json::json!({"last_event_at": null})));
    assert!(
        none.detail
            .contains("no hook event since the daemon started")
            && none.detail.contains("ccwm hooks print")
    );
    assert_eq!(
        cc_workspace_manager::doctor::hooks(None).level,
        cc_workspace_manager::doctor::Level::Info
    );
}

/// "Clear session index" also forgets the open sessions (O16); they come back with their next
/// hook event.
#[tokio::test]
async fn clear_session_index_forgets_open_sessions() {
    let mut t = T::new().await;
    let alpha = t.id("alpha").await;
    t.hook(300, report(Event::UserPromptSubmit, A));
    assign(&t.e.presence, vec![(A.into(), Ok(alpha.clone()))]);
    t.published();
    let r =
        t.e.post("/api/v1/session-index/clear", Some(&t.token), "")
            .await;
    assert_eq!(r.status(), 200);
    assert_eq!(t.live("alpha").await, Value::Null);
    assert!(t.published().contains(&alpha));
    assert_eq!(t.get("/api/v1/service/status").await["hooks"]["open"], 0);
    t.hook(300, report(Event::Stop, A));
    assert_eq!(t.get("/api/v1/service/status").await["hooks"]["open"], 1);
}
