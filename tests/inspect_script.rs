//! The schema inspection script (§19) must never print content. This test runs it ONLY against a
//! synthetic directory seeded with canary strings and asserts that none of them reach the output.

use std::fs;
use std::process::Command;

const CANARIES: [&str; 9] = [
    "CANARY_PROMPT_TEXT",
    "CANARY_TITLE",
    "/home/canary/secret.txt",
    "canary-secret-key",
    "CANARY_TOOL_DATA",
    "CANARY_SOURCE_VALUE_THAT_IS_MUCH_TOO_LONG_TO_BE_A_TOKEN",
    "weird-canary-tag",
    "canary-project-dir",
    "CANARY_CWD",
];

#[test]
fn script_prints_structure_but_no_canary_content() {
    let python = Command::new("python3").arg("--version").output();
    if python.is_err() {
        eprintln!("NOTICE: python3 is not installed; skipping the inspection-script test");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let sid = "11111111-2222-4333-8444-555555555555";
    let proj = t.path().join("projects/-canary-project-dir");
    fs::create_dir_all(proj.join(format!("{sid}/subagents"))).unwrap();
    fs::create_dir_all(proj.join("canary-project-dir-notes")).unwrap();
    fs::write(proj.join("canary-project-dir-notes/secret-name.md"), "x").unwrap();
    let lines = [
        format!(
            r#"{{"type":"user","sessionId":"{sid}","cwd":"/CANARY_CWD","timestamp":"2026-01-02T00:00:00.000Z","version":"2.1.331","promptSource":"typed","turnOrigin":"human","isSidechain":false,"message":{{"role":"user","content":"CANARY_PROMPT_TEXT"}}}}"#
        ),
        format!(
            r#"{{"type":"user","sessionId":"{sid}","cwd":"/CANARY_CWD/x","timestamp":"2026-01-01T00:00:00.000Z","promptSource":"CANARY_SOURCE_VALUE_THAT_IS_MUCH_TOO_LONG_TO_BE_A_TOKEN","message":{{"role":"user","content":"<weird-canary-tag>CANARY_PROMPT_TEXT"}}}}"#
        ),
        format!(
            r#"{{"type":"user","sessionId":"{sid}","timestamp":"2026-01-03T00:00:00.000Z","toolUseResult":{{"/home/canary/secret.txt":"CANARY_TOOL_DATA","canary-secret-key":1}},"message":{{"role":"user","content":[{{"type":"tool_result","content":"CANARY_TOOL_DATA"}}]}}}}"#
        ),
        format!(
            r#"{{"type":"user","sessionId":"{sid}","timestamp":"2026-01-03T00:00:01.000Z","message":{{"role":"user","content":"<task-notification>CANARY_PROMPT_TEXT"}}}}"#
        ),
        format!(r#"{{"type":"ai-title","sessionId":"{sid}","aiTitle":"CANARY_TITLE"}}"#),
        "this line is not json CANARY_PROMPT_TEXT".to_string(),
    ];
    fs::write(proj.join(format!("{sid}.jsonl")), lines.join("\n") + "\n").unwrap();
    fs::write(
        proj.join(format!("{sid}/subagents/agent-abc123.jsonl")),
        format!(r#"{{"type":"assistant","sessionId":"{sid}","isSidechain":true}}"#) + "\n",
    )
    .unwrap();

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/inspect-session-schema.py"
    );
    let out = Command::new("python3")
        .args(["-I", script, "--root"])
        .arg(t.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    for canary in CANARIES {
        assert!(
            !stdout.contains(canary),
            "the script leaked {canary:?}:\n{stdout}"
        );
    }
    assert!(!stdout.contains(sid), "session ids must not be printed");
    assert!(
        !stdout.contains(t.path().to_str().unwrap()),
        "no filesystem paths"
    );

    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["record_counts"]["session:user"], 3 + 1);
    assert_eq!(v["numbers"]["session.malformed_lines"], 1);
    assert_eq!(v["numbers"]["session.files_with_unordered_timestamps"], 1);
    assert_eq!(v["numbers"]["session.files_with_multiple_cwds"], 1);
    assert_eq!(
        v["numbers"]["session.records_with_sessionId_equal_to_file_stem"],
        5
    );
    assert_eq!(v["numbers"]["subagent.files"], 1);
    assert_eq!(v["discriminator_values"]["promptSource"]["typed"], 1);
    assert_eq!(v["discriminator_values"]["promptSource"]["<other>"], 1);
    assert!(v["directory_patterns"]
        .as_object()
        .unwrap()
        .keys()
        .any(|k| k == "projects/<encoded-cwd>/<uuid>.jsonl"));
    assert!(v["directory_patterns"]
        .as_object()
        .unwrap()
        .keys()
        .any(|k| k == "projects/<encoded-cwd>/<name>/<name>.md"));
    let sigs = v["user_record_signatures"].to_string();
    assert!(
        sigs.contains("string:<task-notification>")
            && sigs.contains("string:<other-tag>")
            && sigs.contains("array[tool_result]")
    );
    // key names that are not identifiers are masked
    assert!(v["key_paths_by_record_type"]["user"]
        .as_object()
        .unwrap()
        .keys()
        .any(|k| k.contains("<key>")));
}

#[test]
fn policy_flag_prints_the_allowlists_without_touching_any_files() {
    if Command::new("python3").arg("--version").output().is_err() {
        return;
    }
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/inspect-session-schema.py"
    );
    let out = Command::new("python3")
        .args(["-I", script, "--policy"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["discriminator_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "promptSource"));
}
