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
    if !python_available() {
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

    let out = Command::new("python3")
        .args(["-I", SCRIPT, "--root"])
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

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/inspect-session-schema.py"
);

fn python_available() -> bool {
    let ok = Command::new("python3").arg("--version").output().is_ok();
    if !ok {
        eprintln!("NOTICE: python3 is not installed; skipping the inspection-script test");
    }
    ok
}

fn policy() -> serde_json::Value {
    let out = Command::new("python3")
        .args(["-I", SCRIPT, "--policy"])
        .output()
        .unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Run the script over one synthetic session file made of `lines`; return (stdout, parsed JSON).
fn run_on(lines: &[String]) -> (String, serde_json::Value) {
    let t = tempfile::tempdir().unwrap();
    let proj = t.path().join("projects/-x");
    fs::create_dir_all(&proj).unwrap();
    fs::write(
        proj.join("11111111-2222-4333-8444-555555555555.jsonl"),
        lines.join("\n") + "\n",
    )
    .unwrap();
    let out = Command::new("python3")
        .args(["-I", SCRIPT, "--root"])
        .arg(t.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v = serde_json::from_str(&stdout).unwrap();
    (stdout, v)
}

fn key_paths(v: &serde_json::Value, rtype: &str) -> Vec<String> {
    v["key_paths_by_record_type"][rtype]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

#[test]
fn policy_flag_prints_the_allowlists_without_touching_any_files() {
    if !python_available() {
        return;
    }
    let v = policy();
    assert!(v["discriminator_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "promptSource"));
    assert!(v["map_key_threshold"].as_u64().unwrap() >= 1);
    assert!(v["root_key_threshold"].as_u64().unwrap() >= v["map_key_threshold"].as_u64().unwrap());
    assert_eq!(v["key_mask"], "<key>");
}

/// L6: a data-keyed object (here MCP-server-like names) must not leak ANY of its key names, not even
/// the first ones seen, and the result must not depend on record order.
#[test]
fn data_keyed_objects_are_masked_entirely_regardless_of_order() {
    if !python_available() {
        return;
    }
    let threshold = policy()["map_key_threshold"].as_u64().unwrap() as usize;
    let names: Vec<String> = (0..=threshold)
        .map(|i| format!("canaryServer{}", (b'A' + i as u8) as char))
        .collect();
    let record = |name: &str| {
        format!(
            r#"{{"type":"attachment","servers":{{"{name}":{{"command":"x","args":[]}}}},"message":{{"role":"user"}}}}"#
        )
    };
    for order in [false, true] {
        let mut lines: Vec<String> = names.iter().map(|n| record(n)).collect();
        if order {
            lines.reverse();
        }
        let (stdout, v) = run_on(&lines);
        assert!(
            !stdout.contains("canaryServer"),
            "a data key leaked (reversed={order}):\n{stdout}"
        );
        let paths = key_paths(&v, "attachment");
        for want in [
            "servers.<key>",
            "servers.<key>.command",
            "servers.<key>.args",
            "message.role",
        ] {
            assert!(paths.iter().any(|p| p == want), "{want} missing: {paths:?}");
        }
    }
}

#[test]
fn an_object_at_the_threshold_keeps_its_names_and_one_more_masks_them_all() {
    if !python_available() {
        return;
    }
    let threshold = policy()["map_key_threshold"].as_u64().unwrap() as usize;
    let keys = |n: usize| -> String {
        (0..n)
            .map(|i| format!(r#""fieldName{i}":1"#))
            .collect::<Vec<_>>()
            .join(",")
    };
    let line = |n: usize| format!(r#"{{"type":"assistant","usage":{{{}}}}}"#, keys(n));
    let (_, v) = run_on(&[line(threshold)]);
    let paths = key_paths(&v, "assistant");
    assert!(paths.iter().any(|p| p == "usage.fieldName0"), "{paths:?}");
    assert!(!paths.iter().any(|p| p.contains("<key>")), "{paths:?}");

    let (stdout, v) = run_on(&[line(threshold + 1)]);
    assert!(!stdout.contains("fieldName"), "{stdout}");
    assert!(key_paths(&v, "assistant")
        .iter()
        .any(|p| p == "usage.<key>"));
    // Top-level record keys are the schema and stay visible.
    assert!(key_paths(&v, "assistant").iter().any(|p| p == "usage"));
}

#[test]
fn timestamps_and_leading_tags_never_carry_text_into_the_output() {
    if !python_available() {
        return;
    }
    let lines = [
        r#"{"type":"user","timestamp":"CANARY timestamp text","message":{"role":"user","content":"<canarytag x>hi"}}"#.to_string(),
        r#"{"type":"user","timestamp":"2026-01-02T03:04:05.678Z","message":{"role":"user","content":"<system-reminder>x"}}"#.to_string(),
    ];
    let (stdout, v) = run_on(&lines);
    for canary in ["CANARY", "canarytag", "timestamp text"] {
        assert!(!stdout.contains(canary), "{canary} leaked:\n{stdout}");
    }
    let shapes = v["timestamp_shapes"].as_object().unwrap();
    assert!(
        shapes.contains_key("9999-99-99T99:99:99.999Z"),
        "{shapes:?}"
    );
    assert!(
        shapes.keys().any(|k| k.chars().all(|c| c == 'x')),
        "{shapes:?}"
    );
    let sigs = v["user_record_signatures"].to_string();
    assert!(sigs.contains("string:<other-tag>") && sigs.contains("string:<system-reminder>"));
}
