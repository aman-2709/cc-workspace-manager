//! Runs the dependency-free JavaScript unit tests when `node` is available (it is not a build
//! requirement; without it the test prints a notice and passes).

use std::process::Command;

#[test]
fn ui_helper_tests_pass_under_node() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let Ok(out) = Command::new("node")
        .args(["--test", "tests/ui/app.test.js"])
        .current_dir(dir)
        .output()
    else {
        eprintln!("NOTICE: node is not installed; skipping JavaScript helper tests");
        return;
    };
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
