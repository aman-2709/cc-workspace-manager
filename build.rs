//! Embeds the Git commit the binary was built from (`CCWM_GIT_COMMIT`), so `/health` and
//! `ccwm status` can tell whether the CLI and the running daemon come from the same build.
//!
//! Value: the 12-character abbreviated `HEAD`, with `-dirty` when tracked files differ from it,
//! or `unknown` when Git or the repository is unavailable (e.g. a source tarball). This runs Git in
//! **this** repository at build time only; the daemon never runs it.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&dir);
    // Re-run when HEAD moves or any tracked input changes, so `-dirty` is accurate at build time.
    for p in [
        ".git/HEAD",
        ".git/index",
        ".git/refs",
        ".git/packed-refs",
        "src",
        "web",
        "tests",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
    ] {
        println!("cargo:rerun-if-changed={p}");
    }
    let commit = match git(dir, &["rev-parse", "--short=12", "HEAD"]) {
        Some(hash) if !hash.is_empty() => {
            let dirty = git(dir, &["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|s| !s.is_empty());
            if dirty {
                format!("{hash}-dirty")
            } else {
                hash
            }
        }
        _ => "unknown".to_string(),
    };
    println!("cargo:rustc-env=CCWM_GIT_COMMIT={commit}");
}
