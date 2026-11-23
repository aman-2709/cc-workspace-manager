//! `ccwm-synth [DIR] [--projects N]`: create a synthetic environment and print how to use it.

use cc_workspace_manager::synth;
use std::path::PathBuf;

fn main() {
    let mut dir: Option<PathBuf> = None;
    let mut bulk = 0usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--projects" => match args.next().and_then(|n| n.parse().ok()) {
                Some(n) => bulk = n,
                None => return usage("--projects needs a number"),
            },
            "-h" | "--help" => return usage(""),
            _ if dir.is_none() && !a.starts_with('-') => dir = Some(PathBuf::from(a)),
            _ => return usage(&format!("unexpected argument {a}")),
        }
    }
    let dir = dir.unwrap_or_else(|| {
        let suffix: u32 = std::process::id()
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos()));
        PathBuf::from(format!("/tmp/ccwm-synth-{suffix:08x}"))
    });
    match synth::generate(&dir, bulk) {
        Ok(env) => {
            let lines: String = env
                .env_pairs()
                .iter()
                .map(|(k, v)| format!("{k}={}\n", v.display()))
                .collect();
            if let Err(e) = std::fs::write(env.root.join("env"), &lines) {
                eprintln!("ccwm-synth: cannot write env file: {e}");
                std::process::exit(1);
            }
            println!("Synthetic environment created in {}\n\n{lines}\nUse it for ccwm only (never for cargo):\n  env $(cat {}/env) target/debug/ccwm serve --port 0", env.root.display(), env.root.display());
        }
        Err(e) => {
            eprintln!("ccwm-synth: {e}");
            std::process::exit(1);
        }
    }
}

fn usage(problem: &str) {
    if !problem.is_empty() {
        eprintln!("ccwm-synth: {problem}");
    }
    eprintln!("usage: ccwm-synth [DIR] [--projects N]\nCreates a synthetic HOME, XDG and Claude config directory under DIR (default /tmp/ccwm-synth-XXXXXXXX).");
    std::process::exit(if problem.is_empty() { 0 } else { 2 });
}
