use clap::Parser;

fn main() {
    // `ccwm hook <Event>` is run by Claude Code: it is dispatched before argument parsing, whose
    // usage error would exit with status 2 — which blocks a prompt (REQUIREMENTS.md §21.3).
    let mut args = std::env::args_os();
    if args.nth(1).as_deref() == Some(std::ffi::OsStr::new("hook")) {
        cc_workspace_manager::cli::hook(args.next().as_deref());
    }
    // Single-threaded here: `serve` applies the Landlock sandbox before any thread is created.
    let cli = cc_workspace_manager::cli::Cli::parse();
    if let Err(e) = cc_workspace_manager::cli::run(cli) {
        cc_workspace_manager::cli::write_stderr(format_args!("ccwm: {e}\n"));
        std::process::exit(e.exit_code());
    }
}
