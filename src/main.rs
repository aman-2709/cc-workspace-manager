use clap::Parser;

fn main() {
    // Single-threaded here: `serve` applies the Landlock sandbox before any thread is created.
    let cli = cc_workspace_manager::cli::Cli::parse();
    if let Err(e) = cc_workspace_manager::cli::run(cli) {
        cc_workspace_manager::cli::write_stderr(format_args!("ccwm: {e}\n"));
        std::process::exit(e.exit_code());
    }
}
