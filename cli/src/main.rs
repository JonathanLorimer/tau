use clap::Parser;

mod allowlist;
mod audit;
mod cmd;
mod honeypot;
mod mcp_config;
mod mgmt;
mod paths;
mod proxy;
mod util;

/// Personal coding harness for pi: firewall daemon, sandbox launcher, and CLI.
#[derive(Parser)]
#[command(name = "tau", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run the firewall daemon (HTTPS proxy + management socket).
    Serve(cmd::serve::Args),
    /// Launch pi inside a bwrap sandbox routed through the firewall.
    Jail(cmd::jail::Args),
    /// Interact with a running tau daemon.
    Ctl(cmd::ctl::Args),
    /// Open a URL in the host browser via the tau daemon.
    Open(cmd::open::Args),
}

fn main() -> std::io::Result<()> {
    // When bind-mounted into the jail as /tau-shims/xdg-open, argv[0] ends
    // with "xdg-open". Intercept before clap so npm's `open` package routes
    // MCP OAuth browser launches through the daemon instead of the display.
    if std::env::args()
        .next()
        .as_deref()
        .map(|s| s.ends_with("xdg-open"))
        .unwrap_or(false)
    {
        return cmd::open::run_as_shim();
    }

    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => with_tokio(cmd::serve::run(args)),
        Command::Jail(args) => cmd::jail::run(args),
        Command::Ctl(args) => with_tokio(cmd::ctl::run(args)),
        Command::Open(args) => cmd::open::run(args),
    }
}

fn with_tokio<F: std::future::Future<Output = std::io::Result<()>>>(
    fut: F,
) -> std::io::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(fut)
}
