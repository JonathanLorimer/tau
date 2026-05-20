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
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => with_tokio(cmd::serve::run(args)),
        Command::Jail(args) => cmd::jail::run(args),
        Command::Ctl(args) => with_tokio(cmd::ctl::run(args)),
    }
}

fn with_tokio<F: std::future::Future<Output = std::io::Result<()>>>(
    fut: F,
) -> std::io::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(fut)
}
