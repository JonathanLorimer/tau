use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::mcp_config;
use crate::mgmt::{Command, Reply};
use crate::paths;

#[derive(clap::Args)]
pub struct Args {
    /// Path to the daemon's management socket.
    #[arg(long, env = "TAU_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: CtlCommand,
}

#[derive(clap::Subcommand)]
enum CtlCommand {
    /// List entries in the persistent allowlist.
    List,
    /// Add a host. Persistent by default.
    Add {
        host: String,
        /// Add only for the current daemon session, not to disk.
        #[arg(long)]
        session: bool,
    },
    /// Remove a host from both session and persistent sets.
    Remove { host: String },
    /// Add the default seed host list (anthropic, github, npm, crates, pypi, …).
    Seed,
    /// Read MCP config files and allowlist every https host they reference.
    ///
    /// With no paths, scans the standard locations used by `pi-mcp-adapter`:
    /// `~/.config/mcp/mcp.json`, `~/.pi/agent/mcp.json`, `$PWD/.mcp.json`,
    /// and `$PWD/.pi/mcp.json`. Stdio servers (those with `command`) are
    /// silently skipped; non-`https://` urls are reported and skipped.
    SeedMcp {
        /// Explicit config paths. If omitted, the standard locations are scanned.
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,
        /// Add to the daemon's session set instead of persisting to disk.
        #[arg(long)]
        session: bool,
        /// Print what would be added without contacting the daemon.
        #[arg(long)]
        dry_run: bool,
    },
}

const DEFAULT_SEEDS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "pypi.org",
    "files.pythonhosted.org",
];

pub async fn run(args: Args) -> std::io::Result<()> {
    let socket = args.socket.unwrap_or_else(paths::default_socket);

    match args.command {
        CtlCommand::List => match send(&socket, &Command::List).await? {
            Reply::Entries { entries, .. } => {
                for e in entries {
                    println!("{}", e.host);
                }
            }
            Reply::Simple { ok } => {
                return Err(io_error(format!("unexpected simple reply (ok={ok})")));
            }
        },
        CtlCommand::Add { host, session } => {
            let cmd = if session {
                Command::AddSession { host }
            } else {
                Command::AddPersist { host }
            };
            expect_ok(send(&socket, &cmd).await?)?;
            println!("ok");
        }
        CtlCommand::Remove { host } => {
            expect_ok(send(&socket, &Command::Remove { host }).await?)?;
            println!("ok");
        }
        CtlCommand::Seed => {
            let mut added = 0;
            for host in DEFAULT_SEEDS {
                let cmd = Command::AddPersist {
                    host: (*host).to_string(),
                };
                expect_ok(send(&socket, &cmd).await?)?;
                added += 1;
            }
            println!("seeded {added} entries");
        }
        CtlCommand::SeedMcp { paths, session, dry_run } => {
            let paths = if paths.is_empty() {
                let cwd = std::env::current_dir()?;
                let home = std::env::var("HOME")
                    .map(PathBuf::from)
                    .map_err(|_| io_error("HOME not set"))?;
                mcp_config::default_paths(&cwd, &home)
            } else {
                paths
            };

            let scan = mcp_config::scan(&paths);

            for path in &scan.files_read {
                println!("read {}", path.display());
            }
            for (path, err) in &scan.parse_errors {
                eprintln!("warn: skipping {}: {}", path.display(), err);
            }
            for url in &scan.non_https_skipped {
                eprintln!("warn: skipping non-https url: {url}");
            }
            for url in &scan.unparseable_urls {
                eprintln!("warn: skipping unparseable url: {url}");
            }

            if scan.hosts.is_empty() {
                println!(
                    "no https hosts found ({} stdio entries skipped)",
                    scan.stdio_skipped
                );
                return Ok(());
            }

            if dry_run {
                println!(
                    "would add {} host(s) ({}; {} stdio skipped):",
                    scan.hosts.len(),
                    if session { "session" } else { "persistent" },
                    scan.stdio_skipped
                );
                for host in &scan.hosts {
                    println!("  {host}");
                }
                return Ok(());
            }

            let mut added = 0;
            for host in &scan.hosts {
                let cmd = if session {
                    Command::AddSession { host: host.clone() }
                } else {
                    Command::AddPersist { host: host.clone() }
                };
                expect_ok(send(&socket, &cmd).await?)?;
                added += 1;
            }
            println!(
                "seeded {added} host(s) ({}; {} stdio skipped)",
                if session { "session" } else { "persistent" },
                scan.stdio_skipped
            );
        }
    }

    Ok(())
}

async fn send(socket: &Path, cmd: &Command) -> std::io::Result<Reply> {
    let stream = UnixStream::connect(socket).await?;
    let (read, mut write) = stream.into_split();
    let mut payload = serde_json::to_string(cmd).map_err(std::io::Error::other)?;
    payload.push('\n');
    write.write_all(payload.as_bytes()).await?;
    write.shutdown().await?;

    let mut reader = BufReader::new(read);
    let mut response = String::new();
    reader.read_line(&mut response).await?;
    serde_json::from_str(response.trim()).map_err(std::io::Error::other)
}

fn expect_ok(reply: Reply) -> std::io::Result<()> {
    match reply {
        Reply::Simple { ok: true } => Ok(()),
        Reply::Simple { ok: false } => Err(io_error("daemon returned ok=false")),
        Reply::Entries { .. } => Err(io_error("unexpected entries reply")),
    }
}

fn io_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}
