use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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
