use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

use crate::allowlist::{Allowlist, Entry};

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Command {
    List,
    AddSession { host: String, port: u16 },
    AddPersist { host: String, port: u16 },
    Remove { host: String, port: u16 },
}

// Untagged so replies serialize as plain JSON objects. Do not add a serde tag
// without updating the corresponding TypeScript types in extension/index.ts.
#[derive(Serialize)]
#[serde(untagged)]
enum Reply {
    Entries { ok: bool, entries: Vec<Entry> },
    Simple { ok: bool },
}

pub async fn run(path: &Path, allowlist: Arc<RwLock<Allowlist>>) -> std::io::Result<()> {
    // Remove stale socket from a previous run before binding
    let _ = tokio::fs::remove_file(path).await;
    let listener = UnixListener::bind(path)?;
    tracing::info!("mgmt socket at {}", path.display());
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let allowlist = allowlist.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(socket, allowlist).await {
                        tracing::debug!("mgmt connection closed: {e}");
                    }
                });
            }
            Err(e) => tracing::error!("mgmt accept error: {e}"),
        }
    }
}

async fn handle(socket: UnixStream, allowlist: Arc<RwLock<Allowlist>>) -> std::io::Result<()> {
    let (read_half, mut writer) = socket.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let reply = match serde_json::from_str::<Command>(trimmed) {
                Ok(cmd) => dispatch(cmd, &allowlist).await,
                Err(e) => {
                    tracing::warn!("invalid mgmt command: {e}");
                    Reply::Simple { ok: false }
                }
            };
            let mut response = serde_json::to_string(&reply)
                .unwrap_or_else(|_| r#"{"ok":false}"#.to_owned());
            response.push('\n');
            writer.write_all(response.as_bytes()).await?;
        }
        line.clear();
    }
    Ok(())
}

async fn dispatch(cmd: Command, allowlist: &Arc<RwLock<Allowlist>>) -> Reply {
    match cmd {
        Command::List => {
            let entries = allowlist.read().await.entries();
            Reply::Entries { ok: true, entries }
        }
        Command::AddSession { host, port } => {
            allowlist.write().await.add_session(host, port);
            Reply::Simple { ok: true }
        }
        Command::AddPersist { host, port } => {
            let mut guard = allowlist.write().await;
            match guard.add_persist(host, port).await {
                Ok(()) => Reply::Simple { ok: true },
                Err(e) => {
                    tracing::error!("failed to persist allowlist: {e}");
                    Reply::Simple { ok: false }
                }
            }
        }
        Command::Remove { host, port } => {
            let mut guard = allowlist.write().await;
            match guard.remove(&host, port).await {
                Ok(()) => Reply::Simple { ok: true },
                Err(e) => {
                    tracing::error!("failed to update allowlist: {e}");
                    Reply::Simple { ok: false }
                }
            }
        }
    }
}
