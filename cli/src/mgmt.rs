use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::RwLock;
use tokio::sync::broadcast::error::RecvError;

use crate::allowlist::{Allowlist, Entry};
use crate::honeypot::EventTx;

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    List,
    AddSession { host: String, port: u16 },
    AddPersist { host: String, port: u16 },
    Remove { host: String, port: u16 },
    /// Switch *this connection* into events-stream mode. After the daemon
    /// acks with `{"ok":true}`, the read half is abandoned and the daemon
    /// only writes — one JSON event per line (see `honeypot::Event`) until
    /// the client disconnects or the channel closes.
    ///
    /// The switch is per-connection, not per-daemon. The mgmt listener
    /// accepts unbounded concurrent connections; subscribing on one
    /// doesn't affect any other. Clients that need both behaviors (the
    /// extension is one) open a long-lived connection for the events
    /// stream and a fresh short-lived connection per command. Keeping the
    /// two protocols on separate sockets sidesteps the framing problem of
    /// interleaving pushed events with command/reply traffic.
    SubscribeEvents,
}

// Untagged so replies serialize as plain JSON objects. Do not add a serde tag
// without updating the corresponding TypeScript types in extension/index.ts.
// Variant order matters for deserialization: Entries (more fields) must come
// before Simple, otherwise serde will match {"ok":true,"entries":[]} as Simple
// and silently drop the entries.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Reply {
    Entries { ok: bool, entries: Vec<Entry> },
    Simple { ok: bool },
}

pub async fn run(
    path: &Path,
    allowlist: Arc<RwLock<Allowlist>>,
    events: EventTx,
) -> std::io::Result<()> {
    // Remove stale socket from a previous run before binding
    let _ = tokio::fs::remove_file(path).await;
    let listener = UnixListener::bind(path)?;
    tracing::info!("mgmt socket at {}", path.display());
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let allowlist = allowlist.clone();
                let events = events.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(socket, allowlist, events).await {
                        tracing::debug!("mgmt connection closed: {e}");
                    }
                });
            }
            Err(e) => tracing::error!("mgmt accept error: {e}"),
        }
    }
}

async fn handle(
    socket: UnixStream,
    allowlist: Arc<RwLock<Allowlist>>,
    events: EventTx,
) -> std::io::Result<()> {
    let (read_half, mut writer) = socket.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            match serde_json::from_str::<Command>(trimmed) {
                Ok(Command::SubscribeEvents) => {
                    writer.write_all(b"{\"ok\":true}\n").await?;
                    return stream_events(writer, events).await;
                }
                Ok(cmd) => {
                    let reply = dispatch(cmd, &allowlist).await;
                    let mut response = serde_json::to_string(&reply)
                        .unwrap_or_else(|_| r#"{"ok":false}"#.to_owned());
                    response.push('\n');
                    writer.write_all(response.as_bytes()).await?;
                }
                Err(e) => {
                    tracing::warn!("invalid mgmt command: {e}");
                    writer.write_all(b"{\"ok\":false}\n").await?;
                }
            }
        }
        line.clear();
    }
    Ok(())
}

/// Drain the broadcast channel to the writer half until the writer fails or
/// the channel closes. Lagged subscribers are logged but kept alive; missing
/// an event is preferable to tearing down the subscription.
async fn stream_events(mut writer: OwnedWriteHalf, events: EventTx) -> std::io::Result<()> {
    let mut rx = events.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                let mut json = serde_json::to_string(&event)
                    .unwrap_or_else(|_| r#"{"ok":false}"#.to_owned());
                json.push('\n');
                if writer.write_all(json.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
            Err(RecvError::Lagged(n)) => {
                tracing::warn!("events subscriber lagged by {n}");
            }
            Err(RecvError::Closed) => return Ok(()),
        }
    }
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
        // Handled inline in `handle`; the dispatcher never sees it.
        Command::SubscribeEvents => Reply::Simple { ok: false },
    }
}
