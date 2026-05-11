//! Append-only audit log of proxy decisions.
//!
//! When `tau serve --audit-log <path>` is set, every CONNECT decision is
//! appended to the file as one line of JSON:
//!
//! ```json
//! {"ts":"2026-05-10T22:00:00Z","host":"github.com","port":443,"decision":"allow","reason":"persistent"}
//! ```
//!
//! Writes go through a single-writer task fed by an unbounded mpsc channel —
//! O_APPEND would actually make per-task writes safe at the kernel level
//! (records are under PIPE_BUF), but tokio's `File::write_all` requires
//! `&mut self`, and routing through one task is cleaner than a contended
//! `Arc<Mutex<File>>`. Fsync is intentionally omitted; OS page-cache is
//! enough for this audit trail and a crash dropping the last few records
//! is acceptable.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::util::iso_timestamp;

/// One decision in the audit trail. `host`/`port` are optional because a
/// malformed CONNECT request never parses an authority.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub decision: &'static str,
    pub reason: &'static str,
    /// Peer address that issued the CONNECT. Recorded for forensics when
    /// the daemon is exposed to anything beyond loopback (today: never).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

/// Cheap, cloneable handle the proxy uses to push records. When the daemon
/// is started without `--audit-log`, this is constructed via `disabled()`
/// and `record()` becomes a no-op — no allocation, no syscalls.
#[derive(Clone)]
pub struct Audit {
    tx: Option<UnboundedSender<AuditRecord>>,
}

impl Audit {
    pub fn disabled() -> Self {
        Self { tx: None }
    }

    pub fn enabled(tx: UnboundedSender<AuditRecord>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Push a record onto the audit channel. Send errors mean the writer
    /// task is gone (daemon shutting down or write loop crashed); we drop
    /// the record silently — losing an audit entry should never take the
    /// proxy decision path down.
    pub fn record(&self, record: AuditRecord) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(record);
        }
    }
}

/// Build an audit record for an allow decision.
pub fn allow(host: &str, port: u16, peer: SocketAddr, reason: &'static str) -> AuditRecord {
    AuditRecord {
        ts: iso_timestamp(),
        host: Some(host.to_owned()),
        port: Some(port),
        decision: "allow",
        reason,
        peer: Some(peer.to_string()),
    }
}

/// Build an audit record for a deny decision with a known authority.
pub fn deny(host: &str, port: u16, peer: SocketAddr, reason: &'static str) -> AuditRecord {
    AuditRecord {
        ts: iso_timestamp(),
        host: Some(host.to_owned()),
        port: Some(port),
        decision: "deny",
        reason,
        peer: Some(peer.to_string()),
    }
}

/// Build an audit record for a deny whose authority couldn't be parsed.
pub fn deny_anonymous(peer: SocketAddr, reason: &'static str) -> AuditRecord {
    AuditRecord {
        ts: iso_timestamp(),
        host: None,
        port: None,
        decision: "deny",
        reason,
        peer: Some(peer.to_string()),
    }
}

pub fn channel() -> (UnboundedSender<AuditRecord>, UnboundedReceiver<AuditRecord>) {
    mpsc::unbounded_channel()
}

/// Audit writer task. Returns only on unrecoverable open() failure;
/// individual write failures are logged and skipped so a transient ENOSPC
/// doesn't bring the daemon down.
pub async fn run(path: PathBuf, mut rx: UnboundedReceiver<AuditRecord>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .await?;
    tracing::info!("audit log writing to {}", path.display());

    while let Some(record) = rx.recv().await {
        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("audit record failed to serialize: {e}");
                continue;
            }
        };
        line.push('\n');
        if let Err(e) = file.write_all(line.as_bytes()).await {
            tracing::error!("audit write failed: {e}");
        }
    }
    Ok(())
}

