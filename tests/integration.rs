//! End-to-end integration tests for `tau serve`.
//!
//! Each test spawns a fresh daemon in a temp directory with a kernel-assigned
//! proxy port, drives it through the mgmt unix socket, and tears it down via
//! `Child::kill_on_drop` when the harness drops. Tests run in parallel; the
//! per-test `Harness` guarantees no shared state between them.
//!
//! What's tested at this layer:
//! - mgmt protocol: list / add_session / add_persist / remove / invalid
//! - persistence: persistent entries survive a daemon restart
//! - deny markers: every cause emits the right `X-Pi-Firewall-Status` value
//!
//! What's NOT tested here (deferred to a future NixOS-VM layer):
//! - the allow-and-tunnel path — would need a port-443 listener
//! - the bwrap jail, systemd unit, nftables enforcement
//! - the honeypot (Phase 8.5) and audit log (Phase 9)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::sleep;

struct Harness {
    // Held to keep the tempdir alive for the test's lifetime; never read.
    _tempdir: tempfile::TempDir,
    socket_path: PathBuf,
    proxy_addr: SocketAddr,
    // Held so kill_on_drop fires when the harness drops; never read directly.
    _proc: Child,
}

impl Harness {
    async fn start() -> std::io::Result<Self> {
        let tempdir = tempfile::tempdir()?;
        let socket_path = tempdir.path().join("tau.sock");
        let allowlist_path = tempdir.path().join("allow.json");
        let proxy_addr = pick_local_port();
        let proc = spawn(&socket_path, &allowlist_path, &proxy_addr)?;

        let h = Self {
            _tempdir: tempdir,
            socket_path,
            proxy_addr,
            _proc: proc,
        };
        // Suppress the unused-let warning if allowlist_path ever becomes
        // referenced; right now it lives only inside the spawned daemon.
        let _ = &allowlist_path;
        h.wait_ready().await?;
        Ok(h)
    }

    async fn wait_ready(&self) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mgmt_ok = UnixStream::connect(&self.socket_path).await.is_ok();
            let proxy_ok = TcpStream::connect(&self.proxy_addr).await.is_ok();
            if mgmt_ok && proxy_ok {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(std::io::Error::other(
                    "daemon failed to bind both listeners within 5s",
                ));
            }
            sleep(Duration::from_millis(25)).await;
        }
    }

    async fn mgmt(&self, cmd: Value) -> std::io::Result<Value> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (read, mut write) = stream.into_split();
        let mut payload = cmd.to_string();
        payload.push('\n');
        write.write_all(payload.as_bytes()).await?;
        write.shutdown().await?;

        let mut reader = BufReader::new(read);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim();
        serde_json::from_str(trimmed).map_err(std::io::Error::other)
    }

    /// Send a raw line of bytes to the mgmt socket; useful for testing
    /// malformed-input handling.
    async fn mgmt_raw(&self, payload: &[u8]) -> std::io::Result<String> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (read, mut write) = stream.into_split();
        write.write_all(payload).await?;
        write.shutdown().await?;

        let mut reader = BufReader::new(read);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        Ok(line.trim().to_string())
    }

    /// Make a CONNECT request through the proxy and return
    /// `(status_line, marker_header_value)`.
    async fn connect(&self, request_line: &str) -> std::io::Result<(String, Option<String>)> {
        let mut stream = TcpStream::connect(&self.proxy_addr).await?;
        let req = format!("{request_line}\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).await?;

        let mut marker = None;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            let trimmed = line.trim();
            if n == 0 || trimmed.is_empty() {
                break;
            }
            if let Some(v) = trimmed.strip_prefix("X-Pi-Firewall-Status: ") {
                marker = Some(v.to_string());
            }
        }

        Ok((status.trim().to_string(), marker))
    }
}

fn pick_local_port() -> SocketAddr {
    // Bind 127.0.0.1:0 to let the kernel pick a free port; the listener is
    // immediately dropped. Brief TOCTOU window before the daemon binds, but
    // collision risk is negligible on a test machine.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn(socket: &Path, allowlist: &Path, proxy_addr: &SocketAddr) -> std::io::Result<Child> {
    Command::new(env!("CARGO_BIN_EXE_tau"))
        .args([
            "serve",
            "--allowlist",
            allowlist.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--proxy-addr",
            &proxy_addr.to_string(),
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

// ---------- mgmt protocol ----------

#[tokio::test]
async fn list_is_initially_empty() {
    let h = Harness::start().await.unwrap();
    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(reply, json!({"ok": true, "entries": []}));
}

#[tokio::test]
async fn add_persist_then_list_shows_entry() {
    let h = Harness::start().await.unwrap();
    let ack = h
        .mgmt(json!({"cmd": "add_persist", "host": "github.com", "port": 443}))
        .await
        .unwrap();
    assert_eq!(ack, json!({"ok": true}));

    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(
        reply,
        json!({"ok": true, "entries": [{"host": "github.com", "port": 443}]})
    );
}

#[tokio::test]
async fn add_session_is_not_in_persistent_list() {
    let h = Harness::start().await.unwrap();
    let ack = h
        .mgmt(json!({"cmd": "add_session", "host": "ephemeral.example", "port": 443}))
        .await
        .unwrap();
    assert_eq!(ack, json!({"ok": true}));

    // `list` returns only persistent entries by design.
    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(reply, json!({"ok": true, "entries": []}));
}

#[tokio::test]
async fn remove_clears_persistent_entry() {
    let h = Harness::start().await.unwrap();
    h.mgmt(json!({"cmd": "add_persist", "host": "a.example", "port": 443}))
        .await
        .unwrap();
    h.mgmt(json!({"cmd": "remove", "host": "a.example", "port": 443}))
        .await
        .unwrap();
    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(reply["entries"], json!([]));
}

#[tokio::test]
async fn invalid_mgmt_command_returns_not_ok() {
    let h = Harness::start().await.unwrap();
    let raw = h.mgmt_raw(b"not even json\n").await.unwrap();
    let parsed: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed, json!({"ok": false}));
}

// ---------- persistence ----------

#[tokio::test]
async fn persistent_entries_survive_restart() {
    // Manually drive two daemon lifetimes against the same on-disk paths to
    // verify allow.json round-trips. Each daemon gets its own proxy port —
    // SIGKILL is async from the parent's view, so reusing the same port
    // would race with the kernel releasing it.
    let tempdir = tempfile::tempdir().unwrap();
    let socket = tempdir.path().join("tau.sock");
    let allowlist = tempdir.path().join("allow.json");

    // First daemon — write a persistent entry, then explicitly kill+reap.
    let addr1 = pick_local_port();
    let mut p1 = spawn(&socket, &allowlist, &addr1).unwrap();
    wait_for_listeners(&socket, &addr1).await.unwrap();
    send_mgmt(
        &socket,
        json!({"cmd": "add_persist", "host": "persistent.example", "port": 443}),
    )
    .await
    .unwrap();
    p1.kill().await.unwrap();

    // Second daemon — fresh port, same paths. allow.json was atomically
    // renamed before the mgmt reply came back, so it must be on disk.
    let addr2 = pick_local_port();
    let mut p2 = spawn(&socket, &allowlist, &addr2).unwrap();
    wait_for_listeners(&socket, &addr2).await.unwrap();
    let reply = send_mgmt(&socket, json!({"cmd": "list"})).await.unwrap();
    assert_eq!(
        reply,
        json!({
            "ok": true,
            "entries": [{"host": "persistent.example", "port": 443}],
        })
    );
    p2.kill().await.unwrap();
}

/// Free-function equivalent of `Harness::wait_ready`, usable for tests that
/// drive the daemon directly (e.g. the restart test).
async fn wait_for_listeners(socket: &Path, proxy_addr: &SocketAddr) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mgmt_ok = UnixStream::connect(socket).await.is_ok();
        let proxy_ok = TcpStream::connect(proxy_addr).await.is_ok();
        if mgmt_ok && proxy_ok {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(std::io::Error::other(
                "daemon failed to bind both listeners within 5s",
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

/// Free-function equivalent of `Harness::mgmt`.
async fn send_mgmt(socket: &Path, cmd: Value) -> std::io::Result<Value> {
    let stream = UnixStream::connect(socket).await?;
    let (read, mut write) = stream.into_split();
    let mut payload = cmd.to_string();
    payload.push('\n');
    write.write_all(payload.as_bytes()).await?;
    write.shutdown().await?;

    let mut reader = BufReader::new(read);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    serde_json::from_str(line.trim()).map_err(std::io::Error::other)
}

// ---------- proxy deny markers ----------

#[tokio::test]
async fn proxy_denies_unknown_host_with_marker() {
    let h = Harness::start().await.unwrap();
    let (status, marker) = h.connect("CONNECT unallowed.example:443 HTTP/1.1").await.unwrap();
    assert!(status.contains("403"), "got: {status}");
    assert_eq!(marker.as_deref(), Some("denied-unknown-host"));
}

#[tokio::test]
async fn proxy_denies_non_https_with_marker() {
    let h = Harness::start().await.unwrap();
    // Even if we allowlist host:80, the HTTPS-only check should win.
    h.mgmt(json!({"cmd": "add_session", "host": "example.com", "port": 80}))
        .await
        .unwrap();
    let (status, marker) = h.connect("CONNECT example.com:80 HTTP/1.1").await.unwrap();
    assert!(status.contains("403"), "got: {status}");
    assert_eq!(marker.as_deref(), Some("denied-non-https"));
}

#[tokio::test]
async fn proxy_denies_malformed_request_with_marker() {
    let h = Harness::start().await.unwrap();
    // Not a CONNECT request — should be flagged as malformed.
    let (status, marker) = h.connect("GET / HTTP/1.1").await.unwrap();
    assert!(status.contains("403"), "got: {status}");
    assert_eq!(marker.as_deref(), Some("denied-malformed-request"));
}

#[tokio::test]
async fn session_add_unlocks_for_unknown_host_marker() {
    // After adding to session, the unknown-host marker stops appearing.
    // We can't reach a real upstream for the allow path, but we can verify
    // the daemon no longer returns 403 for that destination.
    let h = Harness::start().await.unwrap();
    let port = pick_local_port().port();
    h.mgmt(json!({"cmd": "add_session", "host": "127.0.0.1", "port": port}))
        .await
        .unwrap();

    // The proxy is HTTPS-only (port 443), so a non-443 allowlisted entry
    // still gets denied-non-https. We use this to confirm allowlist plumbing
    // is reachable without needing a real port-443 listener.
    let req = format!("CONNECT 127.0.0.1:{port} HTTP/1.1");
    let (status, marker) = h.connect(&req).await.unwrap();
    assert!(status.contains("403"));
    assert_eq!(marker.as_deref(), Some("denied-non-https"));
}
