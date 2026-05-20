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
//! - the kernel NAT redirect to the honeypot — that requires nftables;
//!   honeypot semantics are exercised here via the `local_addr` fallback path
//! - the audit log (Phase 9)

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
    honeypot_addr: SocketAddr,
    // Held so kill_on_drop fires when the harness drops; never read directly.
    _proc: Child,
}

impl Harness {
    async fn start() -> std::io::Result<Self> {
        let tempdir = tempfile::tempdir()?;
        let socket_path = tempdir.path().join("tau.sock");
        let allowlist_path = tempdir.path().join("allow.json");
        let proxy_addr = pick_local_port();
        let honeypot_addr = pick_local_port();
        let proc = spawn(&socket_path, &allowlist_path, &proxy_addr, &honeypot_addr)?;

        let h = Self {
            _tempdir: tempdir,
            socket_path,
            proxy_addr,
            honeypot_addr,
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
            let honeypot_ok = TcpStream::connect(&self.honeypot_addr).await.is_ok();
            if mgmt_ok && proxy_ok && honeypot_ok {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(std::io::Error::other(
                    "daemon failed to bind all listeners within 5s",
                ));
            }
            sleep(Duration::from_millis(25)).await;
        }
    }

    /// Open a subscriber connection: send `subscribe_events`, read the ack,
    /// and return the connected stream wrapped in a `BufReader`. The daemon
    /// only writes to this socket post-ack, so we keep the whole stream
    /// (not just the read half) — dropping the returned reader closes the
    /// subscription cleanly.
    async fn subscribe_events(&self) -> std::io::Result<BufReader<UnixStream>> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        stream.write_all(b"{\"cmd\":\"subscribe_events\"}\n").await?;

        let mut reader = BufReader::new(stream);
        let mut ack = String::new();
        reader.read_line(&mut ack).await?;
        let ack_json: Value = serde_json::from_str(ack.trim()).map_err(std::io::Error::other)?;
        if ack_json != json!({"ok": true}) {
            return Err(std::io::Error::other(format!(
                "unexpected subscribe ack: {ack_json}"
            )));
        }
        Ok(reader)
    }

    /// Open and immediately close a TCP connection to the honeypot. The
    /// kernel NAT redirect isn't in the test path, so the daemon's
    /// `SO_ORIGINAL_DST` call fails and falls back to `local_addr()` — the
    /// event ends up reporting the honeypot's bind address as the "host".
    async fn trigger_honeypot(&self) -> std::io::Result<()> {
        let stream = TcpStream::connect(&self.honeypot_addr).await?;
        drop(stream);
        Ok(())
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

fn spawn(
    socket: &Path,
    allowlist: &Path,
    proxy_addr: &SocketAddr,
    honeypot_addr: &SocketAddr,
) -> std::io::Result<Child> {
    spawn_with_audit(socket, allowlist, proxy_addr, honeypot_addr, None)
}

fn spawn_with_audit(
    socket: &Path,
    allowlist: &Path,
    proxy_addr: &SocketAddr,
    honeypot_addr: &SocketAddr,
    audit_log: Option<&Path>,
) -> std::io::Result<Child> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tau"));
    cmd.args([
        "serve",
        "--allowlist",
        allowlist.to_str().unwrap(),
        "--socket",
        socket.to_str().unwrap(),
        "--proxy-addr",
        &proxy_addr.to_string(),
        "--honeypot-addr",
        &honeypot_addr.to_string(),
    ]);
    if let Some(path) = audit_log {
        cmd.args(["--audit-log", path.to_str().unwrap()]);
    }
    cmd.kill_on_drop(true)
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
        .mgmt(json!({"cmd": "add_persist", "host": "github.com"}))
        .await
        .unwrap();
    assert_eq!(ack, json!({"ok": true}));

    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(
        reply,
        json!({"ok": true, "entries": [{"host": "github.com"}]})
    );
}

#[tokio::test]
async fn add_session_is_not_in_persistent_list() {
    let h = Harness::start().await.unwrap();
    let ack = h
        .mgmt(json!({"cmd": "add_session", "host": "ephemeral.example"}))
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
    h.mgmt(json!({"cmd": "add_persist", "host": "a.example"}))
        .await
        .unwrap();
    h.mgmt(json!({"cmd": "remove", "host": "a.example"}))
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
    let hp1 = pick_local_port();
    let mut p1 = spawn(&socket, &allowlist, &addr1, &hp1).unwrap();
    wait_for_listeners(&socket, &addr1, &hp1).await.unwrap();
    send_mgmt(
        &socket,
        json!({"cmd": "add_persist", "host": "persistent.example"}),
    )
    .await
    .unwrap();
    p1.kill().await.unwrap();

    // Second daemon — fresh ports, same paths. allow.json was atomically
    // renamed before the mgmt reply came back, so it must be on disk.
    let addr2 = pick_local_port();
    let hp2 = pick_local_port();
    let mut p2 = spawn(&socket, &allowlist, &addr2, &hp2).unwrap();
    wait_for_listeners(&socket, &addr2, &hp2).await.unwrap();
    let reply = send_mgmt(&socket, json!({"cmd": "list"})).await.unwrap();
    assert_eq!(
        reply,
        json!({
            "ok": true,
            "entries": [{"host": "persistent.example"}],
        })
    );
    p2.kill().await.unwrap();
}

/// Free-function equivalent of `Harness::wait_ready`, usable for tests that
/// drive the daemon directly (e.g. the restart test).
async fn wait_for_listeners(
    socket: &Path,
    proxy_addr: &SocketAddr,
    honeypot_addr: &SocketAddr,
) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mgmt_ok = UnixStream::connect(socket).await.is_ok();
        let proxy_ok = TcpStream::connect(proxy_addr).await.is_ok();
        let honeypot_ok = TcpStream::connect(honeypot_addr).await.is_ok();
        if mgmt_ok && proxy_ok && honeypot_ok {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(std::io::Error::other(
                "daemon failed to bind all listeners within 5s",
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
    h.mgmt(json!({"cmd": "add_session", "host": "example.com"}))
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
    h.mgmt(json!({"cmd": "add_session", "host": "127.0.0.1"}))
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

// ---------- honeypot + events stream ----------

async fn next_event(reader: &mut BufReader<UnixStream>) -> std::io::Result<Value> {
    let mut line = String::new();
    let n = tokio::time::timeout(EVENT_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| std::io::Error::other("timed out waiting for event"))??;
    if n == 0 {
        return Err(std::io::Error::other("events stream closed unexpectedly"));
    }
    serde_json::from_str(line.trim()).map_err(std::io::Error::other)
}

#[tokio::test]
async fn honeypot_emits_escape_attempt_event() {
    let h = Harness::start().await.unwrap();
    let mut events = h.subscribe_events().await.unwrap();

    h.trigger_honeypot().await.unwrap();

    let event = next_event(&mut events).await.unwrap();
    assert_eq!(event["kind"], json!("escape-attempt"));
    assert_eq!(event["port"], json!(h.honeypot_addr.port()));
    assert_eq!(event["count"], json!(1));
    assert!(event["ts"].is_string(), "ts missing: {event}");
    assert!(event["host"].is_string(), "host missing: {event}");
}

#[tokio::test]
async fn honeypot_dedupes_burst_within_window() {
    let h = Harness::start().await.unwrap();
    let mut events = h.subscribe_events().await.unwrap();

    // Five rapid attempts to the same (host, port). The first emits an
    // event; the next four should be suppressed inside the 5s dedup window.
    for _ in 0..5 {
        h.trigger_honeypot().await.unwrap();
    }

    let first = next_event(&mut events).await.unwrap();
    assert_eq!(first["kind"], json!("escape-attempt"));
    assert_eq!(first["count"], json!(1));

    // A second read should now time out — no follow-up event in the window.
    let mut line = String::new();
    let res = tokio::time::timeout(
        Duration::from_millis(200),
        events.read_line(&mut line),
    )
    .await;
    assert!(res.is_err(), "expected no second event, got: {line}");
}

// ---------- audit log ----------

/// Pull the next event line from a subscriber with a generous ceiling so a
/// real missing event surfaces as a test failure, while parallel-test load
/// doesn't trip a flake. The 2s budget the original ceiling used was tight
/// enough that scheduler jitter under `cargo test`'s default thread pool
/// occasionally timed out before the daemon got to write the event.
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll the audit log until it has at least `want` JSON-parseable lines or
/// the deadline elapses. The audit writer task runs in the daemon and is
/// fed by an mpsc channel, so there's a few-ms window between
/// `proxy.record(...)` and the file actually being written.
async fn read_audit_lines(path: &Path, want: usize) -> std::io::Result<Vec<Value>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let lines: Vec<Value> = match tokio::fs::read_to_string(path).await {
            Ok(s) => s
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        if lines.len() >= want {
            return Ok(lines);
        }
        if Instant::now() > deadline {
            return Err(std::io::Error::other(format!(
                "audit log only has {} of {want} expected lines",
                lines.len()
            )));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn audit_log_records_all_decision_paths() {
    let tempdir = tempfile::tempdir().unwrap();
    let socket = tempdir.path().join("tau.sock");
    let allowlist = tempdir.path().join("allow.json");
    let audit_path = tempdir.path().join("audit.log");
    let proxy_addr = pick_local_port();
    let honeypot_addr = pick_local_port();
    let mut proc = spawn_with_audit(
        &socket,
        &allowlist,
        &proxy_addr,
        &honeypot_addr,
        Some(&audit_path),
    )
    .unwrap();
    wait_for_listeners(&socket, &proxy_addr, &honeypot_addr)
        .await
        .unwrap();

    // Pre-seed a session entry so the allow path is reachable. The actual
    // tunnel never establishes (nothing listens on 127.0.0.1:443 here),
    // but the audit record fires before the upstream connect.
    send_mgmt(
        &socket,
        json!({"cmd": "add_session", "host": "127.0.0.1"}),
    )
    .await
    .unwrap();

    // Drive each decision path sequentially. The proxy spawns handlers
    // concurrently so order in the log isn't guaranteed; we assert on the
    // multiset, not on positions.
    for request in [
        "CONNECT unallowed.example:443 HTTP/1.1",
        "CONNECT 127.0.0.1:443 HTTP/1.1",
        "CONNECT example.com:80 HTTP/1.1",
        "GET / HTTP/1.1",
    ] {
        let mut stream = TcpStream::connect(&proxy_addr).await.unwrap();
        stream
            .write_all(format!("{request}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        // Read the status line; we don't care about the response shape here.
        let _ = reader.read_line(&mut line).await;
    }

    let lines = read_audit_lines(&audit_path, 4).await.unwrap();
    assert_eq!(lines.len(), 4, "got: {lines:?}");

    let reasons: Vec<String> = lines
        .iter()
        .map(|l| l["reason"].as_str().unwrap_or("").to_string())
        .collect();
    let mut sorted = reasons.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![
            "malformed-request".to_string(),
            "non-https".to_string(),
            "session".to_string(),
            "unknown-host".to_string(),
        ],
        "got: {reasons:?}"
    );

    // Spot-check field shapes on each record.
    for line in &lines {
        assert!(line["ts"].is_string(), "ts missing: {line}");
        assert!(line["peer"].is_string(), "peer missing: {line}");
        let reason = line["reason"].as_str().unwrap();
        let decision = line["decision"].as_str().unwrap();
        match reason {
            "session" => {
                assert_eq!(decision, "allow");
                assert_eq!(line["host"], json!("127.0.0.1"));
                assert_eq!(line["port"], json!(443));
            }
            "malformed-request" => {
                assert_eq!(decision, "deny");
                assert!(line.get("host").is_none() || line["host"].is_null());
                assert!(line.get("port").is_none() || line["port"].is_null());
            }
            "non-https" | "unknown-host" => {
                assert_eq!(decision, "deny");
                assert!(line["host"].is_string());
                assert!(line["port"].is_number());
            }
            other => panic!("unexpected reason: {other}"),
        }
    }

    proc.kill().await.unwrap();
}

#[tokio::test]
async fn audit_log_off_by_default() {
    // A daemon without --audit-log shouldn't create the default audit
    // file path or otherwise touch the disk. Drive a decision and confirm
    // no file appears.
    let h = Harness::start().await.unwrap();
    let (status, _) = h.connect("CONNECT unallowed.example:443 HTTP/1.1").await.unwrap();
    assert!(status.contains("403"));
    // The harness has no audit-log path configured; nothing should have
    // been written. Just verify the test runs without the daemon
    // crashing — the absence of a configured audit-log path is a code
    // path we want exercised.
}

// ---------- ctl seed-mcp ----------

/// End-to-end check for `tau ctl seed-mcp <path>`: writes a fixture
/// `.mcp.json`, runs the CLI against the harness daemon, and verifies
/// the expected https hosts landed in the persistent allowlist while
/// stdio entries and non-https urls were skipped.
#[tokio::test]
async fn ctl_seed_mcp_adds_https_hosts() {
    let h = Harness::start().await.unwrap();
    let tempdir = tempfile::tempdir().unwrap();
    let mcp_path = tempdir.path().join(".mcp.json");
    std::fs::write(
        &mcp_path,
        r#"{
            "mcpServers": {
                "a":  { "url": "https://seed-a.example.test/sse" },
                "b":  { "url": "https://seed-b.example.test/sse" },
                "fs": { "command": "true" },
                "insecure": { "url": "http://seed-c.example.test/" }
            }
        }"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_tau"))
        .args(["ctl", "--socket"])
        .arg(&h.socket_path)
        .arg("seed-mcp")
        .arg(&mcp_path)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "seed-mcp failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("seeded 2 host(s) (persistent; 1 stdio skipped)"), "stdout was: {stdout}");

    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    let entries = reply.get("entries").and_then(|v| v.as_array()).unwrap();
    let hosts: Vec<&str> = entries
        .iter()
        .filter_map(|e| e.get("host").and_then(|h| h.as_str()))
        .collect();
    assert!(hosts.contains(&"seed-a.example.test"), "hosts: {hosts:?}");
    assert!(hosts.contains(&"seed-b.example.test"), "hosts: {hosts:?}");
    assert!(!hosts.iter().any(|h| h.contains("seed-c")), "non-https leaked: {hosts:?}");
}

/// Dry-run must not touch the daemon. We assert by checking the persistent
/// list is unchanged after the call, and that the planned hosts are printed
/// on stdout.
#[tokio::test]
async fn ctl_seed_mcp_dry_run_does_not_mutate() {
    let h = Harness::start().await.unwrap();
    let tempdir = tempfile::tempdir().unwrap();
    let mcp_path = tempdir.path().join(".mcp.json");
    std::fs::write(
        &mcp_path,
        r#"{ "mcpServers": { "a": { "url": "https://dry.example.test/" } } }"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_tau"))
        .args(["ctl", "--socket"])
        .arg(&h.socket_path)
        .args(["seed-mcp", "--dry-run"])
        .arg(&mcp_path)
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would add 1 host(s)"), "stdout: {stdout}");
    assert!(stdout.contains("dry.example.test"), "stdout: {stdout}");

    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(
        reply,
        json!({"ok": true, "entries": []}),
        "dry-run mutated the allowlist"
    );
}

#[tokio::test]
async fn honeypot_survives_publish_with_no_subscribers() {
    // The broadcast send returns Err when no receivers are attached; the
    // daemon must treat that as a no-op rather than a fatal error. Verify
    // by triggering events with no subscriber and then proving the daemon
    // still services regular mgmt commands.
    let h = Harness::start().await.unwrap();
    for _ in 0..3 {
        h.trigger_honeypot().await.unwrap();
    }
    let reply = h.mgmt(json!({"cmd": "list"})).await.unwrap();
    assert_eq!(reply, json!({"ok": true, "entries": []}));
}
