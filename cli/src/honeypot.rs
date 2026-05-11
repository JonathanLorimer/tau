//! Honeypot listener for Phase 8.5 escape detection.
//!
//! When the NixOS module's nftables rule is active, traffic from the jail UID
//! that doesn't target the proxy gets DNAT'd to `127.0.0.1:8119` — this
//! listener. We recover the pre-DNAT destination via `SO_ORIGINAL_DST`, emit
//! a structured `escape-attempt` event on the daemon's events channel, and
//! close the socket without reading or writing a single byte.
//!
//! Security posture (see PLAN.md "Threat model for the honeypot"):
//!   - never `read()` or `write()` — the suspect process has zero attack
//!     surface against us beyond a TCP accept;
//!   - semaphore-bounded concurrency caps simultaneous accepts so a flood
//!     can't FD-exhaust the daemon;
//!   - hard per-connection timeout backstops the semaphore against
//!     slowloris-style half-open exhaustion;
//!   - dedup at the event layer suppresses retry-storm spam in pi.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio::time::timeout;

use crate::util::iso_timestamp;

/// Coalescing window: a second attempt to the same `(ip, port)` within this
/// interval is counted but not emitted as its own event. The next emission
/// after the window expires carries the accumulated count.
const DEDUP_WINDOW: Duration = Duration::from_secs(5);

/// Cap on simultaneous honeypot accepts. The honeypot accepts arbitrary
/// bytes from a process that has already shown it ignores our policy;
/// bounding concurrency prevents FD exhaustion.
const MAX_CONCURRENT: usize = 32;

/// Hard ceiling on how long a single honeypot connection can live in our
/// process. Backstops the semaphore against half-open exhaustion.
const PER_CONN_TIMEOUT: Duration = Duration::from_millis(500);

/// Capacity of the broadcast channel. Subscribers that lag past this miss
/// events (with a `Lagged` warning logged); on a personal machine a single
/// extension is the only subscriber and 64 is plenty.
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// Events published by the daemon and consumed by the extension.
///
/// Adding a variant is a versioned-contract change: the extension's
/// `MARKER_HEADER` table in `extension/index.ts` must learn it in lockstep.
/// See PLAN.md "Deny marker taxonomy" — the events stream is the
/// out-of-band sibling of the in-band 403 markers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Event {
    /// A process from the jail UID bypassed `HTTPS_PROXY` and got caught by
    /// the kernel NAT redirect. `count` is the number of attempts to this
    /// `(host, port)` accumulated since the previous emission (≥1).
    EscapeAttempt {
        ts: String,
        host: IpAddr,
        port: u16,
        count: u32,
    },
}

pub type EventTx = broadcast::Sender<Event>;

/// Build a fresh broadcast channel. The returned `Sender` is cloned into both
/// the honeypot (for `send`) and mgmt (for `subscribe` per subscriber).
pub fn channel() -> EventTx {
    broadcast::channel(EVENT_CHANNEL_CAPACITY).0
}

struct DedupEntry {
    last_emit: Option<Instant>,
    suppressed: u32,
}

type Dedup = Arc<Mutex<HashMap<(IpAddr, u16), DedupEntry>>>;

pub async fn run(addr: SocketAddr, events: EventTx) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("honeypot listening on {addr}");

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let dedup: Dedup = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((sock, peer)) => {
                let permit = match sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Semaphore full → drop the connection without taking
                        // any bytes. Peer sees a fast close (RST or FIN).
                        tracing::debug!(%peer, "honeypot semaphore full; dropping");
                        drop(sock);
                        continue;
                    }
                };
                let events = events.clone();
                let dedup = dedup.clone();
                tokio::spawn(async move {
                    let _ = timeout(PER_CONN_TIMEOUT, handle(sock, events, dedup)).await;
                    drop(permit);
                });
            }
            Err(e) => tracing::error!("honeypot accept error: {e}"),
        }
    }
}

async fn handle(sock: TcpStream, events: EventTx, dedup: Dedup) {
    let dst = match original_dst(&sock) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("honeypot could not recover destination: {e}");
            return;
        }
    };
    // Close the socket before doing anything else. We never read or write —
    // see the security posture comment at the top of the file.
    drop(sock);

    let ip = dst.ip();
    let port = dst.port();
    if let Some(count) = update_dedup(&dedup, ip, port).await {
        let event = Event::EscapeAttempt {
            ts: iso_timestamp(),
            host: ip,
            port,
            count,
        };
        tracing::warn!(%ip, port, count, "escape-attempt");
        // `send` only errors when there are zero receivers — that's a fine
        // state to be in (no extension subscribed yet) and we just drop.
        let _ = events.send(event);
    }
}

async fn update_dedup(dedup: &Dedup, ip: IpAddr, port: u16) -> Option<u32> {
    let now = Instant::now();
    let mut map = dedup.lock().await;
    let entry = map
        .entry((ip, port))
        .or_insert(DedupEntry { last_emit: None, suppressed: 0 });

    let should_emit = match entry.last_emit {
        None => true,
        Some(last) => now.duration_since(last) >= DEDUP_WINDOW,
    };
    if should_emit {
        let count = entry.suppressed + 1;
        entry.last_emit = Some(now);
        entry.suppressed = 0;
        Some(count)
    } else {
        entry.suppressed += 1;
        None
    }
}

/// Recover the pre-DNAT destination of a connection redirected here by the
/// kernel. If `SO_ORIGINAL_DST` isn't available (no conntrack entry, or
/// running on a host that didn't redirect us at all), fall back to the
/// listener's local address — useful for tests, and harmless in production
/// because real escape attempts always traverse the NAT.
fn original_dst(sock: &TcpStream) -> io::Result<SocketAddr> {
    match so_original_dst(sock) {
        Ok(addr) => Ok(addr),
        Err(e) => {
            tracing::debug!("SO_ORIGINAL_DST unavailable ({e}); using local_addr");
            sock.local_addr()
        }
    }
}

#[cfg(target_os = "linux")]
fn so_original_dst(sock: &TcpStream) -> io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    let fd = sock.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    let port = u16::from_be(addr.sin_port);
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

#[cfg(not(target_os = "linux"))]
fn so_original_dst(_sock: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dedup() -> Dedup {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[tokio::test]
    async fn first_attempt_emits_with_count_one() {
        let d = dedup();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(update_dedup(&d, ip, 443).await, Some(1));
    }

    #[tokio::test]
    async fn second_attempt_in_window_is_suppressed() {
        let d = dedup();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(update_dedup(&d, ip, 443).await, Some(1));
        assert_eq!(update_dedup(&d, ip, 443).await, None);
        assert_eq!(update_dedup(&d, ip, 443).await, None);
    }

    #[tokio::test]
    async fn different_destinations_dedup_independently() {
        let d = dedup();
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(update_dedup(&d, a, 443).await, Some(1));
        assert_eq!(update_dedup(&d, b, 443).await, Some(1));
    }
}
