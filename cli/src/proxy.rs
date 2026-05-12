use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::allowlist::Allowlist;
use crate::audit::{self, Audit};

// Deny markers per PLAN.md "Deny marker taxonomy". The marker is the contract
// between the daemon and the extension; renaming or repurposing one of these
// is a coordinated change with extension/index.ts.
macro_rules! deny_response {
    ($marker:literal) => {
        concat!(
            "HTTP/1.1 403 Forbidden\r\n",
            "X-Pi-Firewall-Status: ", $marker, "\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n",
            "\r\n"
        ).as_bytes()
    };
}

const DENIED_UNKNOWN_HOST: &[u8] = deny_response!("denied-unknown-host");
const DENIED_NON_HTTPS: &[u8] = deny_response!("denied-non-https");
const DENIED_MALFORMED_REQUEST: &[u8] = deny_response!("denied-malformed-request");
const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

pub async fn run(
    addr: SocketAddr,
    allowlist: Arc<RwLock<Allowlist>>,
    audit: Audit,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("proxy listening on {addr}");
    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let allowlist = allowlist.clone();
                let audit = audit.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(socket, peer, allowlist, audit).await {
                        tracing::debug!(%peer, "connection closed: {e}");
                    }
                });
            }
            Err(e) => tracing::error!("accept error: {e}"),
        }
    }
}

async fn handle(
    socket: TcpStream,
    peer: SocketAddr,
    allowlist: Arc<RwLock<Allowlist>>,
    audit: Audit,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = socket.into_split();
    let mut reader = BufReader::new(read_half);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    // Drain headers until blank line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // CONNECT clients must not send tunnel data before receiving our 200,
    // so the read buffer is always empty here. Loss of any buffered bytes
    // via into_inner() would indicate a protocol violation by the client.
    debug_assert!(reader.buffer().is_empty(), "unexpected data after CONNECT headers");
    let read_half = reader.into_inner();

    let Some((host, port)) = parse_authority(&request_line) else {
        // Empty input is a bare TCP probe (port-readiness check, healthcheck,
        // etc.) — not a CONNECT request someone tried and got wrong, so skip
        // the audit noise. Anything non-empty is a real malformed request.
        let trimmed = request_line.trim();
        if trimmed.is_empty() {
            tracing::debug!(%peer, "empty request; treating as probe");
        } else {
            tracing::warn!("unparseable request: {trimmed:?}");
            audit.record(audit::deny_anonymous(peer, "malformed-request"));
        }
        let _ = write_half.write_all(DENIED_MALFORMED_REQUEST).await;
        return Ok(());
    };

    // Architectural anchor: HTTPS only — plain HTTP is rejected
    if port != 443 {
        tracing::warn!(%host, port, "rejected non-HTTPS port");
        audit.record(audit::deny(&host, port, peer, "non-https"));
        write_half.write_all(DENIED_NON_HTTPS).await?;
        return Ok(());
    }

    let source = allowlist.read().await.classify(&host);
    let Some(source) = source else {
        tracing::info!(%host, port, "denied");
        audit.record(audit::deny(&host, port, peer, "unknown-host"));
        write_half.write_all(DENIED_UNKNOWN_HOST).await?;
        return Ok(());
    };

    tracing::info!(%host, port, source = source.as_str(), "allowed, tunneling");
    audit.record(audit::allow(&host, port, peer, source.as_str()));
    write_half.write_all(CONNECTED).await?;

    let mut socket = read_half.reunite(write_half).expect("same socket");
    let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;
    tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
    Ok(())
}

fn parse_authority(line: &str) -> Option<(String, u16)> {
    let line = line.trim();
    let mut parts = line.splitn(3, ' ');
    if parts.next()? != "CONNECT" {
        return None;
    }
    let authority = parts.next()?;
    let (host, port_str) = authority.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_authority() {
        assert_eq!(
            parse_authority("CONNECT github.com:443 HTTP/1.1\r\n"),
            Some(("github.com".to_owned(), 443))
        );
        assert_eq!(
            parse_authority("CONNECT 192.168.1.1:8443 HTTP/1.0"),
            Some(("192.168.1.1".to_owned(), 8443))
        );
    }

    #[test]
    fn parse_strips_crlf() {
        assert_eq!(
            parse_authority("CONNECT github.com:443 HTTP/1.1\r\n"),
            parse_authority("CONNECT github.com:443 HTTP/1.1\n"),
        );
    }

    #[test]
    fn parse_rejects_non_connect() {
        assert_eq!(parse_authority("GET / HTTP/1.1\r\n"), None);
        assert_eq!(parse_authority("POST /api HTTP/1.1"), None);
    }

    #[test]
    fn parse_rejects_missing_port() {
        assert_eq!(parse_authority("CONNECT github.com HTTP/1.1"), None);
    }

    #[test]
    fn parse_rejects_empty() {
        assert_eq!(parse_authority(""), None);
        assert_eq!(parse_authority("\r\n"), None);
    }
}
