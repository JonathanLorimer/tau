use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::allowlist::Allowlist;

const DENIED: &[u8] = b"HTTP/1.1 403 Forbidden\r\nX-Pi-Firewall-Status: denied-unknown-host\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

pub async fn run(allowlist: Arc<RwLock<Allowlist>>) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8118").await?;
    tracing::info!("proxy listening on 127.0.0.1:8118");
    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let allowlist = allowlist.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(socket, allowlist).await {
                        tracing::debug!(%peer, "connection closed: {e}");
                    }
                });
            }
            Err(e) => tracing::error!("accept error: {e}"),
        }
    }
}

async fn handle(socket: TcpStream, allowlist: Arc<RwLock<Allowlist>>) -> std::io::Result<()> {
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
        tracing::warn!("unparseable request: {:?}", request_line.trim());
        write_half.write_all(DENIED).await?;
        return Ok(());
    };

    // Architectural anchor: HTTPS only — plain HTTP is rejected
    if port != 443 {
        tracing::warn!(%host, port, "rejected non-HTTPS port");
        write_half.write_all(DENIED).await?;
        return Ok(());
    }

    if !allowlist.read().await.check(&host, port) {
        tracing::info!(%host, port, "denied");
        write_half.write_all(DENIED).await?;
        return Ok(());
    }

    tracing::info!(%host, port, "allowed, tunneling");
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
