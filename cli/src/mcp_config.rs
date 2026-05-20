//! Read `.mcp.json` style config files and pull out the hosts the proxy
//! will need to allow.
//!
//! Schema (matches `pi-mcp-adapter`'s `ServerEntry`):
//!
//! ```jsonc
//! {
//!   "mcpServers": {
//!     "someserver": { "url": "https://mcp.example.com/sse", ... },
//!     "stdio-thing": { "command": "npx", "args": [...] }
//!   }
//! }
//! ```
//!
//! We only care about entries with a `url` field. The proxy is HTTPS-only
//! (architectural anchor #5) so non-`https://` urls are skipped with a
//! diagnostic, never silently demoted.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::mgmt::{send_blocking, Command, Reply};

/// Per-request budget when seeding from `tau jail`. Generous enough for a
/// healthy local daemon, short enough that a dead daemon doesn't visibly
/// stall the jail launch.
pub const SEED_TIMEOUT: Duration = Duration::from_millis(500);

/// Standard locations `pi-mcp-adapter` reads, in the order it merges them.
/// We deliberately do not chase `imports` or other-tool configs
/// (cursor, claude, etc.) here — keep stage 1 narrow.
pub fn default_paths(cwd: &Path, home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".config").join("mcp").join("mcp.json"),
        home.join(".pi").join("agent").join("mcp.json"),
        cwd.join(".mcp.json"),
        cwd.join(".pi").join("mcp.json"),
    ]
}

/// Result of scanning one or more config files.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Files that existed and were read.
    pub files_read: Vec<PathBuf>,
    /// Files we tried to read but couldn't parse.
    pub parse_errors: Vec<(PathBuf, String)>,
    /// Distinct https hosts found, sorted.
    pub hosts: Vec<String>,
    /// Count of stdio (command-based) entries we skipped.
    pub stdio_skipped: usize,
    /// Url-bearing entries we skipped because the url wasn't https.
    pub non_https_skipped: Vec<String>,
    /// Url-bearing entries where we couldn't extract a host.
    pub unparseable_urls: Vec<String>,
}

#[derive(Deserialize)]
struct McpFile {
    #[serde(default)]
    mcp_servers: serde_json::Map<String, serde_json::Value>,
}

// Accept both camelCase ("mcpServers", the standard) and snake_case just in case.
impl McpFile {
    fn from_value(v: serde_json::Value) -> Result<Self, String> {
        let obj = v.as_object().ok_or_else(|| "top-level must be an object".to_string())?;
        let servers = obj
            .get("mcpServers")
            .or_else(|| obj.get("mcp_servers"))
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let map = match servers {
            serde_json::Value::Object(m) => m,
            _ => return Err("`mcpServers` must be an object".into()),
        };
        Ok(McpFile { mcp_servers: map })
    }
}

/// Scan a set of paths. Missing files are silently ignored; malformed files
/// are recorded in `parse_errors` and skipped (default-deny-flavoured: we
/// don't want a typo to silently widen the allowlist).
pub fn scan(paths: &[PathBuf]) -> Scan {
    let mut out = Scan::default();
    let mut hosts: BTreeSet<String> = BTreeSet::new();

    for path in paths {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                out.parse_errors.push((path.clone(), format!("read: {e}")));
                continue;
            }
        };
        let json: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                out.parse_errors.push((path.clone(), format!("json: {e}")));
                continue;
            }
        };
        let file = match McpFile::from_value(json) {
            Ok(f) => f,
            Err(e) => {
                out.parse_errors.push((path.clone(), e));
                continue;
            }
        };
        out.files_read.push(path.clone());

        for (_name, entry) in file.mcp_servers {
            let url = entry.get("url").and_then(|v| v.as_str());
            match url {
                None => {
                    if entry.get("command").is_some() {
                        out.stdio_skipped += 1;
                    }
                    // Entries with neither url nor command are malformed
                    // but not our problem to diagnose here.
                }
                Some(url) => match parse_https_host(url) {
                    HostParse::Host(h) => {
                        hosts.insert(h);
                    }
                    HostParse::NotHttps => out.non_https_skipped.push(url.to_string()),
                    HostParse::Unparseable => out.unparseable_urls.push(url.to_string()),
                },
            }
        }
    }

    out.hosts = hosts.into_iter().collect();
    out
}

#[derive(Debug, PartialEq, Eq)]
enum HostParse {
    Host(String),
    NotHttps,
    Unparseable,
}

/// Extract the host from an `https://` URL. Strips port and any
/// userinfo / path / query / fragment. IPv6 literals (`[::1]`) are
/// preserved with their brackets, matching what the proxy sees on a
/// `CONNECT` line.
fn parse_https_host(url: &str) -> HostParse {
    let url = url.trim();
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => {
            // Anything we can scheme-detect but isn't https is a hard skip;
            // unparseable strings get their own bucket so the user notices.
            if url.contains("://") {
                return HostParse::NotHttps;
            }
            return HostParse::Unparseable;
        }
    };

    // Strip userinfo: everything up to and including the first '@' before
    // the first '/'.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, _) = rest.split_at(authority_end);
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if authority.is_empty() {
        return HostParse::Unparseable;
    }

    // IPv6 in brackets: keep the brackets, strip any :port that follows ']'.
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return HostParse::Host(format!("[{}]", &stripped[..end]));
        }
        return HostParse::Unparseable;
    }

    // host[:port]
    let host = match authority.rfind(':') {
        Some(i) => &authority[..i],
        None => authority,
    };
    if host.is_empty() {
        return HostParse::Unparseable;
    }
    HostParse::Host(host.to_string())
}

/// Outcome of pushing one host to the daemon. Surfaced so the caller can
/// print a single human-readable summary instead of one line per host.
#[derive(Debug)]
pub enum SeedOutcome {
    Added,
    DaemonError(std::io::Error),
}

/// Send `AddPersist` for each host in `hosts` via a blocking mgmt connection.
///
/// Errors are returned per-host rather than short-circuiting: a transient
/// failure on host N shouldn't prevent host N+1 from being seeded, and the
/// caller (jail) wants to continue launching pi either way — the extension's
/// runtime prompt UX is the fallback for anything we miss.
pub fn seed_hosts_blocking(socket: &Path, hosts: &[String]) -> Vec<(String, SeedOutcome)> {
    let mut out = Vec::with_capacity(hosts.len());
    for host in hosts {
        let cmd = Command::AddPersist { host: host.clone() };
        let outcome = match send_blocking(socket, &cmd, SEED_TIMEOUT) {
            Ok(Reply::Simple { ok: true }) => SeedOutcome::Added,
            Ok(Reply::Simple { ok: false }) => {
                SeedOutcome::DaemonError(std::io::Error::other("daemon returned ok=false"))
            }
            Ok(Reply::Entries { .. }) => {
                SeedOutcome::DaemonError(std::io::Error::other("unexpected entries reply"))
            }
            Err(e) => SeedOutcome::DaemonError(e),
        };
        out.push((host.clone(), outcome));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_host_plain() {
        assert_eq!(
            parse_https_host("https://mcp.notion.com/sse"),
            HostParse::Host("mcp.notion.com".into())
        );
    }

    #[test]
    fn parse_host_with_port() {
        assert_eq!(
            parse_https_host("https://example.com:8443/path"),
            HostParse::Host("example.com".into())
        );
    }

    #[test]
    fn parse_host_with_userinfo() {
        assert_eq!(
            parse_https_host("https://u:p@example.com/x"),
            HostParse::Host("example.com".into())
        );
    }

    #[test]
    fn parse_host_no_path() {
        assert_eq!(
            parse_https_host("https://example.com"),
            HostParse::Host("example.com".into())
        );
    }

    #[test]
    fn parse_host_ipv6() {
        assert_eq!(
            parse_https_host("https://[::1]:8443/x"),
            HostParse::Host("[::1]".into())
        );
    }

    #[test]
    fn parse_host_http_rejected() {
        assert_eq!(parse_https_host("http://example.com"), HostParse::NotHttps);
    }

    #[test]
    fn parse_host_garbage() {
        assert_eq!(parse_https_host("not a url"), HostParse::Unparseable);
        assert_eq!(parse_https_host("https://"), HostParse::Unparseable);
    }

    fn write_tmp(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn scan_mixes_url_and_stdio() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_tmp(
            tmp.path(),
            ".mcp.json",
            r#"{
                "mcpServers": {
                    "notion":   { "url": "https://mcp.notion.com/sse" },
                    "linear":   { "url": "https://mcp.linear.app/sse" },
                    "fs":       { "command": "npx", "args": ["mcp-fs"] },
                    "insecure": { "url": "http://example.com" },
                    "dup":      { "url": "https://mcp.notion.com/v2" }
                }
            }"#,
        );
        let s = scan(&[p.clone()]);
        assert_eq!(s.files_read, vec![p]);
        assert_eq!(s.hosts, vec!["mcp.linear.app".to_string(), "mcp.notion.com".to_string()]);
        assert_eq!(s.stdio_skipped, 1);
        assert_eq!(s.non_https_skipped, vec!["http://example.com".to_string()]);
        assert!(s.parse_errors.is_empty());
    }

    #[test]
    fn scan_missing_file_is_silent() {
        let tmp = tempfile::tempdir().unwrap();
        let s = scan(&[tmp.path().join("nope.json")]);
        assert_eq!(s, Scan::default());
    }

    #[test]
    fn scan_malformed_file_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_tmp(tmp.path(), "bad.json", "{ not json");
        let s = scan(&[p.clone()]);
        assert!(s.files_read.is_empty());
        assert_eq!(s.parse_errors.len(), 1);
        assert_eq!(s.parse_errors[0].0, p);
    }

    #[test]
    fn scan_merges_across_files_dedup() {
        let tmp = tempfile::tempdir().unwrap();
        let a = write_tmp(
            tmp.path(),
            "a.json",
            r#"{ "mcpServers": { "x": { "url": "https://a.example/" } } }"#,
        );
        let b = write_tmp(
            tmp.path(),
            "b.json",
            r#"{ "mcpServers": { "x": { "url": "https://a.example/v2" }, "y": { "url": "https://b.example/" } } }"#,
        );
        let s = scan(&[a, b]);
        assert_eq!(s.hosts, vec!["a.example".to_string(), "b.example".to_string()]);
    }
}
