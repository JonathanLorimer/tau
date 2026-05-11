use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::allowlist::Allowlist;
use crate::audit::{self, Audit};
use crate::{honeypot, mgmt, paths, proxy};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the persistent allowlist file.
    #[arg(long, env = "TAU_ALLOWLIST", value_name = "PATH")]
    allowlist: Option<PathBuf>,

    /// Path to the management Unix socket.
    #[arg(long, env = "TAU_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Address the HTTPS CONNECT proxy binds on.
    #[arg(
        long,
        env = "TAU_PROXY_ADDR",
        value_name = "ADDR",
        default_value = "127.0.0.1:8118"
    )]
    proxy_addr: SocketAddr,

    /// Address the escape-detection honeypot binds on. The kernel NAT rule
    /// installed by the NixOS module (`programs.tau.enforce`) redirects
    /// non-proxy traffic from the jail UID to this address; we recover the
    /// original destination via `SO_ORIGINAL_DST`.
    #[arg(
        long,
        env = "TAU_HONEYPOT_ADDR",
        value_name = "ADDR",
        default_value = "127.0.0.1:8119"
    )]
    honeypot_addr: SocketAddr,

    /// Append one JSON line per CONNECT decision to this file. Off when
    /// unset. The file is opened with `O_APPEND | O_CREAT`; parent
    /// directories are created if missing. Querying:
    /// `jq -s 'group_by(.host)|...' < audit.log`.
    #[arg(long, env = "TAU_AUDIT_LOG", value_name = "PATH")]
    audit_log: Option<PathBuf>,
}

pub async fn run(args: Args) -> std::io::Result<()> {
    init_tracing();

    let config_path = args.allowlist.unwrap_or_else(paths::default_allowlist);
    let socket_path = args.socket.unwrap_or_else(paths::default_socket);

    let allowlist = Allowlist::load(&config_path)?;
    let allowlist = Arc::new(RwLock::new(allowlist));

    let events = honeypot::channel();

    // Audit log is opt-in. When set, the proxy gets an enabled `Audit`
    // handle and the writer task drains the channel; when unset, the
    // handle no-ops and we substitute a never-completing future so
    // `tokio::select!` keeps watching the other listeners.
    let (audit_handle, audit_fut): (
        Audit,
        std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>,
    ) = match args.audit_log {
        Some(path) => {
            let (tx, rx) = audit::channel();
            (Audit::enabled(tx), Box::pin(audit::run(path, rx)))
        }
        None => (
            Audit::disabled(),
            Box::pin(std::future::pending::<std::io::Result<()>>()),
        ),
    };

    tokio::select! {
        res = proxy::run(args.proxy_addr, allowlist.clone(), audit_handle) => {
            tracing::error!("proxy exited: {res:?}");
        }
        res = mgmt::run(&socket_path, allowlist, events.clone()) => {
            tracing::error!("mgmt exited: {res:?}");
        }
        res = honeypot::run(args.honeypot_addr, events) => {
            tracing::error!("honeypot exited: {res:?}");
        }
        res = audit_fut => {
            tracing::error!("audit log task exited: {res:?}");
        }
    }

    Err(std::io::Error::other("daemon listener exited"))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("tau=info".parse().unwrap()),
        )
        .init();
}
