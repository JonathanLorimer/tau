use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::allowlist::Allowlist;
use crate::{mgmt, paths, proxy};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the persistent allowlist file.
    #[arg(long, env = "TAU_ALLOWLIST", value_name = "PATH")]
    allowlist: Option<PathBuf>,

    /// Path to the management Unix socket.
    #[arg(long, env = "TAU_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,
}

pub async fn run(args: Args) -> std::io::Result<()> {
    init_tracing();

    let config_path = args.allowlist.unwrap_or_else(paths::default_allowlist);
    let socket_path = args.socket.unwrap_or_else(paths::default_socket);

    let allowlist = Allowlist::load(&config_path)?;
    let allowlist = Arc::new(RwLock::new(allowlist));

    tokio::select! {
        res = proxy::run(allowlist.clone()) => {
            tracing::error!("proxy exited: {res:?}");
        }
        res = mgmt::run(&socket_path, allowlist) => {
            tracing::error!("mgmt exited: {res:?}");
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
