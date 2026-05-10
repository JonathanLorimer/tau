use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

mod allowlist;
mod mgmt;
mod proxy;

use allowlist::Allowlist;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("pi_firewall=info".parse().unwrap()),
        )
        .init();

    let config_path = xdg_config_dir().join("allow.json");
    let socket_path = xdg_runtime_dir().join("pi-firewall.sock");

    let allowlist = match Allowlist::load(&config_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fatal: could not load allowlist from {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };

    let allowlist = Arc::new(RwLock::new(allowlist));

    tokio::select! {
        res = proxy::run(allowlist.clone()) => {
            tracing::error!("proxy exited: {res:?}");
        }
        res = mgmt::run(&socket_path, allowlist) => {
            tracing::error!("mgmt exited: {res:?}");
        }
    }
    std::process::exit(1);
}

fn xdg_config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".config")
        })
        .join("pi-firewall")
}

fn xdg_runtime_dir() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
