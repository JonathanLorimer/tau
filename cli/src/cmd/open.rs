use std::path::PathBuf;
use std::time::Duration;

use crate::{mgmt, paths};

#[derive(clap::Args)]
pub struct Args {
    /// URL to open in the host browser via the tau daemon.
    url: String,

    /// Management socket path; defaults to $XDG_RUNTIME_DIR/tau.sock.
    #[arg(long, env = "TAU_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,
}

pub fn run(args: Args) -> std::io::Result<()> {
    let socket = args.socket.unwrap_or_else(paths::default_socket);
    send(&socket, &args.url)
}

/// Entry point when tau is exec'd as xdg-open inside the jail.
/// argv[1] is the URL, matching the xdg-open(1) interface.
pub fn run_as_shim() -> std::io::Result<()> {
    let url = std::env::args().nth(1).unwrap_or_default();
    send(&paths::default_socket(), &url)
}

fn send(socket: &std::path::Path, url: &str) -> std::io::Result<()> {
    let cmd = mgmt::Command::OpenUrl { url: url.to_string() };
    match mgmt::send_blocking(socket, &cmd, Duration::from_millis(500)) {
        Ok(mgmt::Reply::Simple { ok: true }) => Ok(()),
        Ok(_) => Err(std::io::Error::other("daemon rejected open_url request")),
        Err(e) => Err(e),
    }
}
