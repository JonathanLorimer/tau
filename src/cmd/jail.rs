use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

// Load-bearing: the Phase 8 nftables rule keys on this exact UID.
// Changing one without the other breaks enforcement.
const JAIL_UID: u32 = 5555;
const JAIL_GID: u32 = 5555;

const PROXY_URL: &str = "http://127.0.0.1:8118";
const NO_PROXY_LIST: &str = "localhost,127.0.0.1,::1";

/// Launch pi inside a bwrap sandbox routed through the firewall.
///
/// The sandbox unshares all namespaces except network, sets the jail UID
/// to 5555 (matching the Phase 8 nftables rule), and forces all outbound
/// HTTPS through the local firewall proxy on 127.0.0.1:8118.
#[derive(clap::Args)]
pub struct Args {
    /// Directory bind-mounted rw inside the jail; defaults to the cwd.
    #[arg(short = 'C', long, value_name = "DIR")]
    project: Option<PathBuf>,

    /// Where pi stores its auth tokens; rw-bound into the jail so `/login`
    /// and OAuth refresh can write. Defaults to ~/.pi (pi's standard
    /// location). Created if it doesn't exist.
    #[arg(long, env = "PI_AUTH_DIR", value_name = "DIR")]
    auth_dir: Option<PathBuf>,

    /// Arguments forwarded to pi.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pi_args: Vec<String>,
}

pub fn run(args: Args) -> std::io::Result<()> {
    let project = match args.project {
        Some(p) => p,
        None => std::env::current_dir()?,
    }
    .canonicalize()?;

    if !project.is_dir() {
        return Err(io_error(format!(
            "project directory '{}' does not exist",
            project.display()
        )));
    }

    let home = std::env::var("HOME").map_err(|_| io_error("HOME not set"))?;
    let auth_dir = args
        .auth_dir
        .unwrap_or_else(|| PathBuf::from(&home).join(".pi"));

    // Ensure the auth dir exists on the host before binding. Without this,
    // first-run /login would create the dir inside the jail's tmpfs $HOME
    // and the tokens would vanish when the jail exits.
    std::fs::create_dir_all(&auth_dir).map_err(|e| {
        io_error(format!(
            "failed to ensure auth dir '{}' exists: {e}",
            auth_dir.display()
        ))
    })?;

    let pi = which_pi()?;

    let mut cmd = Command::new("bwrap");

    cmd.args([
        "--unshare-all",      // unshare every namespace by default (mount, pid, ipc, uts, cgroup, user, net)
        "--share-net",        // …except network — we still need to talk to the local proxy
        "--unshare-user",     // private user namespace lets us remap our uid without root
        "--die-with-parent",  // SIGKILL the jail if our process dies (no orphan jails)
        "--new-session",      // fresh session id; mitigates TIOCSTI escapes back to the parent tty
        "--clearenv",         // drop every inherited env var; we re-add only the allowlist below
    ]);

    let uid = JAIL_UID.to_string();
    let gid = JAIL_GID.to_string();
    cmd.args(["--uid", &uid]); // run as uid 5555 inside (matches the Phase 8 nftables rule)
    cmd.args(["--gid", &gid]); // and gid 5555

    let path = std::env::var("PATH").unwrap_or_default();
    let user = std::env::var("USER").unwrap_or_default();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".into());
    let lang = std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into());
    let nix_cert = std::env::var("NIX_SSL_CERT_FILE").unwrap_or_default();
    let ssl_cert = std::env::var("SSL_CERT_FILE").unwrap_or_default();

    // Re-establish only the env vars we actually want inside the jail.
    // Everything else was just dropped by --clearenv. The HTTPS_PROXY pair is
    // what makes cooperating clients route through the firewall at all.
    for (k, v) in [
        ("PATH", path.as_str()),                  // exec lookup path — pi inherits the host PATH
        ("HOME", home.as_str()),                  // points at the tmpfs we mount below
        ("USER", user.as_str()),                  // tools like git read this for default config
        ("TERM", term.as_str()),                  // terminal type — pi's UI depends on this
        ("LANG", lang.as_str()),                  // locale; affects character encoding
        ("NIX_SSL_CERT_FILE", nix_cert.as_str()), // CA bundle path on NixOS
        ("SSL_CERT_FILE", ssl_cert.as_str()),     // CA bundle path on other distros
        ("HTTPS_PROXY", PROXY_URL),               // route HTTPS through the firewall (uppercase)
        ("https_proxy", PROXY_URL),               // …and lowercase, since some libs only check this
        ("NO_PROXY", NO_PROXY_LIST),              // skip the proxy for localhost (avoid loops)
        ("no_proxy", NO_PROXY_LIST),              // …and lowercase
    ] {
        cmd.args(["--setenv", k, v]);
    }

    cmd.args(["--ro-bind", "/nix/store", "/nix/store"]); // every binary we exec lives here, ro

    // /etc files we need; -try means "skip silently if missing" — handy because
    // /etc/static is a NixOS-ism and won't exist on other distros.
    for p in [
        "/etc/static",        // NixOS: target dir for /etc/* symlinks
        "/etc/ssl",           // CA certificate bundle
        "/etc/resolv.conf",   // DNS configuration
        "/etc/passwd",        // username ↔ uid mapping for getpwuid lookups
        "/etc/group",         // group name ↔ gid mapping
        "/etc/nsswitch.conf", // name service order (DNS vs files etc)
        "/etc/hosts",         // local hostname overrides
    ] {
        cmd.args(["--ro-bind-try", p, p]);
    }

    cmd.args(["--tmpfs", &home]); // fake $HOME backed by tmpfs; hides host dotfiles

    let auth_str = auth_dir.to_string_lossy().into_owned();
    // RW bind so /login, OAuth refresh, and settings writes work. We accept
    // the persistence vector (compromised pi could write an extension that
    // loads on the next run) because RO breaks token rotation, and an
    // attacker already has live token access via process memory anyway.
    cmd.args(["--bind", &auth_str, &auth_str]);

    let project_str = project.to_string_lossy().into_owned();
    cmd.args(["--bind", &project_str, &project_str]); // rw bind of the project dir
    cmd.args(["--chdir", &project_str]);              // start pi in the project dir

    cmd.arg(&pi);
    cmd.args(&args.pi_args);

    // exec replaces this process; only returns on failure
    Err(cmd.exec())
}

fn io_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

fn which_pi() -> std::io::Result<PathBuf> {
    let path = std::env::var("PATH").map_err(|_| io_error("PATH not set"))?;
    for dir in path.split(':') {
        let candidate = PathBuf::from(dir).join("pi");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(io_error("'pi' not found on PATH"))
}
