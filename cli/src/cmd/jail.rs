use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use crate::paths;

// Load-bearing: the nftables enforcement rule installed by the NixOS
// module (programs.tau.enforce) keys on this exact UID. Changing one
// without the other breaks enforcement.
const JAIL_UID: u32 = 5555;
const JAIL_GID: u32 = 5555;

const PROXY_URL: &str = "http://127.0.0.1:8118";
const NO_PROXY_LIST: &str = "localhost,127.0.0.1,::1";

// Env vars we set inside the jail to specific values, regardless of the host.
// Applied last so they override anything inherited.
const ALWAYS_FORCE: &[(&str, &str)] = &[
    ("HTTPS_PROXY", PROXY_URL),
    ("https_proxy", PROXY_URL),
    ("NO_PROXY", NO_PROXY_LIST),
    ("no_proxy", NO_PROXY_LIST),
];

// Curated set of env vars we copy through from the host if present. A pattern
// ending in '*' is a prefix match; everything else is a literal name. Users
// can extend this list via ~/.config/tau/jail.env or `--inherit-env`.
const INHERIT_DEFAULT: &[&str] = &[
    // Core
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    // Terminal sizing / type
    "TERM",
    "COLUMNS",
    "LINES",
    // Locale
    "LANG",
    "LC_*",
    // Time
    "TZ",
    // Editor / pager preferences
    "EDITOR",
    "VISUAL",
    "PAGER",
    // TLS bundles
    "NIX_SSL_CERT_FILE",
    "SSL_CERT_FILE",
    // Git identity
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    // LLM provider keys
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    // Source-forge tokens
    "GH_TOKEN",
    "GITHUB_TOKEN",
    // Package registry tokens
    "NPM_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "CARGO_REGISTRIES_*_TOKEN",
    // The tau extension uses this to compute the mgmt socket path;
    // see also the explicit socket bind in run() below.
    "XDG_RUNTIME_DIR",
];

// Never inherit these, even if the user lists them. They'd either give the
// jail access to host credentials/sessions or defeat the sandbox itself.
const INHERIT_DENY: &[&str] = &[
    // Credential agents
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "GNUPGHOME",
    // Sandbox-defeating loader knobs
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_*",
    // GUI / session access
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    // sudo metadata
    "SUDO_*",
];

/// Launch pi inside a bwrap sandbox routed through the firewall.
///
/// The sandbox unshares all namespaces except network, sets the jail UID
/// to 5555 (matching the nftables enforcement rule), and forces all
/// outbound HTTPS through the local firewall proxy on 127.0.0.1:8118.
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

    /// Additional env-var names to inherit (literal or NAME_* patterns).
    /// Comma-separated; the flag may repeat. Adds to the curated default set
    /// and to entries from ~/.config/tau/jail.env. The denylist always wins.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    inherit_env: Vec<String>,

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
        // Unshare every namespace except PID and net. bwrap has no --share-pid
        // flag, so we list the ones we want explicitly. Mount namespace is
        // always created implicitly by bwrap (no --unshare-mount flag exists).
        "--unshare-user",     // private user ns lets us remap uid without root
        "--unshare-uts",      // own hostname/domain
        "--unshare-ipc",      // own SysV IPC, POSIX message queues
        "--unshare-cgroup-try", // own cgroup namespace if the host supports it
        "--disable-userns",     // prevent nested user namespace creation inside the jail
        // PID namespace deliberately shared: pi-inside-the-jail needs to
        // see host processes for legitimate developer workflows (PID-file
        // liveness checks like `ghciwatch`, `ps`/`top`, attaching debuggers
        // to host services, etc.). Process *control* is still isolated by
        // UID — UID 5555 can't signal UID 1000-owned processes.
        // Net namespace deliberately shared: we need to reach the local
        // proxy at 127.0.0.1:8118.
        "--die-with-parent",  // SIGKILL the jail if our process dies (no orphan jails)
        "--new-session",      // fresh session id; mitigates TIOCSTI escapes back to the parent tty
        "--clearenv",         // drop every inherited env var; we re-add only the allowlist below
    ]);

    let uid = JAIL_UID.to_string();
    let gid = JAIL_GID.to_string();
    cmd.args(["--uid", &uid]); // run as uid 5555 inside (matches the nftables rule)
    cmd.args(["--gid", &gid]); // and gid 5555

    // Build the inherit allowlist: defaults + ~/.config/tau/jail.env + --inherit-env.
    // Denylist always wins; entries it covers are dropped even if the user added them.
    let mut allowlist: Vec<String> = INHERIT_DEFAULT.iter().map(|s| (*s).to_string()).collect();
    allowlist.extend(load_inherit_file()?);
    allowlist.extend(args.inherit_env);

    for (k, v) in std::env::vars() {
        if matches_any(&k, INHERIT_DENY) {
            continue;
        }
        if !matches_any(&k, &allowlist) {
            continue;
        }
        cmd.args(["--setenv", &k, &v]);
    }

    // Sane fallbacks for vars that tools commonly require but users sometimes
    // don't have set in their shell env.
    if std::env::var("TERM").is_err() {
        cmd.args(["--setenv", "TERM", "xterm"]);
    }
    if std::env::var("LANG").is_err() {
        cmd.args(["--setenv", "LANG", "C.UTF-8"]);
    }

    // Forced overrides go last so they win over anything inherited or fallback'd.
    for (k, v) in ALWAYS_FORCE {
        cmd.args(["--setenv", k, v]);
    }

    cmd.args(["--ro-bind", "/nix/store", "/nix/store"]); // every binary we exec lives here, ro
    cmd.args(["--proc", "/proc"]); // fresh procfs; JIT (bun's JSC) reads /proc/self/maps
    cmd.args(["--dev", "/dev"]);   // minimal /dev (null, zero, random, urandom, tty)

    // Profile dirs (/etc/profiles, /run/current-system, /run/wrappers) are
    // deliberately not bound. pi is wrapped by `nix/pi.nix` via makeWrapper
    // so its `$PATH` is prefixed with canonical /nix/store paths for its
    // configured tool deps. The inherited host $PATH still works for any
    // entry that points directly at /nix/store/.../bin — `nix develop`'s
    // `buildInputs` use that shape, so dev-shell tools are reachable
    // without binding the host profile dirs. The agent's only host-FS
    // reach outside /etc/* below is the read-only /nix/store mount.

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

    // Bind the daemon's mgmt socket at the same host-side path so the tau
    // extension inside the jail can manage the allowlist. -try because the
    // daemon might not be running yet when the jail starts up (in that case
    // the extension's slash commands surface a clean "couldn't connect"
    // error to the user).
    let mgmt_socket = paths::default_socket();
    let mgmt_str = mgmt_socket.to_string_lossy().into_owned();
    cmd.args(["--bind-try", &mgmt_str, &mgmt_str]);

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
            // Resolve symlinks so the path we hand bwrap lives under
            // /nix/store (the only host directory we bind-mount). On NixOS
            // `$PATH` typically contains `/etc/profiles/per-user/<u>/bin`,
            // which is a symlink that doesn't exist inside the jail's
            // mount namespace — exec'ing it fails with ENOENT.
            return candidate.canonicalize();
        }
    }
    Err(io_error("'pi' not found on PATH"))
}

/// Read additional inherit-allowlist entries from ~/.config/tau/jail.env.
/// Format: one pattern per line; '#' starts a comment; blank lines OK.
/// Returns an empty list if the file doesn't exist.
fn load_inherit_file() -> std::io::Result<Vec<String>> {
    let path = paths::config_dir().join("jail.env");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if !trimmed.is_empty() {
            entries.push(trimmed.to_string());
        }
    }
    Ok(entries)
}

fn matches_any<S: AsRef<str>>(name: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|p| match_pattern(name, p.as_ref()))
}

/// Match a name against a pattern. A trailing '*' is the only wildcard
/// (prefix match); anything else is compared literally.
fn match_pattern(name: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        assert!(match_pattern("PATH", "PATH"));
        assert!(!match_pattern("PATHX", "PATH"));
        assert!(!match_pattern("path", "PATH"));
    }

    #[test]
    fn prefix_match() {
        assert!(match_pattern("LC_ALL", "LC_*"));
        assert!(match_pattern("LC_", "LC_*"));
        assert!(!match_pattern("LANG", "LC_*"));
        assert!(!match_pattern("XLC_ALL", "LC_*"));
    }

    #[test]
    fn star_only_matches_everything() {
        assert!(match_pattern("anything", "*"));
        assert!(match_pattern("", "*"));
    }

    #[test]
    fn deny_wins() {
        // Even though the user added it, SSH_AUTH_SOCK is in the deny list.
        let allowed: Vec<String> = vec!["SSH_AUTH_SOCK".into()];
        assert!(matches_any("SSH_AUTH_SOCK", &allowed));
        assert!(matches_any("SSH_AUTH_SOCK", INHERIT_DENY));
    }
}
