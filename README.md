# tau

> Tau is just  a thin wrapper around pi, the rename is just for personal amusement

A personal coding harness that runs the [pi](https://github.com/earendil-works/pi-mono)
coding agent inside a bwrap sandbox whose outbound network is constrained
by a small local HTTPS proxy and (optionally) an nftables UID rule. The
agent can only reach hosts you've put on an allowlist; everything else is
blocked at the proxy and, with the nftables module enabled, by the kernel.

## What's in the box

A single Rust binary `tau` exposing three subcommands, a TypeScript pi
extension, and a Nix flake that packages all three plus a NixOS module
and a home-manager module.

```
cli/             Rust crate (workspace member)
  src/
    main.rs         clap top-level dispatch
    paths.rs        XDG path helpers
    allowlist.rs    persistent + session allowlist with atomic writes
    proxy.rs        HTTPS CONNECT proxy with structured deny markers
    mgmt.rs         unix-socket protocol; Command/Reply shared with tau ctl
    honeypot.rs     escape-attempt detector + broadcast channel
    audit.rs        append-only NDJSON decision log
    util.rs         shared helpers (RFC 3339 timestamp)
    cmd/
      serve.rs        daemon entry point
      jail.rs         bwrap wrapper, env-inheritance policy
      ctl.rs          mgmt-socket client
  tests/integration.rs

extension/       pi extension (TypeScript)
  index.ts          slash commands, marker-aware web_fetch, events subscriber
  package.json
  tsconfig.json

nix/             flake outputs
  pi.nix            pi packaged from upstream's bun-compiled binary
  tau.nix           tau built via crane (deps cached separately)
  extension.nix     extension as a runCommand trivial derivation
  home-manager.nix  user-side module (install + service)
  systemd-unit.nix  the systemd user unit for `tau serve`
  nixos.nix         system-side module (bwrap + nftables + kernel knob)

flake.nix        packages.${system}.{tau, pi, tau-extension}; modules; devShell
```

## Subcommands

- **`tau serve`** — runs the firewall daemon. Three listeners share a
  process: the HTTPS CONNECT proxy (default `127.0.0.1:8118`), the
  management unix socket (`$XDG_RUNTIME_DIR/tau.sock`), and the
  escape-detection honeypot (default `127.0.0.1:8119`). With
  `--audit-log <PATH>` it appends one NDJSON record per CONNECT decision.

- **`tau jail [-C dir] [--auth-dir dir] [--inherit-env LIST] -- [pi-args]`**
  — launches pi inside a bwrap sandbox routed through the daemon. Runs
  as UID 5555 (matches the nftables rule), forces `HTTPS_PROXY` to the
  proxy, mounts `/nix/store` ro, project dir rw, pi's auth dir rw,
  everything else tmpfs.

- **`tau ctl {list, add, remove, seed}`** — talks to the daemon's mgmt
  socket to mutate the allowlist. `tau ctl seed` populates the
  persistent set with the usual hosts (anthropic, openai, github, npm,
  crates, pypi, …).

## Architecture

```
                 host                          jail (UID 5555)
   ┌──────────────────────────────┐    ┌──────────────────────────┐
   │                              │    │                          │
   │  tau serve                   │    │  pi  + tau extension     │
   │  ┌────────────────────────┐  │    │  ┌────────────────────┐  │
   │  │ proxy   :8118  ◄───────┼──┼────┼──┤ HTTPS_PROXY        │  │
   │  │ honeypot:8119  ◄ ─ ─ ─ ┤  │    │  │                    │  │
   │  │ mgmt $RUNTIME_DIR/.sock┼──┼────┼──┤ slash commands +   │  │
   │  └────────────────────────┘  │    │  │ events subscriber  │  │
   │            │                 │    │  └────────────────────┘  │
   │            ▼                 │    └──────────────────────────┘
   │     allow.json (atomic)      │              ▲
   │     audit.log (append)       │              │ nftables redirects
   │                              │              │ non-proxy TCP from
   └──────────────────────────────┘              │ UID 5555 → :8119
                                                 │
```

The proxy is a pure decision function: allow → tunnel CONNECT; deny →
403 with a `X-Pi-Firewall-Status` marker. The extension catches deny
markers and renders the appropriate UX (prompt, hard-fail, etc.). Adds
go through the management socket so atomic-rename is the only write
path to `allow.json`. With the NixOS module's `enforce = true`, an
nftables rule keyed on UID 5555 makes the proxy enforcement-grade: any
non-loopback TCP that escapes `HTTPS_PROXY` gets DNAT'd to the
honeypot, which records the original destination via `SO_ORIGINAL_DST`
and emits an `escape-attempt` event.

## Architectural anchors

These are load-bearing. Don't violate them without surfacing the change.

1. **The daemon is a pure decision function.** It never blocks waiting
   for user input. Allowlist hit → tunnel; miss → 403 with marker.
   Approval flow is owned by the extension.

2. **The extension catches deny-marked 403s and retries.** It must not
   fetch directly bypassing the proxy — that defeats the unified
   allowlist and makes the nftables rule incoherent.

3. **The daemon owns all writes to `allow.json`.** The extension reads
   it for display only; mutations go through the mgmt socket so
   atomic-rename is the only write path.

4. **Default-deny on every error path.** Malformed mgmt commands,
   socket-unreachable, mgmt timeout, parse errors → deny. Never
   fail-open.

5. **HTTPS only.** Plain HTTP is rejected by the proxy. Coding agents
   talk HTTPS to everything that matters; reducing parse surface is
   worth the small loss.

6. **The daemon and extension are separate processes with separate
   address spaces.** The daemon doesn't import any LLM/agent code. The
   extension doesn't link the daemon's library; it talks JSON over
   sockets.

7. **Deny markers and escape events are a versioned contract between
   the daemon and the extension.** The `X-Pi-Firewall-Status` header
   value (and the `kind` field of events on the events stream) are
   enumerated, not free-form. The extension switches on them to choose
   UX. Adding a new value requires updating `proxy.rs`/`honeypot.rs`
   and `extension/index.ts` in lockstep.

## Wire contracts

The daemon never returns a generic 403. Every denial is tagged with a
machine-readable cause so the extension can pick the right UX.

### In-band deny markers (proxy 403 `X-Pi-Firewall-Status` header)

| Marker                     | Cause                       | Extension UX                                  |
|----------------------------|-----------------------------|-----------------------------------------------|
| `denied-unknown-host`      | host:port not in allowlist  | prompt: "allow once / always / deny"          |
| `denied-non-https`         | port ≠ 443                  | hard-fail with explanation; not allowlistable |
| `denied-malformed-request` | unparseable CONNECT line    | hard-fail; likely a client bug                |

### Out-of-band events (mgmt-socket events stream)

Events are delivered out-of-band because they describe traffic the
proxy never sees — a process that bypassed `HTTPS_PROXY` entirely and
got caught by the kernel NAT redirect. The extension opens a long-lived
mgmt connection, sends `{"cmd":"subscribe_events"}`, and reads NDJSON
events for the life of the session.

| Event            | Cause                                                      | Extension UX                                                              |
|------------------|------------------------------------------------------------|---------------------------------------------------------------------------|
| `escape-attempt` | process bypassed the proxy; caught by the kernel/honeypot  | red-alert notification with destination IP, port, and dedup count         |

Old markers and events are kept indefinitely once shipped — extensions
may run an older version than the daemon during upgrades. Don't reuse
a marker for a different cause; don't introduce ad-hoc strings.

## Mgmt protocol

JSON lines over `$XDG_RUNTIME_DIR/tau.sock`. Commands and replies are
defined in `cli/src/mgmt.rs`; `tau ctl` and the extension both speak
the same protocol.

```
→ {"cmd":"list"}
← {"ok":true,"entries":[{"host":"github.com"}]}

→ {"cmd":"add_session","host":"example.com"}
← {"ok":true}

→ {"cmd":"add_persist","host":"example.com"}
← {"ok":true}

→ {"cmd":"remove","host":"example.com"}
← {"ok":true}

→ {"cmd":"subscribe_events"}
← {"ok":true}
← {"kind":"escape-attempt","ts":"…","host":"1.2.3.4","port":443,"count":1}
← {"kind":"escape-attempt","ts":"…","host":"5.6.7.8","port":443,"count":1}
…
```

Allowlist entries are *host-only* — port is implicit since the proxy
is HTTPS-only (architectural anchor #5). Escape events still carry
port because the honeypot recovers the original destination address
including the port the bypassing process tried to reach.

`subscribe_events` flips *that connection* into one-way streaming mode.
The switch is per-connection, not per-daemon — `list`/`add`/`remove`
keep working on fresh connections in parallel. Splitting the two
protocols across separate sockets sidesteps the framing problem of
interleaving pushed events with command/reply traffic.

## Installation

### As a flake input

```nix
# flake.nix
{
  inputs.tau.url = "github:jonathanlorimer/tau";  # or wherever you host this

  outputs = { self, nixpkgs, tau, home-manager, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        tau.nixosModules.default
        {
          programs.tau = {
            enable  = true;   # bubblewrap + kernel namespace knob
            enforce = true;   # nftables redirect rules
          };
        }
      ];
    };

    homeConfigurations.user = home-manager.lib.homeManagerConfiguration {
      modules = [
        tau.homeManagerModules.default
        { programs.tau.enable = true; }
      ];
    };
  };
}
```

### Module options

`homeManagerModules.default` exposes under `programs.tau`:

| option                 | type                       | default                   | purpose                                                                       |
|------------------------|----------------------------|---------------------------|-------------------------------------------------------------------------------|
| `enable`               | bool                       | `false`                   | install `tau`, `pi`, the extension symlink, run `tau serve`                   |
| `package`              | package                    | flake's `tau`             | override the tau binary                                                       |
| `installPi`            | bool                       | `true`                    | put pi on PATH too                                                            |
| `pi`                   | package                    | flake's `pi` (rewrapped)  | override pi (default re-wraps with `toolDeps` via `makeWrapper`)              |
| `toolDeps`             | list of package            | `[pkgs.fd pkgs.ripgrep]`  | tools pi needs on PATH inside the jail; threaded into pi's wrapper            |
| `installExtension`     | bool                       | `true`                    | symlink the bundled tau extension into `~/.pi/agent/extensions/tau`           |
| `extension`            | package                    | flake's `tau-extension`   | override the bundled tau extension                                            |
| `extensions`           | attrset of name → src      | `{}`                      | extra extensions to symlink into `~/.pi/agent/extensions/<name>/`             |
| `skills`               | attrset of name → src      | `{}`                      | agent skills to symlink into `~/.pi/agent/skills/<name>/` (see agentskills.io)|
| `settings`             | attrset                    | `{}`                      | written as JSON to `~/.pi/agent/settings.json` (see pi docs/settings.md)      |
| `systemPrompt`         | nullable lines             | `null`                    | replace pi's default prompt; written to `~/.pi/agent/SYSTEM.md` when set      |
| `appendSystemPrompt`   | nullable lines             | `null`                    | append to pi's default prompt; written to `~/.pi/agent/APPEND_SYSTEM.md`      |
| `enableService`        | bool                       | `true`                    | run `tau serve` as a systemd user service                                     |

`nixosModules.default` exposes under `programs.tau`:

| option              | type   | default | purpose                                                                       |
|---------------------|--------|---------|-------------------------------------------------------------------------------|
| `enable`            | bool   | `false` | install bubblewrap, enable `security.unprivilegedUsernsClone`                 |
| `enforce`           | bool   | `false` | install the nftables filter + NAT tables that pin jail UID 5555 to the proxy  |
| `jailUid`           | int    | `5555`  | UID `tau jail` runs the sandbox as; the nftables rules key on this same value |

### Manual run (without the modules)

```sh
# build the binary and put it on PATH
nix build .#tau
./result/bin/tau serve &        # start the daemon
tau ctl seed                     # populate the allowlist
tau jail                         # launch pi in the jail (cwd is the project dir)
```

## Usage

Typical session:

```sh
$ tau ctl seed                          # one-time, populate the persistent allowlist
$ tau jail                              # cd into a project first, then this
# inside pi:
# > /firewall-list                      # see what's allowed
# > /firewall-add docs.python.org       # add for this session and the future
# > /firewall-remove some.host          # take something off the list
```

When pi's `web_fetch` hits a host that isn't on the list, the extension
prompts in-session: *Allow once (session) / Allow always (persist) /
Deny*. Session adds live only in the daemon's memory; persistent adds
are atomically written to
`$XDG_CONFIG_HOME/tau/allow.json` (default `~/.config/tau/allow.json`).

## Configuration

### Jail env inheritance

`tau jail --clearenv`s the bwrap env and selectively reintroduces:

- Always-forced: `HTTPS_PROXY`, `https_proxy`, `NO_PROXY`, `no_proxy`
  → `127.0.0.1:8118` / `localhost,127.0.0.1,::1`.
- Allowlist (passed through if set on the host): `PATH`, `HOME`,
  `USER`, `SHELL`, `TERM`, `LANG`, `LC_*`, `TZ`, `EDITOR`, `PAGER`,
  TLS bundles, git identity vars, LLM provider keys, source-forge
  tokens, package-registry tokens, `XDG_RUNTIME_DIR`.
- Denylist (never passes, even if you add it): `SSH_AUTH_SOCK`, GPG
  agent vars, `LD_*`/`DYLD_*` loader knobs, display/session vars,
  `SUDO_*`.

Two ways to extend the allowlist:
- `~/.config/tau/jail.env` — one pattern per line; `#` starts a
  comment; blank lines OK; a trailing `*` is a prefix glob.
- `--inherit-env NAME1,NAME2,…` on the command line. Repeatable.

The denylist always wins. The full lists live in `cli/src/cmd/jail.rs`.

### Audit log

`tau serve --audit-log <path>` (or `TAU_AUDIT_LOG=<path>`) appends one
NDJSON record per CONNECT decision:

```json
{"ts":"2026-05-10T22:00:00Z","host":"github.com","port":443,"decision":"allow","reason":"persistent","peer":"127.0.0.1:55432"}
```

Reasons: `persistent` / `session` for allows; `unknown-host` /
`non-https` / `malformed-request` for denies. Bare TCP probes (empty
input) are intentionally skipped — they're not malformed requests.

```sh
# top hosts the jail tried to reach
$ jq -s 'group_by(.host) | map({host: .[0].host, count: length}) | sort_by(-.count)' < audit.log

# every deny
$ jq 'select(.decision == "deny")' < audit.log
```

Fsync is intentionally omitted; OS page-cache durability is enough for
this trail.

## Development

```sh
$ nix develop                            # rust, node, bubblewrap, etc.
$ cargo build
$ cargo test
$ cargo clippy --all-targets -- -D warnings
$ nix flake check
$ (cd extension && pnpm typecheck)
```

The Rust crate lives at `cli/`; the workspace root `Cargo.toml` exists
so `cargo` commands work from the repo root. `tests/integration.rs`
spawns a real daemon in a tempdir with kernel-assigned ports, drives
it via the mgmt socket and the proxy, then tears it down via
`Child::kill_on_drop` — no shared state between tests, runs in
parallel.

## Threat model

In scope:
- A coding agent that accidentally or maliciously tries to exfil
  source / secrets to a non-allowlisted destination is blocked at the
  proxy and (with `enforce = true`) at the kernel.
- A tool that ignores `HTTPS_PROXY` and tries to connect directly is
  redirected to the honeypot; the original destination is surfaced as
  an `escape-attempt` event in the pi session.
- An attacker who gets RCE inside the jail is bounded by the bwrap
  mount namespace (tmpfs $HOME, ro `/nix/store`, no SSH agent, no GUI
  socket, no loader-knob env vars) and by the nftables UID rule.

Explicitly out of scope:
- A jailed process that escalates to root via a kernel CVE. The
  nftables UID rule still applies but the rest of the sandbox is
  moot.
- Side-channel inference of the allowlist via timing of
  `denied-unknown-host` responses.
- A compromised daemon process. The systemd unit narrows the blast
  radius (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, etc.) but the worst-case is loss of
  allowlist integrity.

The honeypot itself is hardened against the obvious attacks: never
reads or writes any bytes (no parser to confuse, no fingerprinting
opportunity), bounded concurrency (semaphore cap 32 simultaneous
accepts), hard 500ms per-connection timeout, no reverse DNS lookups
inside the daemon.
