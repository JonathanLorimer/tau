# tau — implementation plan

## Context for the agent

`tau` is a personal coding harness wrapping the `pi` coding agent. It's
exposed as a single Rust binary with three subcommands, plus a Nix flake
that packages pi and (eventually) tau itself.

### Subcommands

- `tau serve` — runs the firewall daemon: an HTTPS CONNECT proxy on
  `127.0.0.1:8118` plus a Unix-socket management interface.
- `tau jail [-C dir] [--auth-dir dir] [--inherit-env LIST] -- [pi-args]`
  — launches pi inside a bwrap sandbox routed through the daemon.
- `tau ctl {list, add, remove, seed}` — talks to the daemon's mgmt
  socket to mutate the allowlist.

### Repository layout

```
src/
  main.rs          clap top-level dispatch
  paths.rs         XDG path helpers (config dir, runtime dir, defaults)
  allowlist.rs     persistent + session allowlist; atomic writes
  proxy.rs         HTTPS CONNECT proxy with structured deny markers
  mgmt.rs          unix-socket protocol; Command/Reply are pub for tau ctl
  cmd/
    serve.rs       daemon entry point
    jail.rs        bwrap wrapper, env-inheritance policy
    ctl.rs         mgmt-socket client
nix/
  pi.nix           pi packaged from upstream's bun-compiled binary
flake.nix          packages.${system}.pi + devShell
```

The extension (`extension/index.ts`) is not yet built — deferred to Phase 3.

### Naming note

This document predates the rename. Wherever it says **pi-firewall** (the
daemon), the current binary is **`tau serve`**. Wherever it says
`scripts/pi-jail` or `scripts/seed-allowlist`, the current equivalents are
`tau jail` and `tau ctl seed`. The architectural intent is unchanged;
only the names moved.

## Architectural anchors (do not violate without flagging)

These are load-bearing and the agent must not silently change them:

1. **The daemon is a pure decision function.** It never blocks waiting
   for user input. Allowlist hit → tunnel; miss → 403 with marker.
   Approval flow is owned by the extension, not the daemon.

2. **The extension catches deny-marked 403s and retries.** It must not
   fetch directly bypassing the proxy — that would defeat the unified
   allowlist and make the future nftables rule incoherent.

3. **The daemon owns all writes to `allow.json`.** The extension reads
   it for display only; mutations go through the management socket so
   atomic-rename is the only write path.

4. **Default-deny on every error path.** Malformed mgmt commands,
   socket-unreachable, mgmt timeout, parse errors → deny. Never
   fail-open.

5. **HTTPS only.** Plain HTTP is rejected by the proxy. Coding agents
   talk HTTPS to everything that matters; reducing parse surface is
   worth the small loss.

6. **The daemon and extension are separate processes with separate
   address spaces.** The daemon must not import any LLM/agent code.
   The extension must not link the daemon's library; it talks JSON
   over sockets.

7. **Deny markers and escape events are a versioned contract between
   the daemon and the extension.** The `X-Pi-Firewall-Status` header
   value (and the `kind` field of events on the events stream) are
   enumerated, not free-form. The extension switches on them to choose
   UX (prompt vs. hard-fail vs. red-alert). Adding a new value requires
   updating both `proxy.rs`/`honeypot.rs` and `extension/index.ts` in
   lockstep. See "Deny marker taxonomy" below.

## Deny marker taxonomy

The daemon never returns a generic 403. Every denial is tagged with a
machine-readable cause so the extension can pick the right UX — there is a
big difference between "this host isn't allowlisted yet, prompt me" and
"a process tried to bypass the proxy, alert me."

**In-band markers** (returned in the 403 `X-Pi-Firewall-Status` header):

| Marker                     | Cause                          | Extension UX                                      |
|----------------------------|--------------------------------|---------------------------------------------------|
| `denied-unknown-host`      | host:port not in allowlist     | prompt user: "allow once / always / deny"         |
| `denied-non-https`         | port ≠ 443                     | hard-fail with explanation; not allowlistable     |
| `denied-malformed-request` | unparseable CONNECT line       | hard-fail; likely a client bug                    |

**Out-of-band events** (delivered via the daemon's events stream — the
proxy never sees these connections, so a 403 is impossible):

| Event              | Cause                                                            | Extension UX                                                       |
|--------------------|------------------------------------------------------------------|--------------------------------------------------------------------|
| `escape-attempt`   | process bypassed the proxy entirely; caught by the Phase 8.5 honeypot | red-alert notification with destination, PID (when resolvable), and dedup count |

Adding a value is a coordinated change. Don't reuse a marker for a
different cause; don't introduce ad-hoc strings. Old markers are kept
indefinitely once shipped — the extension may run an older version
than the daemon during upgrades.

## Status

Done — the foundation is in place:

- ✅ Phase 0 — toolchain (covered by the dev shell in `flake.nix`)
- ✅ Phase 1 — daemon compiles, `cargo test` passes, `cargo clippy -D warnings` clean
- ✅ Phase 2 — daemon integration test as `tests/integration.rs` (10 tests:
  mgmt protocol, persistence-across-restart, and all three deny markers).
  `tau serve` gained `--proxy-addr` so tests can use kernel-assigned ports.
- ✅ Phase 3 — `extension/index.ts` provides three slash commands
  (`/firewall-list`, `/firewall-add`, `/firewall-remove`) and a marker-aware
  `web_fetch` tool with prompt-and-retry on `denied-unknown-host`.
  Packaged as `packages.${system}.tau-extension` via a `runCommand` trivial
  builder. Jail also gained `XDG_RUNTIME_DIR` inheritance plus a
  `--bind-try` for the mgmt socket so the extension reaches the daemon
  from inside the sandbox. The `escape-attempt` event handler is deferred
  to Phase 8.5 (no publisher yet).
- ✅ Phase 4 — bwrap wrapper, now `tau jail`, with curated env-inheritance
  (allowlist + denylist + user-extensible via `~/.config/tau/jail.env`
  and `--inherit-env`)
- ✅ Phase 5 — default-hosts seed, now `tau ctl seed`
- ✅ Deny marker taxonomy implemented in `proxy.rs` via a `deny_response!`
  macro that composes the three structured 403 responses
- ✅ pi packaged in Nix (`nix/pi.nix`, exposed as `packages.${system}.pi`)
- ✅ tau packaged in Nix via crane (`nix/tau.nix`, exposed as
  `packages.${system}.tau`, also set as `packages.${system}.default`).
  Two-step build: `buildDepsOnly` caches the dep tree, `buildPackage`
  links our source.
- ✅ Phase 6 — systemd user service. Folded into the home-manager module
  rather than shipped as a standalone .service file. Hardening directives
  match PLAN.md Phase 6 (NoNewPrivileges, ProtectSystem=strict,
  ProtectHome=read-only with ReadWritePaths=~/.config/tau, etc.).
- ✅ Phase 7 — flake outputs complete:
  - `homeManagerModules.default` (`nix/home-manager.nix`) installs tau +
    pi, symlinks the extension into `~/.pi/agent/extensions/tau`, runs
    `tau serve` as a systemd user service. Granular toggles
    (`installPi`, `installExtension`, `service.enable`).
  - `nixosModules.default` (`nix/nixos.nix`) installs bubblewrap at the
    system level, enables `security.unprivilegedUsernsClone`, and exposes
    `programs.tau.enforce` to install the nftables enforcement rule.
  - `nix/systemd-unit.nix` extracted from `home-manager.nix` so the unit
    definition is reusable.
- ✅ Phase 8 — nftables enforcement rule installed by the NixOS module
  when `programs.tau.enforce = true`. The rule allows the jail UID to
  reach the proxy at `127.0.0.1:8118` and any loopback traffic, and
  rejects everything else with ICMP admin-prohibited so applications
  see a clean "connection refused" rather than a silent timeout.
- ✅ Phase 8.5 — escape detection + honeypot.
  - Daemon: `cli/src/honeypot.rs` runs a third tokio task on
    `127.0.0.1:8119`. Per accept: semaphore-bounded (32 concurrent),
    500ms hard timeout, recovers original destination via
    `SO_ORIGINAL_DST` (with `local_addr` fallback for tests), closes the
    socket without reading any bytes, dedup-keyed
    `HashMap<(IpAddr, u16), …>` over a 5s window, publishes `Event`
    over a `tokio::sync::broadcast` channel. v4 only for the destination
    recovery; the plan calls out v6 as a follow-up.
  - Mgmt protocol: new `subscribe_events` command flips the connection
    into stream mode — ack `{"ok":true}` then NDJSON events until the
    client disconnects or the channel closes. Lagged subscribers are
    warned but kept alive.
  - NixOS module: split into `tau-jail-filter` (inet) and `tau-jail-nat`
    (ip). Filter accepts loopback to `{8118, 8119}` and any `lo`;
    everything else rejected. NAT DNATs non-loopback TCP from the jail
    UID to `127.0.0.1:8119` at priority -100 so conntrack preserves the
    original destination for `SO_ORIGINAL_DST`.
  - Extension: `runEventSubscriber` opens the mgmt socket on factory
    init, subscribes, and renders `escape-attempt` events as
    `ctx.ui.notify(…, "error")` using the most recent session context
    captured via the `session_start` hook. Auto-reconnects with a 2s
    backoff so a temporarily-down daemon doesn't tear the subscriber
    out for the rest of the session.
  - Tests: three new integration tests cover single-emit, burst-dedup,
    and no-subscriber survival. Three new unit tests cover dedup
    semantics. All 26 tests pass under `cargo test`.

TODO — in roughly the right order:

- ⬜ Phase 9 — audit log
- ⬜ Phase 10 — defense-in-depth (optional)

## Phase 0 — environment sanity

Before touching code, verify the toolchain.

**Tasks:**
- Confirm `cargo --version` reports a recent stable Rust (≥1.75).
- Confirm `node --version` reports v20+ (for the extension).
- Confirm `nc -U` works (`netcat-openbsd`, not `netcat-traditional` —
  the BSD variant supports unix sockets).

**Done when:** all three commands succeed.

**Skip if:** the agent already knows the toolchain is in place.

## Phase 1 — compile and unit-test the daemon

The Rust source was written without a compiler. Make it build.

**Tasks:**
- Run `cargo check`. Fix every error.
- Run `cargo clippy -- -D warnings`. Fix every warning.
- Run `cargo test`. The existing tests in `proxy.rs` cover authority
  parsing and CRLF detection; both must pass.
- Run `cargo build --release`. Confirm a binary is produced at
  `target/release/pi-firewall`.

**Likely issues to look for:**
- `Reply` enum in `mgmt.rs` uses `#[serde(untagged)]` — this works for
  current shape but is fragile. **Do not "fix" by adding a tag** unless
  you also update the extension's TypeScript types in lockstep. If the
  agent wants to refactor this, flag for human review first.
- `tokio::net::UnixListener::bind` may need explicit type annotations
  on some toolchain versions.
- The `dispatcher` field in `fetch()` (TS extension) requires recent
  `@types/node`. If TS complains, the `// @ts-expect-error` comment is
  intentional; do not remove it.

**Done when:** `cargo build --release && cargo test` is green.

**Do not:** change architectural decisions to make compilation easier.
If a borrow-checker fight pushes back on the design, surface it as a
question rather than refactoring around it.

## Phase 2 — daemon integration test

Test the daemon end-to-end with `nc` and `curl` before involving pi.

**Tasks:**
- Write `scripts/integration-test.sh` (bash) that:
  1. Starts `pi-firewall` in the background, captures the PID.
  2. Waits for the proxy socket and mgmt socket to appear.
  3. Asserts `echo '{"cmd":"list"}' | nc -U $MGMT_SOCKET` returns
     `{"ok":true,"entries":[]}`.
  4. Asserts `HTTPS_PROXY=http://127.0.0.1:8118 curl -sS https://example.com`
     fails with non-zero exit (because example.com is not allowlisted).
  5. Asserts the curl stderr or response includes the marker
     `X-Pi-Firewall-Status: denied-unknown-host`. (Use `curl -v` and
     grep stderr.)
  6. Asserts `echo '{"cmd":"add_session","host":"example.com","port":443}'
     | nc -U $MGMT_SOCKET` returns `{"ok":true}`.
  7. Asserts the same curl now succeeds.
  8. Asserts `echo '{"cmd":"list"}' ...` still returns empty entries
     (session adds are not persisted).
  9. Asserts `echo '{"cmd":"add_persist","host":"foo.com","port":443}' | nc...`
     → `{"ok":true}`, then `{"cmd":"list"}` → entries contains foo.com.
  10. Kills the daemon, starts a new one, asserts `list` still has foo.com.
  11. Tests `add_persist` writes atomically: kill the daemon mid-write?
      Skip this — too flaky for a shell script. Instead just assert
      the JSON file at `$XDG_CONFIG_HOME/pi-firewall/allow.json` is
      valid JSON after a sequence of adds and removes.
- Use a temporary `XDG_CONFIG_HOME` and `XDG_RUNTIME_DIR` so the test
  doesn't clobber the user's real allowlist. `mktemp -d` for both.
- Cleanup with `trap` to kill the daemon and remove the tempdir.

**Done when:** `bash scripts/integration-test.sh` exits 0.

## Phase 3 — extension type-check

The TypeScript extension has not been type-checked.

**Tasks:**
- In `extension/`, add a minimal `tsconfig.json`:
  ```json
  {
    "compilerOptions": {
      "target": "ES2022",
      "module": "ESNext",
      "moduleResolution": "bundler",
      "strict": true,
      "esModuleInterop": true,
      "skipLibCheck": true,
      "noEmit": true,
      "types": ["node"]
    },
    "include": ["index.ts"]
  }
  ```
- Run `npx tsc --noEmit` against the extension. Fix every error.
- Do **not** install `@mariozechner/pi-coding-agent` as a real
  dependency — the extension is loaded by pi at runtime via jiti, and
  the imports are resolved against pi's own copy. Type errors against
  the peer dep are expected; either install the package as a devDep
  for type-checking only, or add `// @ts-expect-error` with a clear
  comment.

**Likely issues:**
- The `dispatcher` field on `fetch` may need `@types/node@^22` or a
  custom declaration.
- `ExtensionContext` and `ExtensionAPI` types might not match exactly —
  if pi's API has evolved, this is the place where it shows up. Adapt
  the extension's types to whatever is published, not vice versa.

**Done when:** `npx tsc --noEmit` is silent.

## Phase 4 — bwrap wrapper script

Write the bwrap wrapper that launches pi inside the jail. The shape was
sketched earlier in conversation; finalize it as `scripts/pi-jail`.

**Architectural anchors:**
- `--unshare-all --share-net` — every namespace except network.
- `--unshare-user --uid 5555 --gid 5555` — predictable UID for the
  future nftables rule. (UID 5555 is arbitrary; pick whatever isn't
  used on your system. Document the choice in a comment.)
- `--clearenv` then selective `--setenv`. Allowlist:
  `PATH`, `HOME`, `USER`, `TERM`, `LANG`, `NIX_SSL_CERT_FILE`,
  `SSL_CERT_FILE`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`.
- `--tmpfs $HOME` then ro-bind only `$PI_AUTH_DIR`.
- `--ro-bind /nix/store /nix/store`, `/etc/static`, `/etc/resolv.conf`,
  `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, `/etc/hosts`.
- `--bind "$PROJECT_DIR" "$PROJECT_DIR" --chdir "$PROJECT_DIR"`.
- `--die-with-parent --new-session`.
- `--setenv HTTPS_PROXY http://127.0.0.1:8118` — pi's web_fetch and
  bash subshells both inherit this.

**Tasks:**
- Write `scripts/pi-jail` (bash, executable).
- First positional arg is the project directory; defaults to `$PWD`.
- Remaining args are passed to `pi`.
- Find pi via `command -v pi`; fail loudly if not found.
- Allow override of `PI_AUTH_DIR` via env var; default to
  `$HOME/.config/pi`. **The agent should ask the human to verify this
  is where pi actually stores tokens** before committing — pi's
  storage location may have changed.

**Done when:** `scripts/pi-jail /tmp/empty echo hello` runs and prints
`hello`. Run inside the wrapper: `ls $HOME` should show only the pi
auth dir, not the user's real home.

**Human checkpoint:** confirm pi works inside the wrapper by running
`scripts/pi-jail <some-project-dir>` interactively and trying a tool
call. The first time, `web_fetch` to a new host should produce the
prompt-and-retry flow. Commit only after this works.

## Phase 5 — pre-populate the allowlist with default hosts

Without this, the first session is hostile: every tool pi uses (npm,
git, the LLM API, your distro mirror) prompts on first contact.

**Tasks:**
- Write `scripts/seed-allowlist` (bash). It should be idempotent
  (running it twice is fine) and use the management socket to add
  hosts so the daemon owns writes.
- Hosts to seed (let the human edit this list before running):
  - `api.anthropic.com:443`
  - `api.openai.com:443`
  - `github.com:443`
  - `api.github.com:443`
  - `objects.githubusercontent.com:443`
  - `raw.githubusercontent.com:443`
  - `registry.npmjs.org:443`
  - `crates.io:443`
  - `static.crates.io:443`
  - `index.crates.io:443`
  - `pypi.org:443`
  - `files.pythonhosted.org:443`
- Each host added via `add_persist` over the mgmt socket.
- Print a summary at the end: "added N, already-present M".

**Done when:** running the script populates the daemon's allowlist
and `/firewall-list` (via the management socket) shows the seeded
hosts.

**Do not:** hardcode this list in the daemon. It belongs in user-space
config, not in the binary.

## Phase 6 — systemd user service for the daemon

Make the daemon start on login and restart on crash.

**Tasks:**
- Write `systemd/tau.service` as a `--user` unit:
  - `ExecStart=` `${pkgs.tau}/bin/tau serve` (via the home-manager module),
    or the absolute path during manual install.
  - `Restart=on-failure`, `RestartSec=2s`.
  - `NoNewPrivileges=yes`.
  - `ProtectSystem=strict`.
  - `ProtectHome=read-only` with `ReadWritePaths=%h/.config/tau`.
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
  - `RestrictNamespaces=yes`, `LockPersonality=yes`,
    `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`,
    `SystemCallArchitectures=native`.
  - `RuntimeDirectory=tau` if you want systemd to manage the runtime
    dir (optional; we currently default to `$XDG_RUNTIME_DIR/tau.sock`).
- Write a one-line README block explaining
  `systemctl --user enable --now tau.service`.

**Done when:** `systemctl --user start tau` brings up the daemon,
`systemctl --user status tau` shows it running, and
`systemctl --user restart tau` cleanly cycles it without leaving stale
sockets.

## Phase 7 — flake outputs (declarative bundle)

This is the artifact that ties everything together for the user's NixOS
config. Already in place: `flake.nix` exposes a `devShell` and
`packages.${system}.pi` (upstream binary). Still needed: a tau package,
and the two consumer-facing modules.

**Tasks:**

- Add `packages.${system}.tau` to `flake.nix` — build the Rust binary
  with `crane` (mirroring dactyl's pattern: a deps-only build cached
  separately from the full source). `cargoLock.lockFile = ./Cargo.lock`
  for reproducibility.

- Add `homeManagerModules.default` (probably in `nix/home-manager.nix`):
  - Installs `tau` and `pi` on PATH via `home.packages`.
  - Writes the systemd user service from Phase 6 (unit invokes
    `${pkgs.tau}/bin/tau serve`).
  - Optionally symlinks the pi extension (from Phase 3) into
    `~/.pi/agent/extensions/tau`.

- Add `nixosModules.default` (probably in `nix/nixos.nix`):
  - Adds the nftables rule from Phase 8, gated on
    `services.tau.enforce` (default `false` so users opt in).
  - When Phase 8.5 lands, this is where the redirect-to-honeypot rule
    goes too.

**Done when:** `nix flake check` passes, and a minimal test config that
imports both modules evaluates without error.

**Human checkpoint:** the user must `home-manager switch` and
`nixos-rebuild switch` to actually apply the modules. Don't try to do
this from the agent.

## Phase 8 — nftables enforcement rule

This is the kernel-level enforcement that elevates the proxy from
honor-system to enforcement-grade. It must be installed via the NixOS
module from Phase 7, never via raw `nft` commands (those don't
survive reboot and aren't reproducible).

**Architectural anchor:** the rule keys off the bwrap jail's UID
(5555). The bwrap wrapper from Phase 4 must use `--uid 5555`
consistently. If the wrapper changes the UID, this rule must change
in lockstep.

**Tasks:**
- In the NixOS module from Phase 7, add (gated on
  `services.pi-firewall.enforce`):
  ```nix
  networking.nftables = {
    enable = true;
    tables.pi-jail = {
      family = "inet";
      content = ''
        chain output {
          type filter hook output priority 0; policy accept;
          meta skuid 5555 ip  daddr 127.0.0.1 tcp dport 8118 accept
          meta skuid 5555 ip6 daddr ::1       tcp dport 8118 accept
          meta skuid 5555 oifname "lo" accept
          meta skuid 5555 reject with icmpx type admin-prohibited
        }
      '';
    };
  };
  ```
- Document in the README that `services.pi-firewall.enforce = true;`
  is required for real enforcement.

**Done when:** with the rule active, `unset HTTPS_PROXY && curl -v
https://example.com` from inside the bwrap jail fails with
"Permission denied" or "Connection refused" rather than succeeding.

**Human checkpoint:** the user must verify this themselves on their
real NixOS machine. The agent must not try to install nftables rules
from inside any container or test environment — those rules apply to
the host kernel and are dangerous to mess with from automated tooling.

## Phase 8.5 — escape detection and honeypot

Phase 8 makes the firewall actually a firewall. Phase 8.5 makes it
*observable*: when a tool inside the jail bypasses `HTTPS_PROXY` and
opens a direct connection, we want to surface that in the pi session so
the user can distinguish "broken tool" from "misbehaving tool" from
"compromised tool." Without this, escape attempts produce a silent
`Connection refused` and the user is in the dark.

The mechanism is a NAT redirect: instead of dropping bypass attempts at
the kernel, we redirect them to a local honeypot port that the daemon
binds. The daemon recovers the original destination via
`SO_ORIGINAL_DST`, logs the event, and emits it on a new events stream
that the extension subscribes to.

**Architectural anchors specific to this phase:**

- **The honeypot never reads or writes bytes from/to the suspect
  process.** Accept the connection, recover the destination via
  `getsockopt(SOL_IP, SO_ORIGINAL_DST)`, emit the event, close the
  socket. No per-connection buffer allocation, no fingerprinting
  opportunity, no TLS handshake to forge.

- **Bounded concurrency.** A `tokio::sync::Semaphore` (default 32)
  caps simultaneous honeypot accepts so a malicious tool can't
  FD-exhaust the daemon by hammering with connections.

- **Hard 500ms-per-connection timeout** backstops the semaphore and
  protects against half-open-connection exhaustion.

- **Dedup at the events layer.** Suppress duplicate
  `(dst_addr, dst_port)` events within a 5-second window so retry
  storms don't spam the pi session — but include a count in the
  emitted event so the user knows it wasn't just one attempt.

- **No reverse DNS lookups inside the daemon.** A compromised tool
  could trigger DNS exfil by hitting many distinct destinations and
  inducing the daemon to look them up. The event carries the IP only;
  the extension can enrich with reverse DNS if it wants to, on its
  own time.

**nftables changes (replace Phase 8's reject with redirect):**

```nix
networking.nftables.tables.pi-jail-filter = {
  family = "inet";
  content = ''
    chain output {
      type filter hook output priority 0; policy accept;
      meta skuid 5555 ip  daddr 127.0.0.1 tcp dport { 8118, 8119 } accept
      meta skuid 5555 ip6 daddr ::1       tcp dport { 8118, 8119 } accept
      meta skuid 5555 oifname "lo" accept
      meta skuid 5555 reject with icmpx type admin-prohibited
    }
  '';
};
networking.nftables.tables.pi-jail-nat = {
  family = "ip";
  content = ''
    chain output {
      type nat hook output priority -100; policy accept;
      meta skuid 5555 ip daddr 127.0.0.1 return
      meta skuid 5555 oifname "lo" return
      meta skuid 5555 tcp redirect to :8119
    }
  '';
};
```

The NAT chain runs at priority -100 (before the filter at 0). For UID
5555 traffic that isn't to localhost or the loopback interface, the
destination is rewritten to `127.0.0.1:8119` and the original is
preserved in conntrack for `SO_ORIGINAL_DST`. The filter chain then
sees a packet to `127.0.0.1:8119`, which it accepts. UID-5555 traffic
that bypasses TCP entirely (UDP, ICMP, raw sockets — including
potential HTTP/3 / QUIC) doesn't match the redirect rule and falls
through to the explicit reject in the filter chain.

A symmetric `family = "ip6"` NAT table is needed for v6 coverage.
Initial implementation can ship v4-only and add v6 once the v4 path
is verified.

**Daemon changes:**

- New `src/honeypot.rs` module — third tokio task, listens on
  `127.0.0.1:8119`. Per-connection logic:
  1. Try to acquire a semaphore permit. If full, close immediately.
  2. `getsockopt(IPPROTO_IP, SO_ORIGINAL_DST)` to recover the
     destination. The `socket2` or `nix` crate is fine for the FFI;
     don't roll our own.
  3. Run the event through the dedup window.
  4. If novel, emit on the events stream.
  5. Close the socket. Do not read.

- New events stream. JSON lines, one per event:

  ```json
  {"ts":"2026-05-10T22:00:00Z","kind":"escape-attempt","host":"1.2.3.4","port":443,"count":1}
  ```

  Easiest implementation: a `subscribe_events` command on the existing
  mgmt socket that switches the connection into "stream mode" — the
  daemon writes events as they happen, the client reads. Alternative
  is a separate `pi-firewall.events.sock`. Pick the one that fits the
  mgmt protocol cleaner once it's concrete.

**Extension changes:**

- Subscribe to the events stream on init; keep the connection open for
  the life of the pi session.
- Render `escape-attempt` events as a red-alert notification. Sample:

  > ⚠️ **Bypass attempt blocked.** A process inside the jail tried
  > to connect directly to `1.2.3.4:443`, ignoring `HTTPS_PROXY`. The
  > kernel redirected it to the honeypot. Likely cause: the tool
  > doesn't respect proxy env vars. If you didn't expect any tool to
  > reach this destination, treat it as suspicious and inspect the
  > running processes.

**Threat model for the honeypot:**

The honeypot accepts arbitrary bytes from a process that has already
demonstrated it ignores our policy. Attack surface analysis:

1. *Connection-flood DoS:* mitigated by the semaphore cap (32 concurrent
   accepts). Excess connections return immediately at the OS level.

2. *Slowloris / half-open exhaustion:* mitigated by the 500ms hard
   timeout. A connection that lingers past that gets dropped.

3. *Bytes-in attacks:* we never call `read()`, so the suspect process
   can send all the bytes it wants — they sit in the kernel receive
   buffer and get discarded when we close. No parser to confuse, no
   buffer to overflow.

4. *Bytes-out / fingerprinting:* we never call `write()`. The suspect
   process sees a TCP connection that closes immediately with no data.
   This is observable but not informative.

5. *PID resolution races:* deferred to a follow-up phase. Walking
   `/proc/net/tcp` plus `/proc/<pid>/fd` to map src-port → PID is slow
   (~10ms) and racy (process may exit before we look). Initial
   implementation reports destination only.

6. *Compromise of the daemon process itself:* bounded by the systemd
   hardening from Phase 6 (`NoNewPrivileges`, `ProtectSystem`,
   `MemoryDenyWriteExecute`, etc.). The daemon never holds elevated
   privileges; the worst-case is loss of allowlist integrity, not host
   compromise.

What we explicitly do **not** defend against:

- A process inside the jail that escalates to root via a kernel
  vulnerability. That's the kernel's problem, and our nftables UID
  rule still applies regardless.
- Side-channel inference of the allowlist via timing of
  `denied-unknown-host` responses. Real but not interesting for a
  personal-machine threat model.

**Tasks:**
- Update the Phase 7 NixOS module with the redirect rules above.
- Add `src/honeypot.rs` and wire it as a third `tokio::spawn` in
  `main.rs`.
- Add the events stream to the mgmt protocol (or a new socket).
- Implement dedup with a `HashMap<(IpAddr, u16), Instant>` and 5s
  expiry.
- Update `extension/index.ts` to subscribe and render escape events.
- Document the new behavior in the README.

**Done when:** with the rules active and the daemon running, a
non-cooperating tool inside the jail (test with
`unset HTTPS_PROXY && curl -v https://example.com`) produces an
`escape-attempt` event in the pi session that names the destination.
A burst of rapid retries to the same destination collapses into a
single event with a count.

**Human checkpoint:** the user must verify this from their real
machine, like Phase 8. The agent must not install nftables rules from
a container or test environment.

## Phase 9 — observability and audit log

The user wants to be able to ask "what hosts has pi tried this week"
and get an answer. The `tracing` calls in the daemon are noisy log
output; this phase formalizes them as a queryable audit trail.

**Tasks:**
- Add a `--audit-log <path>` flag to the daemon. When set, every
  CONNECT decision is appended as one line of JSON:
  ```json
  {"ts":"2026-05-10T22:00:00Z","host":"github.com","port":443,"decision":"allow","reason":"persistent"}
  ```
- Use `tokio::fs::OpenOptions::append`, no buffering. Fsync is
  overkill; OS-level buffering is fine for an audit log.
- Add to the README: the user can `jq -s 'group_by(.host)|...'` over
  this log to summarize.

**Done when:** the daemon writes one line per decision to the
specified path, and the JSON parses with `jq`.

**Defer:** structured log shipping, log rotation. The user can wire
this up with `logrotate` or systemd journal as they prefer.

## Phase 10 — defense-in-depth additions (optional)

Items the user has explicitly deferred. **Do not implement without
asking** — these have real complexity and the user wants to evaluate
them in isolation.

- Landlock layer on the bwrap wrapper (refuse path access at kernel
  level). Either via the `landrun` external tool or a small Rust shim
  using the `landlock` crate.
- seccomp filter via `--seccomp FD` on the bwrap invocation.
- Proxy self-sandboxing improvements beyond what the systemd unit
  already provides.

If the user requests any of these, plan them as their own phases
with their own checkpoints.

---

## How to use this plan

Work phase by phase. At each "done when" checkpoint, stop, run the
verification command, and either:

1. Move to the next phase if it passes.
2. Surface the failure with a brief diagnosis if it doesn't.

Do not skip phases. Do not bundle multiple phases into one commit.
Each phase is small enough to review in one sitting; that's the point.

If a phase reveals an architectural conflict (e.g. an anchor in the
"Architectural anchors" section is unworkable), stop and ask. Don't
silently change the design.

If a phase requires the user's machine (Phase 4 human checkpoint,
Phase 7 home-manager switch, Phase 8 nftables verification), stop and
hand back to the user with a clear "please run X and confirm Y."

The total scope is small — roughly 1500 lines of Rust+TS+Nix+bash, and
the existing code already covers ~1000 of those. Most of the work is
verification, integration, and the NixOS packaging.
