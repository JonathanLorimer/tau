# pi-firewall — implementation plan

## Context for the agent

This plan assumes you (Claude Code) are picking up partway through. The
following components already exist in this repo and **should not be
rewritten from scratch** — your job is to verify they compile, fix what
the toolchain complains about, and build out the unbuilt pieces:

- `Cargo.toml` — Rust crate manifest
- `src/main.rs` — entry point with two listeners (TCP proxy + mgmt socket)
- `src/proxy.rs` — HTTP CONNECT proxy with deny-marker response
- `src/mgmt.rs` — unix-socket JSON protocol for allowlist mutations
- `src/allowlist.rs` — persistent + session allowlist with atomic writes
- `extension/index.ts` — pi extension: web_fetch tool, deny-and-retry, slash commands
- `extension/package.json` — peer deps
- `README.md` and `extension/README.md` — design docs

These were written without a working compiler in the loop, so expect type
errors, missing trait imports, or borrow issues. **Phase 1 is to make them
compile and pass tests, not to rewrite them.** Preserve the architecture
and comments — they document non-obvious decisions.

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
- Write `systemd/pi-firewall.service` as a `--user` unit:
  - `ExecStart=` the absolute path to the binary (use `%h` for `$HOME`).
  - `Restart=on-failure`, `RestartSec=2s`.
  - `NoNewPrivileges=yes`.
  - `ProtectSystem=strict`.
  - `ProtectHome=read-only` with
    `ReadWritePaths=%h/.config/pi-firewall`.
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
  - `RestrictNamespaces=yes`, `LockPersonality=yes`,
    `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`,
    `SystemCallArchitectures=native`.
  - `RuntimeDirectory=pi-firewall` if you want systemd to manage the
    runtime dir (optional).
- Write a one-line README block in the daemon README explaining
  `systemctl --user enable --now pi-firewall.service`.

**Done when:** `systemctl --user start pi-firewall` brings up the
daemon, `systemctl --user status` shows it running, and
`systemctl --user restart` cleanly cycles it without leaving stale
sockets.

## Phase 7 — NixOS module (declarative bundle)

This is the artifact that ties everything together for the user's
NixOS config. It lives in this repo as `nix/module.nix` and is
intended to be imported via flake from the user's home-manager.

**Tasks:**
- Write `flake.nix` exposing:
  - `packages.${system}.pi-firewall` — the Rust binary built via
    `rustPlatform.buildRustPackage`.
  - `homeManagerModules.default` — a module that:
    - Installs the `pi-firewall` binary on `PATH`.
    - Installs the `pi-jail` wrapper on `PATH` as a
      `pkgs.writeShellApplication` with declared dependencies.
    - Configures the systemd user service (writes the unit from
      Phase 6 verbatim).
    - Optionally installs the pi extension by symlinking
      `$out/share/pi-firewall/extension` to `~/.pi/agent/extensions/firewall`.
  - `nixosModules.default` — a module that:
    - Adds the nftables rule from Phase 8 (gated on a config option
      `services.pi-firewall.enforce` defaulting to `false` so users
      opt in).
- Use `cargoLock.lockFile = ./Cargo.lock` so reproducible builds.

**Done when:** `nix flake check` passes, and a minimal test config
that imports the modules evaluates without error.

**Human checkpoint:** the user must `home-manager switch` and
`nixos-rebuild switch` to actually apply the modules. Don't try to
do this from the agent.

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
