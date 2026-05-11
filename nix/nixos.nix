# NixOS module for tau's system-level prerequisites.
#
# Concerns split between this module and `homeManagerModules.default`:
#
#   - User-level (HM module): tau binary, pi binary, extension symlink,
#     `tau serve` as a systemd user service.
#   - System-level (this module): bubblewrap on PATH, the kernel knob
#     the bwrap jail needs to run unprivileged, and (Phase 8) the
#     nftables rule that turns the proxy from honor-system into a real
#     firewall.
#
# Naming note: this module lives under `programs.tau`, parallel to
# `programs.firejail` (also a sandbox-support module that installs a
# binary and tunes a kernel feature). The same `programs.tau` namespace
# exists in the HM module; they're separate option trees, so there's no
# collision — `programs.tau.enable` in NixOS means "install system-level
# prerequisites," in HM it means "install tau for this user."
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.programs.tau;
in {
  options.programs.tau = {
    enable = lib.mkEnableOption ''
      tau system-level support: install bubblewrap and enable unprivileged
      user namespaces so the bwrap jail can run without setuid.
    '';

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Install the nftables rule that drops outbound TCP from
        `programs.tau.jailUid` except to the local proxy at
        `127.0.0.1:8118`. With this enabled, a tool inside the bwrap jail
        that ignores HTTPS_PROXY can't bypass the firewall — the kernel
        refuses its packets.

        Currently a no-op stub; Phase 8 in PLAN.md will implement the
        rule (and Phase 8.5 will switch the drop to a redirect toward
        the honeypot port for richer telemetry).
      '';
    };

    jailUid = lib.mkOption {
      type = lib.types.int;
      default = 5555;
      description = ''
        UID used by `tau jail` for the sandboxed process. This is
        load-bearing: it must match `JAIL_UID` in `cli/src/cmd/jail.rs`,
        and the Phase 8 nftables rule keys on the same value. Changing
        one without the other breaks enforcement.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # bubblewrap on PATH at the system level so `tau jail` finds it
    # regardless of whether the user is inside a dev shell.
    environment.systemPackages = [pkgs.bubblewrap];

    # Required for `bwrap --unshare-user --uid 5555` to work without
    # bwrap being setuid. On most modern kernels this is on by default,
    # but hardened configs disable it — set it explicitly so the jail
    # keeps working.
    security.unprivilegedUsernsClone = true;

    # Surface the unimplemented `enforce` flag so users don't quietly
    # assume the kernel rule is active when it isn't.
    warnings = lib.optional cfg.enforce ''
      programs.tau.enforce is set, but the nftables enforcement rule is
      not implemented yet (Phase 8 in PLAN.md). The bwrap jail is currently
      honor-system: tools that ignore HTTPS_PROXY bypass the firewall.
    '';

    # Phase 8 will populate this block with the actual rule:
    #
    #   networking.nftables = lib.mkIf cfg.enforce {
    #     enable = true;
    #     tables.tau-jail = {
    #       family = "inet";
    #       content = ''
    #         chain output {
    #           type filter hook output priority 0; policy accept;
    #           meta skuid ${toString cfg.jailUid} ip  daddr 127.0.0.1 tcp dport 8118 accept
    #           meta skuid ${toString cfg.jailUid} ip6 daddr ::1       tcp dport 8118 accept
    #           meta skuid ${toString cfg.jailUid} oifname "lo" accept
    #           meta skuid ${toString cfg.jailUid} reject with icmpx type admin-prohibited
    #         }
    #       '';
    #     };
    #   };
  };
}
