# NixOS module for tau's system-level prerequisites.
#
# Concerns split between this module and `homeManagerModules.default`:
#
#   - User-level (HM module): tau binary, pi binary, extension symlink,
#     `tau serve` as a systemd user service.
#   - System-level (this module): bubblewrap on PATH, the kernel knob
#     the bwrap jail needs to run unprivileged, and the nftables rule
#     that turns the proxy from honor-system into a real firewall.
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
        refuses its packets with ICMP admin-prohibited.

        Phase 8.5 will switch the reject to a NAT redirect toward a
        honeypot port on the daemon for richer telemetry on bypass
        attempts.

        Enabling this also enables `networking.nftables`, which may
        coexist with `networking.firewall` depending on your config.
      '';
    };

    jailUid = lib.mkOption {
      type = lib.types.int;
      default = 5555;
      description = ''
        UID used by `tau jail` for the sandboxed process. Load-bearing:
        it must match `JAIL_UID` in `cli/src/cmd/jail.rs`, and the
        nftables enforcement rule keys on the same value. Changing one
        without the other breaks enforcement.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # bubblewrap on PATH at the system level so `tau jail` finds it
    # regardless of whether the user is inside a dev shell.
    environment.systemPackages = [pkgs.bubblewrap];

    # Required for `bwrap --unshare-user --uid <jailUid>` to work without
    # bwrap being setuid. On most modern kernels this is on by default,
    # but hardened configs disable it — set it explicitly so the jail
    # keeps working.
    security.unprivilegedUsernsClone = true;

    # The enforcement rule. With `policy accept`, only packets that match
    # the explicit jail-UID rules are touched — other users (root, you)
    # are unaffected. The rule order matters:
    #
    #   1. Accept to the proxy on loopback (the legitimate path).
    #   2. Accept any traffic on the `lo` interface — pi may legitimately
    #      need to talk to local services (dev servers, databases, etc.).
    #      We trust localhost; the threat model is external exfiltration.
    #   3. Reject everything else from the jail UID with ICMP
    #      admin-prohibited, so the application sees an immediate
    #      "connection refused" rather than a silent timeout.
    networking.nftables = lib.mkIf cfg.enforce {
      enable = true;
      tables.tau-jail = {
        family = "inet";
        content = ''
          chain output {
            type filter hook output priority 0; policy accept;
            meta skuid ${toString cfg.jailUid} ip  daddr 127.0.0.1 tcp dport 8118 accept
            meta skuid ${toString cfg.jailUid} ip6 daddr ::1       tcp dport 8118 accept
            meta skuid ${toString cfg.jailUid} oifname "lo" accept
            meta skuid ${toString cfg.jailUid} reject with icmpx type admin-prohibited
          }
        '';
      };
    };
  };
}
