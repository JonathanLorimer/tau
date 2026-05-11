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
# binary and tunes a kernel feature). The home-manager module is
# `services.tau` instead, since on the user side the main thing
# happening is a systemd user unit running `tau serve`.
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
        Install the nftables rules that constrain outbound TCP from
        `programs.tau.jailUid`. With this enabled:

          - traffic from the jail UID to the proxy (`127.0.0.1:8118`)
            and any loopback destination is accepted unchanged;
          - all other TCP traffic from the jail UID is DNAT-redirected
            to the local honeypot at `127.0.0.1:8119`, where the daemon
            records the original destination via `SO_ORIGINAL_DST` and
            emits an `escape-attempt` event to subscribed extensions;
          - non-TCP traffic from the jail UID is rejected with ICMP
            admin-prohibited so the application sees a clean failure
            rather than a silent timeout.

        Currently IPv4 only — the NAT chain rewrites v4 only. v6 traffic
        falls through to the filter's reject so it's still blocked, just
        not redirected to the honeypot for telemetry.

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

    # Enforcement is split across two tables. With `policy accept` on each
    # chain, only packets that match the explicit jail-UID rules are
    # touched — other users (root, you) are unaffected.
    #
    # The NAT chain runs at priority -100, well before the filter chain at
    # priority 0. Order of effect on a jail-UID v4 packet to a non-loopback
    # destination:
    #
    #   1. nat output (prio -100) — destination rewritten to 127.0.0.1:8119.
    #      The original destination is preserved in conntrack and recovered
    #      by the honeypot via `SO_ORIGINAL_DST`.
    #   2. filter output (prio 0) — the rewritten packet now targets
    #      127.0.0.1:8119, which matches the loopback-to-honeypot accept rule.
    #
    # Traffic that doesn't match the NAT redirect (loopback, non-TCP) flows
    # through the filter chain unchanged and is either accepted (loopback)
    # or rejected (everything else).
    networking.nftables = lib.mkIf cfg.enforce {
      enable = true;
      tables.tau-jail-filter = {
        family = "inet";
        content = ''
          chain output {
            type filter hook output priority 0; policy accept;
            meta skuid ${toString cfg.jailUid} ip  daddr 127.0.0.1 tcp dport { 8118, 8119 } accept
            meta skuid ${toString cfg.jailUid} ip6 daddr ::1       tcp dport { 8118, 8119 } accept
            meta skuid ${toString cfg.jailUid} oifname "lo" accept
            meta skuid ${toString cfg.jailUid} reject with icmpx type admin-prohibited
          }
        '';
      };
      tables.tau-jail-nat = {
        family = "ip";
        content = ''
          chain output {
            type nat hook output priority -100; policy accept;
            meta skuid ${toString cfg.jailUid} ip daddr 127.0.0.1 return
            meta skuid ${toString cfg.jailUid} oifname "lo" return
            meta skuid ${toString cfg.jailUid} tcp redirect to :8119
          }
        '';
      };
    };
  };
}
