# Home-manager-flavored systemd user unit for `tau serve`.
#
# Returns the attrset to plug into `systemd.user.services.tau`. Keep this
# file home-manager-shaped (camelCase keys: Unit, Service, Install); if we
# ever need a NixOS system-level equivalent, that gets its own file with
# lowercase keys (description, restart, etc.).
{
  tauPackage,
  xdgUtils,
  glib,
}: {
  Unit = {
    Description = "tau firewall daemon (HTTPS CONNECT proxy + management socket)";
    # Wait for the graphical user session so the runtime dir (where we put
    # the mgmt socket) is ready to use.
    After = ["default.target"];
  };

  Install = {
    WantedBy = ["default.target"];
  };

  Service = {
    ExecStart = "${tauPackage}/bin/tau serve";
    Environment = [
      "PATH=${xdgUtils}/bin:${glib}/bin"
      # On systemd+dbus-broker (NixOS default), the session bus socket is
      # always at $XDG_RUNTIME_DIR/bus (%t expands to XDG_RUNTIME_DIR in
      # unit specifiers). Setting this explicitly avoids relying on the
      # variable being present in the user manager's environment, which can
      # be absent on compositors like Sway that don't always import it.
      "DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus"
    ];
    Restart = "on-failure";
    RestartSec = "2s";

    # Hardening. Tau is a proxy, so it explicitly needs outbound TCP/IP
    # in addition to the loopback listener and the mgmt unix socket —
    # AF_INET + AF_INET6 + AF_UNIX covers all three. Outbound destination
    # filtering is policy (the allowlist), enforced in-process; we don't
    # add IPAddressAllow/Deny here since the set of upstreams is dynamic.
    # On the filesystem side: read-only home with one rw exception for
    # the daemon's config dir, and the standard set of protections.
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = "read-only";
    # %h/.config/tau — allow.json (and optionally audit.log) live here.
    # %t           — $XDG_RUNTIME_DIR; the mgmt socket binds at %t/tau.sock.
    #                Without this, the daemon's UnixListener::bind returns
    #                EROFS because ProtectSystem=strict makes /run read-only
    #                in the service's mount namespace.
    ReadWritePaths = ["%h/.config/tau" "%t"];
    # Pass display variables so xdg-open can find the compositor and open
    # a browser via the XDG portal when handling open_url commands.
    PassEnvironment = "DISPLAY WAYLAND_DISPLAY XDG_CURRENT_DESKTOP";

    RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6";
    RestrictNamespaces = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    RestrictRealtime = true;
    SystemCallArchitectures = "native";
  };
}
