{
  config,
  lib,
  pkgs,
  tauPackages,
  ...
}: let
  cfg = config.services.tau;
in {
  options.services.tau = {
    enable = lib.mkEnableOption "tau personal coding harness";

    package = lib.mkOption {
      type = lib.types.package;
      default = tauPackages.tau;
      defaultText = "tauPackages.tau";
      description = "The tau Rust binary to install on PATH.";
    };

    installPi = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to install the pi coding agent on PATH.";
    };

    toolDeps = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = with pkgs; [fd ripgrep];
      defaultText = lib.literalExpression "with pkgs; [ fd ripgrep ]";
      description = ''
        Runtime tools pi expects on PATH but doesn't bundle. Threaded
        into the pi derivation via `makeWrapper` — pi's `$PATH` is
        prefixed with the canonical store-paths of these packages, so
        pi finds them regardless of the launching shell's environment
        and the jail doesn't need to bind any host profile dirs.

        Without this, pi auto-downloads `fd` and `rg` from GitHub
        releases on first run, which fails under the tau firewall.
        Extend the list to make additional tools (`git`, `jq`, …)
        reachable from inside the jail.
      '';
    };

    pi = lib.mkOption {
      type = lib.types.package;
      default = tauPackages.pi.override {inherit (cfg) toolDeps;};
      defaultText = "tauPackages.pi.override { inherit (cfg) toolDeps; }";
      description = ''
        The pi package to install when installPi = true. By default the
        flake's pi is rewrapped with `cfg.toolDeps` on its PATH.
      '';
    };

    installExtension = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to symlink the tau extension into
        ~/.pi/agent/extensions/tau so pi auto-discovers it.
      '';
    };

    extension = lib.mkOption {
      type = lib.types.package;
      default = tauPackages.tau-extension;
      defaultText = "tauPackages.tau-extension";
      description = "The tau-extension package to symlink when installExtension = true.";
    };

    service.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to run `tau serve` as a systemd user service. Disable
        this if you want to run the daemon manually (e.g. for debugging)
        or under a different supervisor.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages =
      [cfg.package]
      ++ lib.optional cfg.installPi cfg.pi;

    home.file.".pi/agent/extensions/tau" = lib.mkIf cfg.installExtension {
      source = "${cfg.extension}/share/tau-extension";
    };

    # The systemd unit's `ReadWritePaths=%h/.config/tau` requires the
    # directory to exist before the service starts — systemd's mount
    # namespace setup binds the path in, and bind-mounting a missing dir
    # fails with `status=226/NAMESPACE`. We create an empty `.keep` file so
    # home-manager materializes the directory at activation time. The
    # daemon writes `allow.json` (and optionally `audit.log`) inside.
    home.file.".config/tau/.keep" = lib.mkIf cfg.service.enable {
      text = "";
    };

    systemd.user.services.tau = lib.mkIf cfg.service.enable (
      import ./systemd-unit.nix {tauPackage = cfg.package;}
    );
  };
}
