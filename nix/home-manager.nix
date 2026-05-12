{
  config,
  lib,
  pkgs,
  tauPackages,
  ...
}: let
  cfg = config.programs.tau;
in {
  options.programs.tau = {
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
        Whether to symlink the bundled tau extension into
        ~/.pi/agent/extensions/tau. Independent of the user-supplied
        `extensions` attrset — those install regardless.
      '';
    };

    extension = lib.mkOption {
      type = lib.types.package;
      default = tauPackages.tau-extension;
      defaultText = "tauPackages.tau-extension";
      description = "The tau-extension package to symlink when installExtension = true.";
    };

    extensions = lib.mkOption {
      type = lib.types.attrsOf (lib.types.either lib.types.package lib.types.path);
      default = {};
      example = lib.literalExpression ''
        {
          # Source from a package output:
          my-ext = "''${pkgs.someExtensionPkg}/share/pi-extension";
          # Or a literal path:
          local = ./extensions/local;
        }
      '';
      description = ''
        Additional pi extensions to symlink into
        `~/.pi/agent/extensions/<name>/`. Each value is a directory
        containing the extension's entry point (typically `index.ts`
        or `index.js`) plus its `package.json`. See pi's docs/extensions.md.

        The bundled tau extension is managed separately via
        `installExtension` / `extension` and is not part of this attrset.
      '';
    };

    skills = lib.mkOption {
      type = lib.types.attrsOf (lib.types.either lib.types.package lib.types.path);
      default = {};
      example = lib.literalExpression ''
        {
          code-review = ./skills/code-review;
          security    = "''${pkgs.someSkillsPkg}/share/skill";
        }
      '';
      description = ''
        Agent skills to symlink into `~/.pi/agent/skills/<name>/`.
        Each value is a directory following the
        [agentskills.io](https://agentskills.io) spec (a `SKILL.md`
        plus any supporting files). See pi's docs/skills.md.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.attrs;
      default = {};
      example = lib.literalExpression ''
        {
          defaultProvider = "anthropic";
          defaultModel    = "claude-sonnet-4-6";
          theme           = "dark";
          quietStartup    = true;
        }
      '';
      description = ''
        Pi's `~/.pi/agent/settings.json`, written as a home-manager-
        managed symlink to a JSON file. The attrset is serialized as-is;
        see pi's docs/settings.md for the available keys. Set to `{}`
        (the default) to leave the file unmanaged so pi can write to it
        from `/settings`.
      '';
    };

    enableService = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to run `tau serve` as a systemd user service. Disable
        this if you want to run the daemon manually (e.g. for debugging)
        or under a different supervisor.
      '';
    };

    systemPrompt = lib.mkOption {
      type = lib.types.nullOr lib.types.lines;
      default = null;
      example = ''
        You are a precise software engineer. Default to small, focused
        diffs. Ask before introducing new dependencies.
      '';
      description = ''
        Replace pi's default system prompt entirely. When set, written
        to `~/.pi/agent/SYSTEM.md` as a home-manager-managed symlink.
        Leave as `null` to keep pi's built-in prompt.

        Project-level overrides (`.pi/SYSTEM.md`) take precedence over
        this; manage those per-repo, not here.
      '';
    };

    appendSystemPrompt = lib.mkOption {
      type = lib.types.nullOr lib.types.lines;
      default = null;
      example = ''
        Conventions for this machine: prefer fd over find, rg over
        grep, and jj over git when the repo is colocated.
      '';
      description = ''
        Append text to pi's default system prompt without replacing it.
        Written to `~/.pi/agent/APPEND_SYSTEM.md` when set.
      '';
    };
  };

  config = lib.mkIf cfg.enable (let
    jsonFormat = pkgs.formats.json {};

    # Build `home.file` entries from an attrset of name → source. Each
    # source is a directory; we symlink it at `<basePath>/<name>`.
    symlinkUnder = basePath:
      lib.mapAttrs' (name: src:
        lib.nameValuePair "${basePath}/${name}" {source = src;});
  in {
    home.packages =
      [cfg.package]
      ++ lib.optional cfg.installPi cfg.pi;

    home.file =
      (symlinkUnder ".pi/agent/extensions" cfg.extensions)
      // (symlinkUnder ".pi/agent/skills" cfg.skills)
      // (lib.optionalAttrs cfg.installExtension {
        ".pi/agent/extensions/tau".source = "${cfg.extension}/share/tau-extension";
      })
      // (lib.optionalAttrs (cfg.systemPrompt != null) {
        ".pi/agent/SYSTEM.md".text = cfg.systemPrompt;
      })
      // (lib.optionalAttrs (cfg.appendSystemPrompt != null) {
        ".pi/agent/APPEND_SYSTEM.md".text = cfg.appendSystemPrompt;
      })
      // (lib.optionalAttrs (cfg.settings != {}) {
        ".pi/agent/settings.json".source =
          jsonFormat.generate "pi-settings.json" cfg.settings;
      })
      # The systemd unit's `ReadWritePaths=%h/.config/tau` requires the
      # directory to exist before the service starts — systemd's mount
      # namespace setup binds the path in, and bind-mounting a missing dir
      # fails with `status=226/NAMESPACE`. An empty `.keep` is the minimal
      # way to make home-manager materialize the directory at activation.
      # The daemon writes `allow.json` (and optionally `audit.log`) inside.
      // (lib.optionalAttrs cfg.enableService {
        ".config/tau/.keep".text = "";
      });

    systemd.user.services.tau = lib.mkIf cfg.enableService (
      import ./systemd-unit.nix {tauPackage = cfg.package;}
    );
  });
}
