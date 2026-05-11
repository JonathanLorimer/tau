{
  description = "tau — personal coding harness: pi packaging, firewall daemon, bwrap jail, and NixOS/home-manager modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    crane,
    ...
  }: let
    forAllSystems = function:
      nixpkgs.lib.genAttrs ["x86_64-linux" "aarch64-linux"] (system:
        function rec {
          inherit system;
          pkgs = import nixpkgs {
            inherit system;
            overlays = [(import rust-overlay)];
          };
          rust = pkgs.rust-bin.stable.latest.default;
        });
  in {
    packages = forAllSystems ({
      pkgs,
      rust,
      ...
    }: let
      craneLib = (crane.mkLib pkgs).overrideToolchain rust;
      tau = import ./nix/tau.nix {
        inherit craneLib;
        inherit (pkgs) lib;
      };
    in {
      inherit tau;
      default = tau;
      pi = pkgs.callPackage ./nix/pi.nix {};
      tau-extension = pkgs.callPackage ./nix/extension.nix {};
    });

    homeManagerModules.default = {pkgs, ...}: {
      imports = [./nix/home-manager.nix];
      # Inject our flake's packages so the module can default the
      # tau/pi/tau-extension package options to them without each user's
      # config having to know the flake's output names.
      _module.args.tauPackages = self.packages.${pkgs.system};
    };

    # System-level prerequisites: bubblewrap, kernel knobs for the jail,
    # and (Phase 8) the nftables enforcement rule.
    nixosModules.default = ./nix/nixos.nix;

    devShells = forAllSystems ({
      pkgs,
      rust,
      ...
    }: {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rust
          rust-analyzer
          rustfmt

          nodejs_20
          typescript-go
          pnpm

          bubblewrap
          netcat-openbsd
          curl
          jq
        ];
      };
    });
  };
}
