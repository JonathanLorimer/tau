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
    packages = forAllSystems ({pkgs, ...}: {
      pi = pkgs.callPackage ./nix/pi.nix {};
    });

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
          typescript

          bubblewrap
          netcat-openbsd
          curl
          jq
        ];
      };
    });
  };
}
