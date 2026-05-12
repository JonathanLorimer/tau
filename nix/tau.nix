{
  craneLib,
  lib,
}: let
  # `cleanCargoSource` strips files that have no effect on a cargo build
  # (docs, the nix/ dir, the extension/, etc.) — keeps Cargo.{toml,lock},
  # src/, tests/, examples/, benches/ at any depth.
  src = craneLib.cleanCargoSource ../.;

  # Single source of truth for the version: `cli/Cargo.toml`. Without
  # this, crane only sees the workspace root `Cargo.toml` (which has no
  # `[package]` section) and falls back to a `0.0.1` default for the
  # derivation name.
  crateInfo = craneLib.crateNameFromCargoToml {
    cargoToml = ../cli/Cargo.toml;
  };

  commonArgs = {
    inherit src;
    inherit (crateInfo) version;
    strictDeps = true;
    # The tau crate has no native dependencies; tokio, clap, serde, etc.
    # are pure-Rust crates. So no nativeBuildInputs / buildInputs.
  };

  # Build the dep tree separately so changes to our own source don't
  # invalidate the cargo cache. This is the standard crane two-step:
  # depsRelease → buildPackage with cargoArtifacts.
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs
    // {
      pname = "tau-deps";
      cargoExtraArgs = "-p tau --locked";
    });
in
  craneLib.buildPackage (commonArgs
    // {
      inherit cargoArtifacts;
      pname = "tau";
      cargoExtraArgs = "-p tau --locked";

      meta = {
        description = "Personal coding harness: HTTPS firewall daemon, bwrap jail wrapper, and CLI for the pi coding agent";
        license = lib.licenses.mit;
        mainProgram = "tau";
      };
    })
