{
  stdenv,
  fetchurl,
  lib,
  autoPatchelfHook,
}: let
  version = "0.74.0";

  # Upstream publishes bun-compiled standalone binaries as GitHub release
  # assets. No npm install / TypeScript build required — just a single binary
  # plus runtime assets (themes, photon wasm, HTML export templates) that the
  # binary expects to find as siblings.
  sources = {
    "x86_64-linux" = {
      url = "https://github.com/earendil-works/pi-mono/releases/download/v${version}/pi-linux-x64.tar.gz";
      hash = "sha256-1nZXow1JyfrKgIaNKkvbpN/KwEcCiT9FptFLJJNF640=";
    };
    "aarch64-linux" = {
      url = "https://github.com/earendil-works/pi-mono/releases/download/v${version}/pi-linux-arm64.tar.gz";
      hash = "sha256-JhqpEoeMqYPJA9nEoECDEN2GN7WDCFZR2bXdtwyd9XI=";
    };
    "x86_64-darwin" = {
      url = "https://github.com/earendil-works/pi-mono/releases/download/v${version}/pi-darwin-x64.tar.gz";
      hash = lib.fakeHash;
    };
    "aarch64-darwin" = {
      url = "https://github.com/earendil-works/pi-mono/releases/download/v${version}/pi-darwin-arm64.tar.gz";
      hash = lib.fakeHash;
    };
  };

  source =
    sources.${stdenv.hostPlatform.system}
    or (throw "pi: unsupported system ${stdenv.hostPlatform.system}");
in
  stdenv.mkDerivation {
    pname = "pi-coding-agent";
    inherit version;

    src = fetchurl source;

    # autoPatchelfHook rewrites the dynamic-linker path so the bun-compiled
    # binary loads on NixOS. Darwin binaries don't need this.
    nativeBuildInputs = lib.optional stdenv.isLinux autoPatchelfHook;

    dontConfigure = true;
    dontBuild = true;

    # Tarball extracts to ./pi/ (which becomes cwd after unpackPhase). The
    # binary expects its sibling files (theme/, photon_rs_bg.wasm, etc.) at
    # runtime, so we keep the layout intact under $out/share/pi/ and symlink
    # just the binary onto PATH.
    installPhase = ''
      runHook preInstall
      mkdir -p $out/share/pi $out/bin
      cp -r . $out/share/pi/
      chmod +x $out/share/pi/pi
      ln -s $out/share/pi/pi $out/bin/pi
      runHook postInstall
    '';

    meta = {
      description = "Pi coding agent CLI (bun-compiled standalone binary)";
      homepage = "https://pi.dev";
      license = lib.licenses.mit;
      mainProgram = "pi";
      platforms = lib.attrNames sources;
      sourceProvenance = [lib.sourceTypes.binaryNativeCode];
    };
  }
