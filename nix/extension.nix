{
  runCommand,
  lib,
}:
# Pi loads index.ts via jiti at runtime; imports (typebox, undici,
# @earendil-works/pi-coding-agent) resolve against pi's own node_modules,
# so we don't ship any dependencies. tsconfig.json and the lockfile are
# dev-only and stay outside the runtime closure.
runCommand "tau-extension-0.1.0" {
  meta = {
    description = "tau-firewall pi extension: marker-aware web_fetch + allowlist slash commands";
    license = lib.licenses.mit;
  };
} ''
  mkdir -p $out/share/tau-extension
  cp ${../extension/index.ts} $out/share/tau-extension/index.ts
  cp ${../extension/package.json} $out/share/tau-extension/package.json
''
