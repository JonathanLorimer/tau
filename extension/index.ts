/**
 * tau pi extension.
 *
 * Provides:
 *   - /firewall-list, /firewall-add, /firewall-remove — manage the allowlist
 *     from inside pi by talking to the daemon's mgmt socket.
 *   - web_fetch tool — fetches a URL through the tau-firewall proxy and,
 *     on a deny-marked 403, prompts the user (allow-once / allow-always /
 *     deny) and retries.
 *
 * Architecture note: this extension never bypasses the proxy. All HTTP
 * traffic goes through 127.0.0.1:8118, which means the firewall has a
 * single source of truth for what the agent's reaching.
 */

import { connect } from "node:net";
import { join } from "node:path";
import { Type } from "typebox";
import { fetch, ProxyAgent } from "undici";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const PROXY_URL = "http://127.0.0.1:8118";
const MARKER_HEADER = "x-pi-firewall-status"; // lowercased; fetch headers are case-insensitive
const DEFAULT_PORT = 443;
const MAX_RETRY_ATTEMPTS = 3;

// ---------------- mgmt socket client ----------------

interface Entry {
  host: string;
  port: number;
}

type MgmtCmd =
  | { cmd: "list" }
  | { cmd: "add_session"; host: string; port: number }
  | { cmd: "add_persist"; host: string; port: number }
  | { cmd: "remove"; host: string; port: number };

type MgmtReply =
  | { ok: true; entries: Entry[] }
  | { ok: boolean };

function socketPath(): string {
  // Mirrors paths::default_socket() in the daemon: $XDG_RUNTIME_DIR/tau.sock,
  // falling back to /tmp. Inside the jail, both the env var and the bind
  // are mirrored from the host so we land on the same path.
  const runtime = process.env.XDG_RUNTIME_DIR ?? "/tmp";
  return join(runtime, "tau.sock");
}

function sendMgmt(cmd: MgmtCmd): Promise<MgmtReply> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath());
    let buf = "";
    socket.setEncoding("utf-8");
    socket.on("data", (chunk) => {
      buf += chunk;
    });
    socket.on("end", () => {
      try {
        resolve(JSON.parse(buf.trim()) as MgmtReply);
      } catch (err) {
        reject(err);
      }
    });
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write(`${JSON.stringify(cmd)}\n`);
      socket.end();
    });
  });
}

// ---------------- helpers ----------------

/**
 * Parse `host` or `host:port` (or two whitespace-separated tokens).
 * Returns `null` on invalid input.
 */
function parseTarget(args: string): { host: string; port: number } | null {
  const trimmed = args.trim();
  if (!trimmed) return null;

  // First try whitespace-separated: "github.com 443"
  const ws = trimmed.split(/\s+/);
  if (ws.length === 2) {
    const port = Number.parseInt(ws[1], 10);
    if (!Number.isNaN(port) && ws[0]) return { host: ws[0], port };
    return null;
  }
  if (ws.length === 1) {
    const single = ws[0];
    // Then try host:port
    const colon = single.lastIndexOf(":");
    if (colon > 0 && colon < single.length - 1) {
      const port = Number.parseInt(single.slice(colon + 1), 10);
      if (!Number.isNaN(port)) {
        return { host: single.slice(0, colon), port };
      }
    }
    // Bare host — default port
    return { host: single, port: DEFAULT_PORT };
  }
  return null;
}

// ---------------- extension entry point ----------------

export default function (pi: ExtensionAPI) {
  // ---- slash commands ----

  pi.registerCommand("firewall-list", {
    description: "List entries in the tau-firewall allowlist",
    handler: async (_args, ctx) => {
      try {
        const reply = await sendMgmt({ cmd: "list" });
        if (!("entries" in reply) || !reply.ok) {
          ctx.ui.notify("Firewall daemon returned an unexpected reply", "error");
          return;
        }
        if (reply.entries.length === 0) {
          ctx.ui.notify("Allowlist is empty", "info");
          return;
        }
        const lines = reply.entries.map((e) => `  ${e.host}:${e.port}`).join("\n");
        ctx.ui.notify(`Allowlist (${reply.entries.length} entries):\n${lines}`, "info");
      } catch (err) {
        ctx.ui.notify(`Failed to contact tau daemon: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("firewall-add", {
    description: "Add HOST[:PORT] (or 'HOST PORT') to the tau allowlist; persistent by default",
    handler: async (args, ctx) => {
      const target = parseTarget(args);
      if (!target) {
        ctx.ui.notify("Usage: /firewall-add HOST[:PORT]   (default port 443)", "error");
        return;
      }
      try {
        const reply = await sendMgmt({ cmd: "add_persist", ...target });
        if (reply.ok) {
          ctx.ui.notify(`Added ${target.host}:${target.port} to the allowlist`, "info");
        } else {
          ctx.ui.notify("tau daemon returned ok=false", "error");
        }
      } catch (err) {
        ctx.ui.notify(`Failed to contact tau daemon: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("firewall-remove", {
    description: "Remove HOST[:PORT] (or 'HOST PORT') from the tau allowlist",
    handler: async (args, ctx) => {
      const target = parseTarget(args);
      if (!target) {
        ctx.ui.notify("Usage: /firewall-remove HOST[:PORT]   (default port 443)", "error");
        return;
      }
      try {
        const reply = await sendMgmt({ cmd: "remove", ...target });
        if (reply.ok) {
          ctx.ui.notify(`Removed ${target.host}:${target.port} from the allowlist`, "info");
        } else {
          ctx.ui.notify("tau daemon returned ok=false", "error");
        }
      } catch (err) {
        ctx.ui.notify(`Failed to contact tau daemon: ${(err as Error).message}`, "error");
      }
    },
  });

  // ---- web_fetch tool ----

  pi.registerTool({
    name: "web_fetch",
    label: "web_fetch",
    description:
      "Fetch a URL through the tau firewall. HTTPS only. On the first attempt to reach " +
      "a host outside the allowlist, the user will be prompted to allow or deny.",
    parameters: Type.Object({
      url: Type.String({ description: "URL to fetch; must be https://" }),
      method: Type.Optional(
        Type.String({ description: "HTTP method (GET, HEAD, POST, ...). Default GET." }),
      ),
    }),

    async execute(_id, params, signal, _onUpdate, ctx) {
      const method = (params.method ?? "GET").toUpperCase();

      // Parse the destination up front so we can prompt with a real host.
      let host: string;
      let port: number;
      try {
        const u = new URL(params.url);
        host = u.hostname;
        port = u.port ? Number.parseInt(u.port, 10) : DEFAULT_PORT;
      } catch {
        return {
          content: [{ type: "text", text: `Invalid URL: ${params.url}` }],
          details: { error: true },
        };
      }

      for (let attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        let response: Awaited<ReturnType<typeof fetch>>;
        try {
          response = await fetch(params.url, {
            method,
            dispatcher: new ProxyAgent(PROXY_URL),
            signal,
          });
        } catch (err) {
          return {
            content: [{ type: "text", text: `Network error: ${(err as Error).message}` }],
            details: { error: true },
          };
        }

        // Inspect the marker on a 403; only marker-tagged responses are ours.
        const marker = response.status === 403 ? response.headers.get(MARKER_HEADER) : null;

        if (!marker) {
          // Either success, or some other-status response from upstream — pass through.
          const body = await response.text();
          const truncated = body.length > 50_000 ? `${body.slice(0, 50_000)}\n\n[truncated at 50KB]` : body;
          return {
            content: [{ type: "text", text: truncated }],
            details: {
              status: response.status,
              contentType: response.headers.get("content-type") ?? null,
              bytes: body.length,
            },
          };
        }

        if (marker === "denied-non-https") {
          return {
            content: [
              {
                type: "text",
                text: `tau-firewall blocks plain HTTP. ${host}:${port} can't be reached this way; use https:// (port 443) instead. This is policy and cannot be allowlisted.`,
              },
            ],
            details: { blocked: "non-https", host, port },
          };
        }

        if (marker === "denied-malformed-request") {
          return {
            content: [
              { type: "text", text: `tau-firewall rejected the request as malformed (CONNECT line couldn't be parsed). This is almost always a bug.` },
            ],
            details: { blocked: "malformed" },
          };
        }

        if (marker === "denied-unknown-host") {
          if (!ctx.hasUI) {
            return {
              content: [
                {
                  type: "text",
                  text: `${host}:${port} is not in the tau allowlist, and there's no UI available to prompt for approval. Add it from a separate terminal via 'tau ctl add ${host} ${port}' and retry.`,
                },
              ],
              details: { blocked: "unknown-host-no-ui", host, port },
            };
          }

          const choice = await ctx.ui.select(`Allow ${host}:${port}?`, [
            "Allow once (session)",
            "Allow always (persist)",
            "Deny",
          ]);

          if (choice === "Allow once (session)") {
            try {
              await sendMgmt({ cmd: "add_session", host, port });
            } catch (err) {
              return {
                content: [{ type: "text", text: `Failed to update allowlist: ${(err as Error).message}` }],
                details: { error: true },
              };
            }
            continue; // retry the request
          }
          if (choice === "Allow always (persist)") {
            try {
              await sendMgmt({ cmd: "add_persist", host, port });
            } catch (err) {
              return {
                content: [{ type: "text", text: `Failed to update allowlist: ${(err as Error).message}` }],
                details: { error: true },
              };
            }
            continue; // retry the request
          }
          // "Deny" or selector dismissed
          return {
            content: [{ type: "text", text: `User denied access to ${host}:${port}` }],
            details: { blocked: "user-denied", host, port },
          };
        }

        // Unknown marker — shouldn't happen, but fail closed.
        return {
          content: [
            { type: "text", text: `tau-firewall returned an unrecognized marker: ${marker}` },
          ],
          details: { blocked: "unknown-marker", marker },
        };
      }

      return {
        content: [{ type: "text", text: `Gave up after ${MAX_RETRY_ATTEMPTS} attempts` }],
        details: { error: true },
      };
    },
  });
}
