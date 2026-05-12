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
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

const PROXY_URL = "http://127.0.0.1:8118";
const MARKER_HEADER = "x-pi-firewall-status"; // lowercased; fetch headers are case-insensitive
const DEFAULT_PORT = 443;
const MAX_RETRY_ATTEMPTS = 3;
const EVENTS_RECONNECT_DELAY_MS = 2_000;
const FETCH_TIMEOUT_MS = 10_000;
const MGMT_TIMEOUT_MS = 5_000;

// ---------------- mgmt socket client ----------------

interface Entry {
  host: string;
}

type MgmtCmd =
  | { cmd: "list" }
  | { cmd: "add_session"; host: string }
  | { cmd: "add_persist"; host: string }
  | { cmd: "remove"; host: string }
  | { cmd: "subscribe_events" };

type MgmtReply =
  | { ok: true; entries: Entry[] }
  | { ok: boolean };

// Out-of-band events emitted by the daemon's honeypot. Versioned contract
// with `cli/src/honeypot.rs::Event` — adding a `kind` requires updating
// both sides in lockstep (see PLAN.md "Deny marker taxonomy").
type DaemonEvent = {
  kind: "escape-attempt";
  ts: string;
  host: string;
  port: number;
  count: number;
};

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
    socket.setTimeout(MGMT_TIMEOUT_MS);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("mgmt socket timed out"));
    });
    socket.on("data", (chunk) => {
      buf += chunk;
    });
    socket.on("end", () => {
      const trimmed = buf.trim();
      if (!trimmed) {
        // Empty reply means the daemon closed the socket before writing.
        // The mutation may have already succeeded on the daemon side
        // (it persists allow.json before constructing the reply), so the
        // resulting state is ambiguous. Surface that explicitly instead
        // of dressing it up as a JSON parse error.
        reject(
          new Error(
            "daemon closed connection without replying; the operation may have succeeded — verify with /firewall-list",
          ),
        );
        return;
      }
      try {
        resolve(JSON.parse(trimmed) as MgmtReply);
      } catch (err) {
        reject(new Error(`daemon returned unparseable reply: ${(err as Error).message}`));
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
 * Normalize a slash-command argument to a bare hostname. Strips an optional
 * `:port` suffix (a leftover from older usage), trims whitespace, and
 * returns `null` on empty input. The proxy is HTTPS-only so port is
 * meaningless in the allowlist.
 */
function parseHost(args: string): string | null {
  const trimmed = args.trim().split(/\s+/)[0]?.trim();
  if (!trimmed) return null;
  const colon = trimmed.lastIndexOf(":");
  return colon > 0 ? trimmed.slice(0, colon) : trimmed;
}

// ---------------- escape-attempt event subscriber ----------------

/**
 * Long-running subscriber to the daemon's events stream. Opens a fresh mgmt
 * socket connection, sends `subscribe_events`, then renders each
 * `escape-attempt` event as a red-alert notification via the most recently
 * seen session context. Reconnects on disconnect.
 *
 * Runs for the life of the extension. We don't await this from the factory;
 * the promise is fired-and-forgotten with a top-level catch.
 */
async function runEventSubscriber(getCtx: () => ExtensionContext | null): Promise<void> {
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      await subscribeOnce(getCtx);
    } catch (err) {
      // Daemon down, socket missing, parse error — fall through to reconnect.
      console.error(`tau: events subscriber error: ${(err as Error).message}`);
    }
    await new Promise((r) => setTimeout(r, EVENTS_RECONNECT_DELAY_MS));
  }
}

function subscribeOnce(getCtx: () => ExtensionContext | null): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath());
    socket.setEncoding("utf-8");

    let buf = "";
    let sawAck = false;

    socket.on("data", (chunk) => {
      buf += chunk;
      let newline: number;
      while ((newline = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, newline).trim();
        buf = buf.slice(newline + 1);
        if (!line) continue;

        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          // Bad line — drop and continue.
          continue;
        }

        if (!sawAck) {
          const ack = parsed as MgmtReply;
          if (!ack.ok) {
            socket.destroy();
            reject(new Error("daemon refused subscribe_events"));
            return;
          }
          sawAck = true;
          continue;
        }

        renderEvent(parsed as DaemonEvent, getCtx());
      }
    });

    socket.on("error", reject);
    socket.on("end", () => resolve());
    socket.on("close", () => resolve());
    socket.on("connect", () => {
      const cmd: MgmtCmd = { cmd: "subscribe_events" };
      socket.write(`${JSON.stringify(cmd)}\n`);
    });
  });
}

function renderEvent(event: DaemonEvent, ctx: ExtensionContext | null): void {
  if (event.kind !== "escape-attempt") return;

  const countSuffix = event.count > 1 ? ` (×${event.count})` : "";
  const message =
    `tau-firewall: bypass attempt blocked${countSuffix}. A process in the jail tried to connect ` +
    `directly to ${event.host}:${event.port}, ignoring HTTPS_PROXY. The kernel redirected it to ` +
    `the honeypot. If you didn't expect any tool to reach this destination, treat it as suspicious.`;

  if (ctx && ctx.hasUI) {
    ctx.ui.notify(message, "error");
  } else {
    // No active session UI — log so it shows up somewhere.
    console.error(`tau: ${message}`);
  }
}

// ---------------- extension entry point ----------------

export default function (pi: ExtensionAPI) {
  // The active session's context, refreshed on every session_start. The
  // events subscriber pulls this via a closure so notifications go to the
  // session that's currently in the foreground.
  let currentCtx: ExtensionContext | null = null;
  pi.on("session_start", (_event, ctx) => {
    currentCtx = ctx;
  });

  runEventSubscriber(() => currentCtx).catch((err) => {
    console.error(`tau: events subscriber crashed: ${(err as Error).message}`);
  });

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
        const lines = reply.entries.map((e) => `  ${e.host}`).join("\n");
        ctx.ui.notify(`Allowlist (${reply.entries.length} entries):\n${lines}`, "info");
      } catch (err) {
        ctx.ui.notify(`Failed to contact tau daemon: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("firewall-add", {
    description: "Add HOST to the tau allowlist; persistent by default",
    handler: async (args, ctx) => {
      const host = parseHost(args);
      if (!host) {
        ctx.ui.notify("Usage: /firewall-add HOST", "error");
        return;
      }
      try {
        const reply = await sendMgmt({ cmd: "add_persist", host });
        if (reply.ok) {
          ctx.ui.notify(`Added ${host} to the allowlist`, "info");
        } else {
          ctx.ui.notify("tau daemon returned ok=false", "error");
        }
      } catch (err) {
        ctx.ui.notify(`Failed to contact tau daemon: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("firewall-remove", {
    description: "Remove HOST from the tau allowlist",
    handler: async (args, ctx) => {
      const host = parseHost(args);
      if (!host) {
        ctx.ui.notify("Usage: /firewall-remove HOST", "error");
        return;
      }
      try {
        const reply = await sendMgmt({ cmd: "remove", host });
        if (reply.ok) {
          ctx.ui.notify(`Removed ${host} from the allowlist`, "info");
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
          // Combine the caller's abort signal with a hard timeout so a
          // slow/hung proxy or upstream doesn't stall the agent forever.
          const timeoutSignal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
          const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
          response = await fetch(params.url, {
            method,
            dispatcher: new ProxyAgent(PROXY_URL),
            signal: combinedSignal,
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
                  text: `${host} is not in the tau allowlist, and there's no UI available to prompt for approval. Add it from a separate terminal via 'tau ctl add ${host}' and retry.`,
                },
              ],
              details: { blocked: "unknown-host-no-ui", host },
            };
          }

          const choice = await ctx.ui.select(`Allow ${host}?`, [
            "Allow once (session)",
            "Allow always (persist)",
            "Deny",
          ]);

          if (choice === "Allow once (session)" || choice === "Allow always (persist)") {
            const cmd = choice === "Allow once (session)" ? "add_session" : "add_persist";
            ctx.ui.setWorkingMessage(`Adding ${host} to allowlist…`);
            let added = false;
            try {
              await sendMgmt({ cmd, host });
              ctx.ui.setWorkingMessage();
              added = true;
            } catch (err) {
              ctx.ui.setWorkingMessage();
              const msg = (err as Error).message;
              // The daemon may have persisted the entry before closing the
              // connection — treat as likely success and still offer retry.
              if (msg.includes("daemon closed connection without replying")) {
                added = true;
              } else {
                return {
                  content: [{ type: "text", text: `Failed to update allowlist: ${msg}` }],
                  details: { error: true },
                };
              }
            }
            if (added) {
              const retry = await ctx.ui.confirm(`Added ${host} to allowlist`, "Retry the fetch now?");
              if (retry) continue;
              return {
                content: [{ type: "text", text: `${host} added to allowlist; fetch skipped.` }],
                details: { host },
              };
            }
          }
          // "Deny" or selector dismissed
          return {
            content: [{ type: "text", text: `User denied access to ${host}` }],
            details: { blocked: "user-denied", host },
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
