/**
 * Security hooks for opencode — scope enforcement + cost tracking.
 *
 * Replaces the Claude-Code-style "hooks" config key (not supported in opencode 1.18.x)
 * with the native plugin event system:
 *   - tool.execute.before  -> PreToolUse equivalent: blocks out-of-scope bash commands
 *   - event (session.idle) -> SubagentStop equivalent: logs cost per completed session
 *
 * Register in opencode.jsonc:
 *   "plugin": ["/home/bb/.config/opencode/plugin/security-hooks.js"]
 *
 * Scope data file (optional): ~/.config/vulnera-mcp/scope.yaml
 *   in_scope:
 *     - "*.example.com"
 *   out_of_scope:
 *     - "careers.example.com"
 */
import { readFileSync, mkdirSync, appendFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const HOME = homedir();
const SCOPE_FILE = join(HOME, ".config", "vulnera-mcp", "scope.yaml");
const COST_LOG = join(HOME, ".config", "vulnera-mcp", "cost-tracking.jsonl");

/** Minimal YAML-ish parser for scope.yaml — handles in_scope / out_of_scope lists. */
function parseScopeYaml(text) {
  const scope = { in_scope: [], out_of_scope: [] };
  let section = null;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (/^in_scope\s*:/.test(line)) { section = "in_scope"; continue; }
    if (/^out_of_scope\s*:/.test(line)) { section = "out_of_scope"; continue; }
    if (section && line.startsWith("-")) {
      const val = line.replace(/^-\s*/, "").replace(/["']/g, "").trim();
      if (val) scope[section].push(val);
    }
  }
  return scope;
}

/** Convert a (possibly wildcard) domain to a regex fragment matching it in a command string. */
function domainRegex(d) {
  const core = d.startsWith("*.") ? d.slice(2) : d;
  const escaped = core.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return `(?:^|[.\\s'"\\/])` + escaped;
}

export const SecurityHooks = async ({ project, client, $, directory, worktree }) => {
  return {
    /** PreToolUse equivalent — block out-of-scope Bash commands before execution. */
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash" && input.tool !== "Bash") return;

      const cmd = output.args?.command || "";
      if (!cmd) return;

      let scope = null;
      try {
        if (existsSync(SCOPE_FILE)) {
          scope = parseScopeYaml(readFileSync(SCOPE_FILE, "utf8"));
        }
      } catch { scope = null; }

      if (!scope) return; // fail-open if no scope file

      // Hard block: any out_of_scope domain in the command
      for (const oos of scope.out_of_scope || []) {
        if (!oos) continue;
        try {
          const re = new RegExp(domainRegex(oos), "i");
          if (re.test(cmd)) {
            throw new Error(`Out-of-scope target detected: ${oos} in command`);
          }
        } catch (e) { /* regex error — skip this pattern */ }
      }
    },

    /** SubagentStop equivalent — log cost when a session goes idle. */
    event: async ({ event }) => {
      try {
        if (event.type !== "session.idle") return;
        const sessionId = event.session_id || event.sessionID || "";
        const tokens = Number(event.total_tokens || event.tokens || 0);
        const costUsd = Math.round((tokens / 1000) * 0.045 * 10000) / 10000;
        const entry = {
          ts: new Date().toISOString(),
          session: sessionId,
          tokens,
          cost_usd: costUsd,
        };
        mkdirSync(join(HOME, ".config", "vulnera-mcp"), { recursive: true });
        appendFileSync(COST_LOG, JSON.stringify(entry) + "\n");
      } catch { /* non-fatal — logging must never break the session */ }
    },
  };
};
