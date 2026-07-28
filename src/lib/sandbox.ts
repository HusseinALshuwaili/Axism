/**
 * Sandbox executor + command risk gate.
 *
 * Commands NEVER run on the host. They run in an isolated E2B microVM
 * (Firecracker) when E2B_API_KEY is set; otherwise the executor is in DRY-RUN
 * mode and returns the plan without executing anything.
 *
 * The risk gate classifies every command before it can run:
 *   - "safe"    read-only recon → may auto-run
 *   - "review"  mutating/state-changing → requires explicit human approval
 *   - "blocked" destructive / exfiltration / pipe-to-shell → never run
 */

import { logger } from "./logger.js";

export type Risk = "safe" | "review" | "blocked";

export interface ClassifiedCommand {
  cmd: string;
  risk: Risk;
  reason: string;
}

export interface ExecResult {
  cmd: string;
  risk: Risk;
  executed: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  note?: string;
}

// --- Hard-blocked patterns: destructive, exfiltration, or shell-injection ---
const BLOCKED: Array<{ re: RegExp; reason: string }> = [
  { re: /\brm\s+-\w*[rf]/i, reason: "recursive/forced delete" },
  { re: /\bmkfs\b|\bfdisk\b|\bparted\b/i, reason: "filesystem/partition modification" },
  { re: /\bdd\b[^|]*\bof=\/dev\//i, reason: "raw write to a device" },
  { re: /:\s*\(\)\s*\{.*\}\s*;/, reason: "fork bomb" },
  { re: /\b(shutdown|reboot|halt|poweroff|init\s+0)\b/i, reason: "host power control" },
  { re: />\s*\/dev\/(sd|nvme|disk)/i, reason: "overwrite a block device" },
  { re: /\bchmod\s+-\w*R\s+0*777\s+\//i, reason: "world-writable on root" },
  { re: /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i, reason: "pipe remote content to a shell" },
  { re: /\b(nc|ncat|netcat)\b[^\n]*-e\b/i, reason: "reverse/bind shell" },
  { re: /\/etc\/(shadow|sudoers)\b[^\n]*(>|>>|tee)/i, reason: "writing to auth files" },
];

// --- Read-only recon allowlist (may auto-run). Base command must match. ---
const READONLY = new Set([
  "ls", "cat", "head", "tail", "less", "more", "grep", "egrep", "rg", "find", "stat",
  "ps", "top", "htop", "pgrep", "netstat", "ss", "lsof", "who", "w", "id", "whoami",
  "uname", "hostname", "uptime", "df", "du", "free", "env", "printenv", "date",
  "ip", "ifconfig", "route", "arp", "dig", "nslookup", "host", "ping", "traceroute",
  "which", "whereis", "file", "sha256sum", "md5sum", "wc", "sort", "uniq", "awk",
  "sed", "cut", "echo", "history", "crontab", "systemctl", "journalctl", "dpkg", "rpm",
]);

// systemctl/crontab/journalctl/dpkg are only read-only for status/list subcommands.
const READONLY_SUBCMD_ONLY: Record<string, RegExp> = {
  systemctl: /^systemctl\s+(status|list-units|list-unit-files|is-active|is-enabled|show)\b/i,
  crontab:   /^crontab\s+-l\b/i,
  journalctl:/^journalctl\b(?!.*\b(--rotate|--vacuum)\b)/i,
  dpkg:      /^dpkg\s+(-l|--list|-s|--status)\b/i,
  sed:       /^sed\s+(?!.*\b-i\b)/i, // sed without -i (no in-place edit) is read-only
};

function baseCommand(cmd: string): string {
  const trimmed = cmd.trim().replace(/^sudo\s+/, "");
  return (trimmed.split(/\s+/)[0] || "").toLowerCase();
}

/** Classify a single command's risk. Default is "review" (needs approval). */
export function classifyCommand(cmd: string): ClassifiedCommand {
  const c = cmd.trim();

  for (const { re, reason } of BLOCKED) {
    if (re.test(c)) return { cmd: c, risk: "blocked", reason };
  }

  // A pipe/redirect/chained command is only as safe as its most dangerous part —
  // conservatively route anything with obvious mutation operators to review.
  if (/\b(rm|mv|cp|chmod|chown|kill|pkill|apt|apt-get|yum|dnf|pip|npm|git|useradd|passwd|iptables|ufw|mount|umount|truncate)\b/i.test(c)) {
    return { cmd: c, risk: "review", reason: "mutating/state-changing command" };
  }
  if (/(^|[^>])>\s*\/(?!dev\/null)/.test(c) || />>/.test(c)) {
    return { cmd: c, risk: "review", reason: "writes to a file" };
  }

  const base = baseCommand(c);
  const subRe = READONLY_SUBCMD_ONLY[base];
  if (subRe) {
    return subRe.test(c)
      ? { cmd: c, risk: "safe", reason: "read-only subcommand" }
      : { cmd: c, risk: "review", reason: `${base} in a non-read-only mode` };
  }
  if (READONLY.has(base)) {
    return { cmd: c, risk: "safe", reason: "read-only recon" };
  }

  return { cmd: c, risk: "review", reason: "unrecognized — requires review" };
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

export function sandboxAvailable(): boolean {
  return !!process.env.E2B_API_KEY;
}

interface RawOut { stdout: string; stderr: string; exitCode: number | null; }

/**
 * Actually run a list of raw commands in an isolated E2B microVM. The caller is
 * responsible for deciding which commands are allowed to run. Returns a map of
 * cmd → output. Empty map means nothing ran (no key or e2b not installed);
 * the caller then labels those results as dry-run.
 */
async function runRaw(cmds: string[]): Promise<Map<string, RawOut>> {
  const results = new Map<string, RawOut>();
  if (!sandboxAvailable() || cmds.length === 0) return results;

  // Dynamic import via non-literal specifier so the build doesn't require the
  // e2b package until you actually enable sandboxing.
  const specifier = "e2b";
  let Sandbox: unknown;
  try {
    const mod: Record<string, unknown> = await import(specifier);
    Sandbox = mod.Sandbox;
  } catch (err) {
    logger.warn("e2b package not installed — falling back to dry-run", { err: String(err) });
    return results;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sbx: any = await (Sandbox as any).create({ apiKey: process.env.E2B_API_KEY });
  try {
    for (const cmd of cmds) {
      const out = await sbx.commands.run(cmd, { timeoutMs: 20000 }).catch((e: unknown) => ({ stdout: "", stderr: String(e), exitCode: 1 }));
      results.set(cmd, {
        stdout: String(out.stdout ?? "").slice(0, 8000),
        stderr: String(out.stderr ?? "").slice(0, 2000),
        exitCode: typeof out.exitCode === "number" ? out.exitCode : 0,
      });
    }
  } finally {
    await sbx.kill?.().catch(() => {});
  }
  logger.info("sandbox run complete", { count: cmds.length });
  return results;
}

function dryRunNote(): string {
  return sandboxAvailable()
    ? "dry-run: e2b package not installed (`npm i e2b`)"
    : "dry-run: no E2B_API_KEY configured";
}

/**
 * Execute a classified plan: only "safe" commands run; "review"/"blocked" are
 * returned unexecuted. With no sandbox, safe commands are reported as dry-run.
 */
export async function executeInSandbox(commands: ClassifiedCommand[]): Promise<ExecResult[]> {
  const ran = await runRaw(commands.filter((c) => c.risk === "safe").map((c) => c.cmd));
  return commands.map((c) => {
    if (c.risk !== "safe") {
      return { cmd: c.cmd, risk: c.risk, executed: false, stdout: "", stderr: "", exitCode: null, note: `not executed (${c.risk}): ${c.reason}` };
    }
    const r = ran.get(c.cmd);
    return r
      ? { cmd: c.cmd, risk: "safe", executed: true, ...r }
      : { cmd: c.cmd, risk: "safe", executed: false, stdout: "", stderr: "", exitCode: null, note: dryRunNote() };
  });
}

/**
 * Execute human-approved commands. "blocked" (destructive) commands are refused
 * even when explicitly approved; safe + review commands run in the sandbox.
 */
export async function executeApproved(cmds: string[]): Promise<ExecResult[]> {
  const classified = cmds.map(classifyCommand);
  const ran = await runRaw(classified.filter((c) => c.risk !== "blocked").map((c) => c.cmd));
  return classified.map((c) => {
    if (c.risk === "blocked") {
      return { cmd: c.cmd, risk: "blocked", executed: false, stdout: "", stderr: "", exitCode: null, note: `blocked: ${c.reason} — refused even with approval` };
    }
    const r = ran.get(c.cmd);
    return r
      ? { cmd: c.cmd, risk: c.risk, executed: true, ...r }
      : { cmd: c.cmd, risk: c.risk, executed: false, stdout: "", stderr: "", exitCode: null, note: dryRunNote() };
  });
}
