/**
 * AI Security Shell agent — Axism's MVP core.
 *
 * intent (natural language) → PLAN commands → GATE by risk → EXECUTE safe ones
 * in the sandbox → EXPLAIN the output. Streams each stage via a callback.
 *
 * Uses the "deep" role (route to an agentic model like Kimi K2) for planning,
 * and "fast" for the explanation.
 */

import { callLLM, hasAnyProvider, safeParseJson } from "./runtime.js";
import { classifyCommand, executeInSandbox, sandboxAvailable, type ExecResult, type Risk } from "./sandbox.js";

export interface PlannedCommand { cmd: string; purpose: string; risk: Risk; reason: string; }

export interface ShellOutcome {
  intent: string;
  summary: string;
  planned: PlannedCommand[];
  results: ExecResult[];
  explanation: string;
  needsApproval: PlannedCommand[];   // "review" commands awaiting human OK
  blocked: PlannedCommand[];         // "blocked" commands that will never run
  sandbox: "microvm" | "dry-run";
}

export type Emit = (event: { type: string; message?: string; stage?: string; data?: unknown }) => void;

interface RawPlan { summary?: string; commands?: Array<{ cmd?: string; purpose?: string }> }

const PLAN_SYSTEM =
  "You are Axism, an expert security operations assistant. Given the user's intent, produce a concise plan " +
  "of concrete Linux shell commands to accomplish it on a single host. Prefer read-only recon commands. " +
  "Never propose destructive actions (no rm -rf, mkfs, dd to devices, fork bombs, or piping remote content to a shell). " +
  'Respond ONLY with JSON: {"summary": string, "commands": [{"cmd": string, "purpose": string}]}. Keep it to 1–6 commands.';

/** Run the AI Security Shell pipeline for one intent. */
export async function runSecurityShell(intent: string, emit: Emit): Promise<ShellOutcome> {
  const sandbox: "microvm" | "dry-run" = sandboxAvailable() ? "microvm" : "dry-run";

  if (!hasAnyProvider()) {
    throw new Error("No LLM provider configured — set GROQ_API_KEY (or another provider) in .env");
  }

  // --- Stage 1: Plan ---
  emit({ type: "stage", stage: "plan", message: "Planning commands" });
  const raw = await callLLM(PLAN_SYSTEM, `Intent: ${intent}`, { role: "deep", temperature: 0.2, maxTokens: 800 });
  const parsed = (safeParseJson(raw) as RawPlan) ?? {};
  const summary = parsed.summary?.trim() || `Plan for: ${intent}`;
  const rawCommands = Array.isArray(parsed.commands) ? parsed.commands : [];

  // --- Stage 2: Gate (classify each command) ---
  emit({ type: "stage", stage: "gate", message: "Classifying command risk" });
  const planned: PlannedCommand[] = rawCommands
    .filter((c) => c && typeof c.cmd === "string" && c.cmd.trim())
    .slice(0, 6)
    .map((c) => {
      const cls = classifyCommand(c.cmd as string);
      return { cmd: cls.cmd, purpose: String(c.purpose ?? ""), risk: cls.risk, reason: cls.reason };
    });

  const needsApproval = planned.filter((p) => p.risk === "review");
  const blocked = planned.filter((p) => p.risk === "blocked");
  emit({ type: "plan", message: `${planned.length} command(s): ${planned.filter(p=>p.risk==="safe").length} safe, ${needsApproval.length} need approval, ${blocked.length} blocked`, data: planned });

  // --- Stage 3: Execute (safe only, sandboxed) ---
  emit({ type: "stage", stage: "execute", message: sandbox === "microvm" ? "Executing safe commands in microVM" : "Dry-run (no sandbox configured)" });
  const results = await executeInSandbox(
    planned.map((p) => ({ cmd: p.cmd, risk: p.risk, reason: p.reason })),
  );
  for (const r of results) {
    emit({ type: "exec", message: `${r.executed ? "▸" : "·"} ${r.cmd}${r.note ? ` — ${r.note}` : ""}`, data: r });
  }

  // --- Stage 4: Explain ---
  emit({ type: "stage", stage: "explain", message: "Interpreting results" });
  let explanation = "";
  const executed = results.filter((r) => r.executed);
  if (executed.length) {
    const evidence = executed
      .map((r) => `$ ${r.cmd}\n${(r.stdout || "(no output)").slice(0, 1500)}${r.stderr ? `\n[stderr] ${r.stderr.slice(0, 300)}` : ""}`)
      .join("\n\n");
    explanation = await callLLM(
      "You are Axism, a security analyst. Explain what the command output reveals about the host in plain language, " +
      "flag anything suspicious, and suggest the next step. Be concise.",
      `Intent: ${intent}\n\nCommand output:\n${evidence}`,
      { role: "fast", temperature: 0.3, maxTokens: 600, json: false },
    ).catch(() => "");
  }
  if (!explanation) {
    explanation = sandbox === "dry-run"
      ? "Dry-run mode: no sandbox configured, so commands were planned but not executed. Set E2B_API_KEY to run them in an isolated microVM."
      : "No safe commands were executed; review the flagged commands before approving them.";
  }

  const outcome: ShellOutcome = { intent, summary, planned, results, explanation, needsApproval, blocked, sandbox };
  emit({ type: "complete", message: "Done", data: outcome });
  return outcome;
}
