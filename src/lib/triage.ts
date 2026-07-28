import { callLLM, hasAnyProvider, safeParseJson } from "./runtime.js";
import { extractIndicators, enrichMany, formatEnrichmentContext } from "./enrichment.js";

export interface Alert {
  id: string;
  title: string;
  description: string;
  source: string;
  severity: "low" | "medium" | "high" | "critical";
  assetName: string;
  indicators?: string[];
  receivedAt: string;
}

export type Verdict = "true_positive" | "false_positive" | "needs_review";

export interface TriageResult {
  alertId: string;
  verdict: Verdict;
  confidence: number;
  severityScore: number;
  priority: number;
  rationale: string;
  recommendation: string;
  mode: "model" | "deterministic";
  intel?: string;   // live threat-intel on the alert's indicators
}

const SEV_BASE: Record<string, number> = { critical: 90, high: 70, medium: 45, low: 20 };
const BENIGN = ["scheduled", "authorized", "approved", "update", "backup", "test", "maintenance"];
const MALICIOUS = ["ransomware","lockbit","mimikatz","c2","beacon","exfil","reverse shell",
  "privilege escalation","credential dump","lateral movement","brute force","malware","exploit"];

function deterministic(alert: Alert): TriageResult {
  const text = `${alert.title} ${alert.description}`.toLowerCase();
  let score = SEV_BASE[alert.severity] ?? 40;
  const benign = BENIGN.some((w) => text.includes(w));
  const malicious = MALICIOUS.some((w) => text.includes(w));
  const hasIocs = (alert.indicators?.length ?? 0) > 0;

  if (malicious) score += 15;
  if (benign) score -= 30;
  if (hasIocs) score += 5;
  score = Math.round(Math.max(0, Math.min(100, score)));

  let verdict: Verdict;
  if (malicious && !benign && score >= 60) verdict = "true_positive";
  else if (benign && !malicious && score < 40) verdict = "false_positive";
  else verdict = "needs_review";

  const priority = score >= 80 ? 1 : score >= 60 ? 2 : score >= 40 ? 3 : score >= 20 ? 4 : 5;
  return {
    alertId: alert.id, verdict, confidence: 0.5, severityScore: score, priority, mode: "deterministic",
    rationale: `Rule score ${score}/100 — ${malicious ? "threat keywords; " : ""}${benign ? "benign pattern; " : ""}${hasIocs ? "has indicators." : "no indicators."}`,
    recommendation: verdict === "true_positive" ? "Escalate and contain the asset."
      : verdict === "false_positive" ? "Close as false positive." : "Assign to an analyst for review.",
  };
}

const SYSTEM = `You are Axism, a SOC triage analyst. Classify the alert as exactly one of: ` +
  `true_positive, false_positive, needs_review. Respond ONLY with JSON: ` +
  `{"verdict":"...","confidence":0..1,"severityScore":0..100,"priority":1..5,"rationale":string,"recommendation":string}.`;
const VALID = ["true_positive", "false_positive", "needs_review"];

export async function triageAlert(alert: Alert): Promise<TriageResult> {
  const base = deterministic(alert);

  // Live threat-intel on the alert's indicators (IPs, hashes, CVEs).
  const indicators = extractIndicators(`${alert.title} ${alert.description} ${(alert.indicators ?? []).join(" ")}`);
  const enrichments = indicators.length ? await enrichMany(indicators) : [];
  const intel = enrichments.length ? enrichments.map((e) => `${e.indicator} → ${e.verdict}`).join("; ") : undefined;
  const intelCtx = formatEnrichmentContext(enrichments);
  base.intel = intel;

  if (!hasAnyProvider()) return base;
  try {
    const raw = await callLLM(SYSTEM,
      `Alert:\n- Title: ${alert.title}\n- Description: ${alert.description}\n` +
      `- Source: ${alert.source}\n- Severity: ${alert.severity}\n- Asset: ${alert.assetName}\n` +
      `- Indicators: ${(alert.indicators ?? []).join(", ") || "none"}\n\n` +
      `Rule pre-score: ${base.severityScore}/100 (${base.verdict}).${intelCtx}`,
      { role: "fast", temperature: 0.2 });
    const o = safeParseJson(raw) as Record<string, unknown> | null;
    if (o && typeof o.verdict === "string" && VALID.includes(o.verdict)) {
      let verdict = o.verdict as Verdict;
      let rationale = String(o.rationale ?? base.rationale);
      let recommendation = String(o.recommendation ?? base.recommendation);
      const conf = Number(o.confidence), sev = Number(o.severityScore), pri = Number(o.priority);
      let severityScore = Number.isFinite(sev) ? Math.round(Math.max(0, Math.min(100, sev))) : base.severityScore;
      let priority = pri >= 1 && pri <= 5 ? pri : base.priority;
      let confidence = conf >= 0 && conf <= 1 ? conf : 0.6;

      // Guardrail: never let the model ESCALATE a clearly-benign alert.
      // If the rules confidently say false_positive (benign keywords, no malicious
      // signal, low score) but the model says true_positive, trust the rules.
      if (base.verdict === "false_positive" && verdict === "true_positive") {
        verdict = "false_positive";
        rationale = `Rules identify this as a benign, authorized event, so the model's escalation was overridden. (Model note: ${rationale})`;
        recommendation = "Close as false positive.";
        severityScore = base.severityScore;
        priority = base.priority;
        confidence = 0.6;
      }

      return { alertId: alert.id, verdict, confidence, severityScore, priority, rationale, recommendation, mode: "model", intel };
    }
  } catch { /* fall back to deterministic */ }
  return base;
}
