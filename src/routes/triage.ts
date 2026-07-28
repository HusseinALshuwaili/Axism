import { Router, type IRouter } from "express";
import { randomUUID } from "node:crypto";
import { triageAlert, type Alert, type TriageResult } from "../lib/triage.js";
import { logger } from "../lib/logger.js";

const router: IRouter = Router();

const alerts = new Map<string, Alert>();
const results = new Map<string, TriageResult>();

// Seed sample alerts so there's data to try (scenario ideas borrowed from AiSOC).
(function seed() {
  const samples: Omit<Alert, "id" | "receivedAt">[] = [
    { title: "LockBit ransomware behavior detected", description: "Process rapidly encrypting files and dropping a ransom note; matches LockBit 3.0 TTPs.", source: "wazuh", severity: "critical", assetName: "FIN-SRV-02", indicators: ["185.220.101.5"] },
    { title: "Scheduled backup completed", description: "Nightly backup ran as authorized during the maintenance window.", source: "cron", severity: "low", assetName: "BACKUP-01", indicators: [] },
    { title: "Impossible travel sign-in", description: "User signed in from two countries within 5 minutes.", source: "okta", severity: "high", assetName: "user:jdoe", indicators: ["45.83.12.7"] },
    { title: "Chrome auto-update", description: "Approved Chrome update process launched.", source: "edr", severity: "low", assetName: "WS-114", indicators: [] },
    { title: "Mimikatz-like LSASS access", description: "Process read LSASS memory; possible credential dumping.", source: "defender", severity: "high", assetName: "HR-WS-08", indicators: [] },
  ];
  for (const s of samples) {
    const id = randomUUID();
    alerts.set(id, { ...s, id, receivedAt: new Date().toISOString() });
  }
})();

// POST /ingest/alert — accept real alerts (webhook-ready). Body: one alert or an array.
router.post("/ingest/alert", (req, res): void => {
  const items = Array.isArray(req.body) ? req.body : [req.body];
  const created: Alert[] = [];
  for (const it of items) {
    if (!it || typeof it.title !== "string") continue;
    const id = randomUUID();
    const alert: Alert = {
      id,
      title: it.title,
      description: String(it.description ?? ""),
      source: String(it.source ?? "unknown"),
      severity: ["low", "medium", "high", "critical"].includes(it.severity) ? it.severity : "medium",
      assetName: String(it.assetName ?? it.asset ?? "unknown"),
      indicators: Array.isArray(it.indicators) ? it.indicators.map(String) : [],
      receivedAt: new Date().toISOString(),
    };
    alerts.set(id, alert);
    created.push(alert);
  }
  if (!created.length) { res.status(400).json({ error: "No valid alerts — each needs at least a title." }); return; }
  logger.info("alerts ingested", { count: created.length });
  res.status(201).json({ ingested: created.length, alerts: created });
});

// GET /alerts — list alerts with their latest verdict
router.get("/alerts", (_req, res): void => {
  const list = [...alerts.values()].map((a) => ({ ...a, triage: results.get(a.id) ?? null }));
  res.json({ alerts: list });
});

// POST /triage/:id — run the triage agent on one alert
router.post("/triage/:id", async (req, res): Promise<void> => {
  const alert = alerts.get(req.params.id);
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  const result = await triageAlert(alert);
  results.set(alert.id, result);
  res.json(result);
});

export default router;
