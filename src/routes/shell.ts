import { Router, type IRouter } from "express";
import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { runSecurityShell, type ShellOutcome } from "../lib/security-shell.js";
import { executeApproved } from "../lib/sandbox.js";
import { logger } from "../lib/logger.js";

const router: IRouter = Router();

interface Run { emitter: EventEmitter; done: boolean; outcome?: ShellOutcome; error?: string; }
const runs = new Map<string, Run>();

// POST /shell/run  — start an AI Security Shell task
router.post("/shell/run", (req, res): void => {
  const intent = typeof req.body?.intent === "string" ? req.body.intent.trim() : "";
  if (!intent) {
    res.status(400).json({ error: "Provide an 'intent' string" });
    return;
  }

  const runId = randomUUID();
  const emitter = new EventEmitter();
  emitter.setMaxListeners(20);
  const run: Run = { emitter, done: false };
  runs.set(runId, run);

  runSecurityShell(intent, (event) => emitter.emit("event", event))
    .then((outcome) => { run.done = true; run.outcome = outcome; })
    .catch((err) => {
      run.done = true;
      run.error = err instanceof Error ? err.message : String(err);
      emitter.emit("event", { type: "error", message: run.error });
      logger.error("shell run failed", { runId, err: run.error });
    })
    .finally(() => setTimeout(() => runs.delete(runId), 5 * 60 * 1000));

  res.json({ runId, intent });
});

// GET /shell/:id/stream  — SSE live pipeline
router.get("/shell/:id/stream", (req, res): void => {
  const run = runs.get(req.params.id);
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
  const send = (e: unknown) => res.write(`data: ${JSON.stringify(e)}\n\n`);

  if (!run) {
    send({ type: "error", message: "Run not found or expired" });
    res.end();
    return;
  }
  if (run.done) {
    send(run.error ? { type: "error", message: run.error } : { type: "complete", message: "Done", data: run.outcome });
    res.end();
    return;
  }

  const onEvent = (event: { type?: string }) => {
    send(event);
    if (event.type === "complete" || event.type === "error") {
      res.end();
      run.emitter.off("event", onEvent);
    }
  };
  run.emitter.on("event", onEvent);
  req.on("close", () => run.emitter.off("event", onEvent));
});

// POST /shell/:id/approve  — run human-approved "review" commands from a run
router.post("/shell/:id/approve", async (req, res): Promise<void> => {
  const run = runs.get(req.params.id);
  if (!run || !run.outcome) { res.status(404).json({ error: "Run not found or expired" }); return; }

  const requested: string[] = Array.isArray(req.body?.commands)
    ? req.body.commands.filter((c: unknown): c is string => typeof c === "string")
    : [];
  if (!requested.length) { res.status(400).json({ error: "Provide commands[]" }); return; }

  // Only commands this run actually flagged for approval may be run.
  const approvable = new Set(run.outcome.needsApproval.map((p) => p.cmd));
  const cmds = requested.filter((c) => approvable.has(c));
  if (!cmds.length) { res.status(400).json({ error: "None of those commands are approvable for this run" }); return; }

  try {
    const results = await executeApproved(cmds);
    logger.info("approved commands executed", { runId: req.params.id, count: cmds.length });
    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// GET /shell/:id  — fetch a finished run's outcome
router.get("/shell/:id", (req, res): void => {
  const run = runs.get(req.params.id);
  if (!run) { res.status(404).json({ error: "Run not found or expired" }); return; }
  res.json({ done: run.done, outcome: run.outcome ?? null, error: run.error ?? null });
});

export default router;
