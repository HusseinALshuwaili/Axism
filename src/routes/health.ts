import { Router, type IRouter } from "express";
import { hasAnyProvider } from "../lib/runtime.js";
import { sandboxAvailable } from "../lib/sandbox.js";

const router: IRouter = Router();

router.get("/healthz", (_req, res) => {
  res.json({
    status: "ok",
    service: "axism",
    llm: hasAnyProvider() ? "configured" : "none",
    sandbox: sandboxAvailable() ? "microvm" : "dry-run",
  });
});

export default router;
