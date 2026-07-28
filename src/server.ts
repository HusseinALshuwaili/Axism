import "dotenv/config";
import express, { type Express } from "express";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";
import healthRouter from "./routes/health.js";
import shellRouter from "./routes/shell.js";
import triageRouter from "./routes/triage.js";
import { logger } from "./lib/logger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app: Express = express();

// Trust a single reverse-proxy hop (Render/Fly/Railway) for correct client IPs.
app.set("trust proxy", 1);

const allowedOrigins = (process.env.CORS_ORIGIN ?? "http://localhost:5173")
  .split(",").map((s) => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    if (/^https?:\/\/localhost(:\d+)?$/.test(origin)) return cb(null, true);   // ← NEW: allow local dev
    logger.warn("cors rejected", { origin });
    cb(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));

app.use(express.json({ limit: "256kb" }));

// Serve the chat UI (public/index.html) at "/"
app.use(express.static(path.join(__dirname, "..", "public")));

app.use(healthRouter);
app.use(shellRouter);
app.use(triageRouter);

const port = Number(process.env.PORT ?? 4000);
app.listen(port, () => logger.info("Axism listening", { port, url: `http://localhost:${port}` }));

export default app;
