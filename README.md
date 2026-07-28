# Axism

**AI-native security operations — the autonomous security brain.**
Red, blue, and grey, one AI.

Axism is a fresh, clean-architecture rebuild that combines everything learned
building Riley: a multi-provider LLM runtime, an enrichment/memory layer, MITRE
RAG, and agentic pipelines — now organized around a chat-driven **AI Security
Shell** that plans, executes (sandboxed), and explains security tasks.

## MVP — AI Security Shell + chat brain

You type intent in plain language ("find suspicious cron jobs", "what's listening
on this box", "check this IP"). Axism:

1. **Plans** — an LLM (routed to an agentic model like Kimi K2) proposes concrete
   shell commands, each with a purpose and a risk rating.
2. **Gates** — every command is classified `safe` (read-only) / `review`
   (mutating — needs your approval) / `blocked` (destructive — never run).
3. **Executes** — `safe` commands run inside an **isolated E2B microVM sandbox**,
   never on the host. No sandbox key → **dry-run** (plan only, nothing executes).
4. **Explains** — the model interprets the output in plain language.

Everything streams live over SSE.

### Safety model (built in, not bolted on)
- **Sandboxed by default.** Commands run in a throwaway microVM, isolated from
  the host and your infrastructure. (2026 consensus: never run agent commands in
  plain Docker or on the host.)
- **Risk gate.** Destructive commands (`rm -rf`, `mkfs`, fork bombs, pipe-to-shell,
  etc.) are hard-blocked. Mutating commands require explicit human approval.
- **Authorized scope only.** Real-host targeting (later) requires an explicit
  allowlist of assets you own or are contractually authorized to test.

## Architecture

```
src/
  server.ts              Express app + routes + CORS
  lib/
    runtime.ts           Multi-provider LLM (Groq/OpenRouter/DeepSeek/GLM/…) + role routing + fallback
    sandbox.ts           Command risk classifier + E2B microVM executor (dry-run fallback)
    security-shell.ts    The AI Security Shell agent: plan → gate → execute → explain
    logger.ts            Minimal structured logger
  routes/
    shell.ts             POST /shell/run  (start) + GET /shell/:id/stream (SSE)
    health.ts            GET /healthz
```

## Run

```bash
cp .env.example .env      # add at least one LLM key (GROQ_API_KEY is easiest)
npm install
npm run dev               # http://localhost:4000
```

Health: `GET /healthz`. Kick off a task: `POST /shell/run` with `{ "intent": "list listening ports" }`.

## Roadmap (from the build kit)

- **Now:** AI Security Shell (this MVP) + safety foundation.
- **Next:** blue-team agents (triage/detection/hunting, ported from Riley), purple
  loop (Atomic/Caldera attack → detect → gap report), red-team agent (graph + swarm),
  and an MCP server exposing it all.

See `../docs/riley-agent-build-kit.md` for the code-level references behind each.
