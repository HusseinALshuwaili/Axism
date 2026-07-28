/**
 * Multi-provider LLM runtime — ported from Riley, the proven core.
 *
 * Any OpenAI-compatible provider (Groq, OpenRouter, DeepSeek, Together,
 * Fireworks, DeepInfra, Zhipu/GLM). Agents call by role ("fast" | "deep");
 * the runtime routes to the configured provider+model, with fallback to Groq.
 *
 * Env (all optional; defaults = Groq):
 *   GROQ_API_KEY / OPENROUTER_API_KEY / DEEPSEEK_API_KEY / TOGETHER_API_KEY /
 *   FIREWORKS_API_KEY / DEEPINFRA_API_KEY / ZHIPU_API_KEY
 *   LLM_FAST_PROVIDER  LLM_FAST_MODEL
 *   LLM_DEEP_PROVIDER  LLM_DEEP_MODEL
 *   LLM_FALLBACK_PROVIDER
 */

export const GROQ_MODEL = "llama-3.3-70b-versatile";
export const GROQ_FAST_MODEL = "llama-3.1-8b-instant";

export type LlmRole = "fast" | "deep";

interface Provider {
  name: string;
  baseUrl: string;
  apiKeyEnv: string;
  extraHeaders?: Record<string, string>;
}

const PROVIDERS: Record<string, Provider> = {
  groq:       { name: "groq",       baseUrl: "https://api.groq.com/openai/v1",        apiKeyEnv: "GROQ_API_KEY" },
  openrouter: { name: "openrouter", baseUrl: "https://openrouter.ai/api/v1",          apiKeyEnv: "OPENROUTER_API_KEY",
                extraHeaders: { "HTTP-Referer": "https://axism.ai", "X-Title": "Axism" } },
  together:   { name: "together",   baseUrl: "https://api.together.xyz/v1",           apiKeyEnv: "TOGETHER_API_KEY" },
  fireworks:  { name: "fireworks",  baseUrl: "https://api.fireworks.ai/inference/v1", apiKeyEnv: "FIREWORKS_API_KEY" },
  deepinfra:  { name: "deepinfra",  baseUrl: "https://api.deepinfra.com/v1/openai",   apiKeyEnv: "DEEPINFRA_API_KEY" },
  deepseek:   { name: "deepseek",   baseUrl: "https://api.deepseek.com/v1",           apiKeyEnv: "DEEPSEEK_API_KEY" },
  zhipu:      { name: "zhipu",      baseUrl: "https://open.bigmodel.cn/api/paas/v4",  apiKeyEnv: "ZHIPU_API_KEY" },
};

interface Route { provider: Provider; model: string; }

function providerByName(name: string | undefined): Provider {
  return (name && PROVIDERS[name.toLowerCase()]) || PROVIDERS.groq;
}

function routeForRole(role: LlmRole): Route {
  if (role === "fast") {
    return { provider: providerByName(process.env.LLM_FAST_PROVIDER ?? "groq"), model: process.env.LLM_FAST_MODEL ?? GROQ_FAST_MODEL };
  }
  return { provider: providerByName(process.env.LLM_DEEP_PROVIDER ?? "groq"), model: process.env.LLM_DEEP_MODEL ?? GROQ_MODEL };
}

function fallbackRoute(role: LlmRole): Route {
  return { provider: providerByName(process.env.LLM_FALLBACK_PROVIDER ?? "groq"), model: role === "fast" ? GROQ_FAST_MODEL : GROQ_MODEL };
}

export async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 30000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

interface ChatOpts { temperature?: number; maxTokens?: number; json?: boolean; }

async function chatOnRoute(route: Route, systemPrompt: string, userContent: string, opts: ChatOpts): Promise<string> {
  const key = process.env[route.provider.apiKeyEnv];
  if (!key) throw new Error(`${route.provider.apiKeyEnv} not configured`);

  const MAX_RETRIES = 4;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const res = await fetchWithTimeout(`${route.provider.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(route.provider.extraHeaders ?? {}) },
      body: JSON.stringify({
        model: route.model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userContent },
        ],
        temperature: opts.temperature ?? 0.3,
        max_tokens: opts.maxTokens ?? 1024,
        ...(opts.json === false ? {} : { response_format: { type: "json_object" } }),
      }),
    }, 45000);

    if (res.ok) {
      const json = (await res.json()) as { choices: Array<{ message: { content: string } }> };
      return json.choices[0]?.message?.content ?? "{}";
    }

    const body = await res.text();
    if ((res.status === 429 || res.status >= 500) && attempt < MAX_RETRIES) {
      const match = body.match(/try again in ([\d.]+)s/i);
      const waitMs = match ? Math.ceil(parseFloat(match[1]) * 1000) + 500 : (attempt + 1) * 4000;
      await new Promise((r) => setTimeout(r, waitMs));
      continue;
    }
    throw new Error(`LLM ${route.provider.name} error ${res.status}: ${body.slice(0, 300)}`);
  }
  throw new Error(`LLM ${route.provider.name}: max retries exceeded`);
}

export interface CallLlmOpts extends ChatOpts {
  role?: LlmRole;
  provider?: string;
  model?: string;
}

/** Call an LLM by role (or explicit provider/model). Falls back to Groq on failure. */
export async function callLLM(systemPrompt: string, userContent: string, opts: CallLlmOpts = {}): Promise<string> {
  const role: LlmRole = opts.role ?? "fast";
  const base = routeForRole(role);
  const primary: Route = {
    provider: opts.provider ? providerByName(opts.provider) : base.provider,
    model: opts.model ?? base.model,
  };
  try {
    return await chatOnRoute(primary, systemPrompt, userContent, opts);
  } catch (err) {
    const fb = fallbackRoute(role);
    if (fb.provider.name !== primary.provider.name && process.env[fb.provider.apiKeyEnv]) {
      return await chatOnRoute(fb, systemPrompt, userContent, opts);
    }
    throw err;
  }
}

/** Whether any provider key is configured — lets callers degrade gracefully. */
export function hasAnyProvider(): boolean {
  return Object.values(PROVIDERS).some((p) => !!process.env[p.apiKeyEnv]);
}

/** Parse a JSON object from a model response, tolerant of surrounding text. */
export function safeParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      try { return JSON.parse(m[0]); } catch { /* fall through */ }
    }
    return null;
  }
}
