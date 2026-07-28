/**
 * Live threat-intel enrichment — free, no-key public APIs.
 *
 * Turns raw indicators (public IPs, file hashes, CVE IDs) found in command
 * output, an intent, or an alert into real intelligence the analyst LLM can
 * cite — so the analysis stops being generic and starts saying things like
 * "that IP belongs to a hosting provider in RU" or "that CVE is CVSS 9.8".
 *
 * Sources (all free, NO API key required):
 *   - IPinfo            https://ipinfo.io      IP geo / ASN / org
 *   - CIRCL CVE Search  https://cve.circl.lu   CVE details (CVSS, summary)
 *   - CIRCL hashlookup  https://hashlookup.circl.lu   known-file lookup
 *
 * Never throws — any failure returns null and is silently skipped.
 */

import { fetchWithTimeout } from "./runtime.js";

export type IndicatorType = "ip" | "hash" | "cve";
export interface Indicator { indicator: string; type: IndicatorType; }
export interface Enrichment { indicator: string; type: IndicatorType; verdict: string; detail: string; source: string; }

const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const RE_HASH = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
const RE_CVE  = /\bCVE-\d{4}-\d{4,7}\b/gi;

/** Skip private/loopback/reserved IPs — no point enriching them. */
function isPublicIp(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n > 255)) return false;
  if (p[0] === 10 || p[0] === 127 || p[0] === 0) return false;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
  if (p[0] === 192 && p[1] === 168) return false;
  if (p[0] === 169 && p[1] === 254) return false;
  if (p[0] >= 224) return false;
  return true;
}

/** Pull public IPs, file hashes, and CVE IDs out of any text. */
export function extractIndicators(text: string): Indicator[] {
  const found = new Map<string, Indicator>();
  for (const m of text.match(RE_CVE) ?? []) found.set(m.toUpperCase(), { indicator: m.toUpperCase(), type: "cve" });
  for (const m of text.match(RE_HASH) ?? []) found.set(m.toLowerCase(), { indicator: m.toLowerCase(), type: "hash" });
  for (const m of text.match(RE_IPV4) ?? []) if (isPublicIp(m)) found.set(m, { indicator: m, type: "ip" });
  return [...found.values()].slice(0, 8); // cap to keep it fast
}

async function enrichIp(ip: string): Promise<Enrichment | null> {
  try {
    const r = await fetchWithTimeout(`https://ipinfo.io/${ip}/json`, { headers: { Accept: "application/json" } }, 8000);
    if (!r.ok) return null;
    const d = await r.json() as { org?: string; city?: string; region?: string; country?: string; hostname?: string };
    const loc = [d.city, d.region, d.country].filter(Boolean).join(", ");
    const verdict = [d.org, loc].filter(Boolean).join(" · ") || "resolved";
    return { indicator: ip, type: "ip", verdict, detail: d.hostname ? `host ${d.hostname}` : "", source: "IPinfo" };
  } catch { return null; }
}

async function enrichCve(cve: string): Promise<Enrichment | null> {
  try {
    const r = await fetchWithTimeout(`https://cve.circl.lu/api/cve/${cve}`, { headers: { Accept: "application/json" } }, 8000);
    if (!r.ok) return null;
    const d = await r.json() as { id?: string; cvss?: number; summary?: string } | null;
    if (!d || (!d.id && !d.summary)) return { indicator: cve, type: "cve", verdict: "no record found", detail: "", source: "CIRCL" };
    const verdict = d.cvss ? `CVSS ${d.cvss}` : "known CVE";
    return { indicator: cve, type: "cve", verdict, detail: (d.summary ?? "").slice(0, 160), source: "CIRCL CVE Search" };
  } catch { return null; }
}

async function enrichHash(hash: string): Promise<Enrichment | null> {
  const algo = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : "sha256";
  try {
    const r = await fetchWithTimeout(`https://hashlookup.circl.lu/lookup/${algo}/${hash}`, { headers: { Accept: "application/json" } }, 8000);
    if (r.status === 404) return { indicator: hash, type: "hash", verdict: "unknown file (not in reference set)", detail: "", source: "CIRCL hashlookup" };
    if (!r.ok) return null;
    const d = await r.json() as { FileName?: string };
    return { indicator: hash, type: "hash", verdict: "known file", detail: d.FileName ? `e.g. ${d.FileName}` : "", source: "CIRCL hashlookup" };
  } catch { return null; }
}

/** Enrich a batch of indicators in parallel. Nulls (failures) are dropped. */
export async function enrichMany(indicators: Indicator[]): Promise<Enrichment[]> {
  const out = await Promise.all(indicators.map((i) =>
    i.type === "ip"  ? enrichIp(i.indicator) :
    i.type === "cve" ? enrichCve(i.indicator) :
                       enrichHash(i.indicator)));
  return out.filter((r): r is Enrichment => r !== null);
}

/** Format enrichment as a compact block to inject into an LLM prompt. */
export function formatEnrichmentContext(items: Enrichment[]): string {
  if (!items.length) return "";
  return "\n\nTHREAT INTEL (live lookups):\n" + items.map((e) =>
    `- ${e.indicator} [${e.type}] → ${e.verdict}${e.detail ? ` — ${e.detail}` : ""} (${e.source})`).join("\n");
}
