// server/fx.ts — USD→TWD reference rate for NewebPay pricing.
//
// Prices are denominated in USD (USD_PER_CREDIT); NewebPay can only charge TWD
// (the MPG `Amt` field is Int, 新台幣 — there is no currency parameter), so every
// order converts USD→TWD at checkout time using the rate cached here.
//
// The checkout path must never make a network call or throw, so this module
// refreshes in the background and resolves reads in this order:
//   1. in-memory rate, if fresher than FX_MAX_AGE_MS
//   2. last known good rate persisted in SQLite (survives restarts)
//   3. FALLBACK_TWD_PER_USD from the environment
// A rate outside SANE_MIN..SANE_MAX is rejected at every layer, so a broken or
// hijacked upstream cannot silently reprice the product.

import { db } from "./db";

export function getFallbackTwdPerUsd(): number {
  const parsed = Number(process.env.FALLBACK_TWD_PER_USD);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 32;
}
const FX_MAX_AGE_MS = Number(process.env.FX_MAX_AGE_MS) || (24 * 60 * 60 * 1000);

// USD/TWD has stayed inside roughly 27–35 for two decades. These bounds exist to
// reject garbage (0, null-coerced NaN, an inverted quote), not to track markets.
const SANE_MIN = 20;
const SANE_MAX = 45;

// Both endpoints are keyless and return JSON. Tried in order.
const SOURCES: { url: string; pick: (j: any) => unknown }[] = [
  { url: "https://open.er-api.com/v6/latest/USD", pick: (j) => j?.rates?.TWD },
  {
    url: "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json",
    pick: (j) => j?.usd?.twd,
  },
];

db.exec(`
  CREATE TABLE IF NOT EXISTS fx_rates (
    pair      TEXT PRIMARY KEY,        -- e.g. 'USD/TWD'
    rate      REAL NOT NULL,
    source    TEXT NOT NULL,
    fetchedAt TEXT NOT NULL
  );
`);

const readRate = db.prepare("SELECT * FROM fx_rates WHERE pair = 'USD/TWD'");
const writeRate = db.prepare(`
  INSERT INTO fx_rates (pair, rate, source, fetchedAt) VALUES ('USD/TWD', ?, ?, ?)
  ON CONFLICT(pair) DO UPDATE SET rate = excluded.rate,
                                  source = excluded.source,
                                  fetchedAt = excluded.fetchedAt
`);

export interface FxRate {
  rate: number;
  source: string;
  fetchedAt: string;
  /** true when serving FALLBACK_TWD_PER_USD because nothing better exists. */
  stale: boolean;
}

function isSane(v: unknown): v is number {
  const n = Number(v);
  return Number.isFinite(n) && n >= SANE_MIN && n <= SANE_MAX;
}

let memo: FxRate | null = null;

/**
 * Current USD→TWD rate. Synchronous and total — never throws, never blocks.
 */
export function getTwdPerUsd(): FxRate {
  if (memo && Date.now() - Date.parse(memo.fetchedAt) < FX_MAX_AGE_MS) return memo;

  const row = readRate.get() as
    | { rate: number; source: string; fetchedAt: string }
    | undefined;
  if (row && isSane(row.rate)) {
    // Served even when older than FX_MAX_AGE_MS: a stale real rate beats the
    // hardcoded fallback, and refresh() is already trying to replace it.
    memo = { ...row, stale: false };
    return memo;
  }

  return {
    rate: getFallbackTwdPerUsd(),
    source: "fallback",
    fetchedAt: new Date(0).toISOString(),
    stale: true,
  };
}

/** Fetch a fresh rate and persist it. Safe to call concurrently. */
export async function refresh(): Promise<FxRate | null> {
  for (const { url, pick } of SOURCES) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const value = pick(await res.json());
      if (!isSane(value)) throw new Error(`implausible rate: ${value}`);

      const fetchedAt = new Date().toISOString();
      const host = new URL(url).host;
      writeRate.run(Number(value), host, fetchedAt);
      memo = { rate: Number(value), source: host, fetchedAt, stale: false };
      console.log(`fx: USD/TWD = ${value} (${host})`);
      return memo;
    } catch (err) {
      console.warn(`fx: ${url} failed —`, (err as Error).message);
    }
  }
  console.error("fx: all sources failed; keeping last known rate");
  return null;
}

/** Refresh now, then daily. Call once at startup; failures are non-fatal. */
export function startFxRefresh(): void {
  void refresh();
  setInterval(() => void refresh(), FX_MAX_AGE_MS).unref();
}
