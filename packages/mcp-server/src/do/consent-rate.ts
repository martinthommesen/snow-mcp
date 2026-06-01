import { DurableObject } from "cloudflare:workers";

// ConsentRateDO (finding 4) — admission control for the OAuth consent write.
//
// GET /authorize writes a `consent:<uuid>` entry into OAUTH_KV on EVERY request, before any
// operator-secret check (the secret is entered ON the consent page). The endpoint is public
// OAuth surface and the Origin guard allows no-Origin clients, so a non-browser caller holding a
// registered client_id can flood /authorize and churn unbounded KV writes. This DO bounds consent
// writes per (client_id + IP) within a rolling window; over-cap requests are rejected with 429
// BEFORE the KV put, so the flood cannot consume KV write quota or interfere with OAuth storage.
//
// Counters are held IN MEMORY ONLY — there is deliberately NO per-request `ctx.storage` write, or
// we would merely relocate the write-flood from KV into DO storage. A DO eviction resets the
// window (the limiter re-engages on the very next request), which is acceptable: the goal is to
// bound SUSTAINED floods, and a transient reset cannot produce unbounded KV writes.
const WINDOW_MS = 60_000; // rolling window length
const MAX_PER_WINDOW = 30; // consent writes allowed per (client_id + IP) per window
const MAX_KEYS = 10_000; // memory bound; prune expired entries before exceeding it

export class ConsentRateDO extends DurableObject {
  private windows = new Map<string, { count: number; resetAt: number }>();

  /**
   * Admit one consent write for `key` (e.g. `clientId|ip`) at time `now` (ms). Returns true and
   * counts the request when within the window cap; returns false (deny -> caller 429s) when the
   * key is already at the cap for the current window. The DO is single-threaded, so this
   * read-check-write is atomic without any storage round-trip.
   */
  async allow(key: string, now: number): Promise<boolean> {
    const w = this.windows.get(key);
    if (!w || now >= w.resetAt) {
      if (this.windows.size >= MAX_KEYS) this.prune(now);
      this.windows.set(key, { count: 1, resetAt: now + WINDOW_MS });
      return true;
    }
    if (w.count >= MAX_PER_WINDOW) return false;
    w.count++;
    return true;
  }

  /** Drop expired windows to bound memory (called only when the map is large). */
  private prune(now: number): void {
    for (const [k, w] of this.windows) {
      if (now >= w.resetAt) this.windows.delete(k);
    }
  }
}
