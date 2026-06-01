import { DurableObject } from "cloudflare:workers";

// ConsentRateDO (finding 4 + follow-up) — admission control for the OAuth consent write.
//
// GET /authorize writes a `consent:<uuid>` entry into OAUTH_KV on EVERY request, before any
// operator-secret check (the secret is entered ON the consent page). The endpoint is public
// OAuth surface and the Origin guard allows no-Origin clients, so a non-browser caller can flood
// /authorize and churn unbounded KV writes. This DO bounds consent writes per SOURCE IP within a
// rolling window; over-cap requests are rejected with 429 BEFORE the KV put, so the flood cannot
// consume KV write quota or interfere with OAuth storage.
//
// KEY BY IP, NOT client_id (follow-up finding): dynamic client registration (/oauth/register) lets
// an attacker mint unlimited client_ids. Keying by `client_id|ip` would let each fresh client_id
// create a distinct limiter entry — multiplying memory AND splitting the per-key cap so the
// aggregate write rate per IP is unbounded. Keying by IP alone caps an attacker IP regardless of
// how many clients it registers, and bounds the live key set to ~one entry per active source IP.
//
// HARD MEMORY BOUND: counters live IN MEMORY ONLY (no per-request `ctx.storage` write — that would
// just relocate the flood into DO storage). The map is capped at MAX_KEYS: a genuinely new key
// first prunes expired entries, then — if still full — evicts the oldest-inserted entry (== the
// soonest to expire, since the window length is constant) BEFORE inserting. The map therefore
// never exceeds MAX_KEYS, closing the unbounded-growth hole. We EVICT (not reject-when-full) on
// purpose: an evicted key gets a fresh window on its next request, so filling the map can never
// DENY a legitimate IP — the only denial path is the per-IP cap. (Reject-when-full would be a
// legit-lockout DoS.) A DO eviction/reset re-engages the limiter on the next request, which is
// acceptable: the goal is to bound SUSTAINED floods.
const WINDOW_MS = 60_000; // rolling window length
const MAX_PER_WINDOW = 30; // consent writes allowed per source IP per window
const MAX_KEYS = 10_000; // HARD cap on tracked keys; oldest is evicted when full

export class ConsentRateDO extends DurableObject {
  private windows = new Map<string, { count: number; resetAt: number }>();

  /**
   * Admit one consent write for `key` (the source IP) at time `now` (ms). Returns true and counts
   * the request when within the window cap; returns false (deny -> caller 429s) when the key is at
   * the cap for the current window. The DO is single-threaded, so this read-check-write is atomic
   * without any storage round-trip. A genuinely new key enforces the MAX_KEYS hard cap first.
   */
  async allow(key: string, now: number): Promise<boolean> {
    const w = this.windows.get(key);
    if (w && now < w.resetAt) {
      if (w.count >= MAX_PER_WINDOW) return false;
      w.count++;
      return true;
    }
    // No live window: we are about to (re)insert. Only a genuinely NEW key grows the map, so
    // enforce the hard cap there — prune expired, then evict oldest until there is room.
    if (!w && this.windows.size >= MAX_KEYS) {
      this.prune(now);
      while (this.windows.size >= MAX_KEYS) {
        const oldest = this.windows.keys().next().value;
        if (oldest === undefined) break;
        this.windows.delete(oldest);
      }
    }
    this.windows.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }

  /** Drop expired windows (called on the new-key path when the map is at capacity). */
  private prune(now: number): void {
    for (const [k, w] of this.windows) {
      if (now >= w.resetAt) this.windows.delete(k);
    }
  }

  /** Observability/tests: current tracked-key count (never exceeds MAX_KEYS). */
  async count(): Promise<number> {
    return this.windows.size;
  }
}
