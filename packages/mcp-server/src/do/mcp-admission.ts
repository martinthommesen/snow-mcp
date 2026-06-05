import { DurableObject } from "cloudflare:workers";

const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 60;
const MAX_IN_FLIGHT = 4;
const STALE_LEASE_MS = 75_000;

const WINDOW_KEY = "window";
const LEASES_KEY = "leases";

interface WindowState {
  startAt: number;
  count: number;
}

type LeaseMap = Record<string, number>;

export type McpAdmissionResult =
  | { ok: true; leaseId: string }
  | { ok: false; reason: "rate" | "concurrency"; retryAfterMs: number };

export class McpAdmissionDO extends DurableObject {
  private chain: Promise<unknown> = Promise.resolve();

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.chain.then(task);
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  admit(now: number = Date.now()): Promise<McpAdmissionResult> {
    return this.enqueue(() => this.admitCritical(now));
  }

  private async admitCritical(now: number): Promise<McpAdmissionResult> {
    const stored = await this.ctx.storage.get<WindowState | LeaseMap>([WINDOW_KEY, LEASES_KEY]);
    let window = stored.get(WINDOW_KEY) as WindowState | undefined;
    if (!window || now >= window.startAt + WINDOW_MS) {
      window = { startAt: now, count: 0 };
    }
    if (window.count >= MAX_REQUESTS_PER_WINDOW) {
      return { ok: false, reason: "rate", retryAfterMs: Math.max(1, window.startAt + WINDOW_MS - now) };
    }

    const leases = this.pruneLeases((stored.get(LEASES_KEY) as LeaseMap | undefined) ?? {}, now);
    const leaseExpiries = Object.values(leases);
    if (leaseExpiries.length >= MAX_IN_FLIGHT) {
      const earliestExpiry = Math.min(...leaseExpiries);
      await this.ctx.storage.put({ [WINDOW_KEY]: window, [LEASES_KEY]: leases });
      return { ok: false, reason: "concurrency", retryAfterMs: Math.max(1, earliestExpiry - now) };
    }

    const leaseId = crypto.randomUUID();
    leases[leaseId] = now + STALE_LEASE_MS;
    window = { ...window, count: window.count + 1 };
    await this.ctx.storage.put({ [WINDOW_KEY]: window, [LEASES_KEY]: leases });
    return { ok: true, leaseId };
  }

  release(leaseId: string): Promise<void> {
    return this.enqueue(async () => {
      const leases = await this.ctx.storage.get<LeaseMap>(LEASES_KEY);
      if (!leases || leases[leaseId] === undefined) return;
      delete leases[leaseId];
      await this.ctx.storage.put(LEASES_KEY, leases);
    });
  }

  async snapshot(now: number = Date.now()): Promise<{ windowCount: number; inFlight: number }> {
    const stored = await this.ctx.storage.get<WindowState | LeaseMap>([WINDOW_KEY, LEASES_KEY]);
    const window = stored.get(WINDOW_KEY) as WindowState | undefined;
    return {
      windowCount: window && now < window.startAt + WINDOW_MS ? window.count : 0,
      inFlight: Object.keys(this.pruneLeases((stored.get(LEASES_KEY) as LeaseMap | undefined) ?? {}, now)).length,
    };
  }

  private pruneLeases(leases: LeaseMap, now: number): LeaseMap {
    const live: LeaseMap = {};
    for (const [leaseId, expiresAt] of Object.entries(leases)) {
      if (expiresAt > now) live[leaseId] = expiresAt;
    }
    return live;
  }
}
