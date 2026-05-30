import { describe, expect, it } from "vitest";
import { paginate, type Page } from "../src/sn/pagination.js";

// ─── §2.13 / B7 — ACL-aware keyset pagination ─────────────────────────────────
function rows(ids: string[]): Record<string, unknown>[] {
  return ids.map((id) => ({ sys_id: id, number: `INC${id}` }));
}

describe("§2.13 paginate (B7)", () => {
  it("walks full pages then a short page; complete (no partial), advancing on sys_id", async () => {
    const pages: Page[] = [
      { rows: rows(["a", "b"]), full: true },
      { rows: rows(["c", "d"]), full: true },
      { rows: rows(["e"]), full: false }, // short = end
    ];
    const seen: string[] = [];
    const r = await paginate(async (cursor) => {
      seen.push(cursor);
      return pages.shift() ?? { rows: [], full: false };
    }, { pageSize: 2, maxPages: 10 });
    expect(r.rows.map((x) => x.sys_id)).toEqual(["a", "b", "c", "d", "e"]);
    expect(r.partial).toBe(false);
    expect(seen).toEqual(["", "b", "d"]); // cursor advanced on last sys_id each page
  });

  it("B7 — an empty page does NOT infinite-loop (stops, bounded)", async () => {
    let calls = 0;
    const r = await paginate(async () => {
      calls++;
      return { rows: [], full: false }; // always empty
    }, { pageSize: 100, maxPages: 50 });
    expect(calls).toBe(1); // stopped immediately, no loop
    expect(r.rows).toEqual([]);
  });

  it("caps at maxPages and reports partial:true", async () => {
    const r = await paginate(async () => ({ rows: rows(["x"]), full: true }), { pageSize: 1, maxPages: 3 });
    expect(r.pagesFetched).toBe(3);
    expect(r.partial).toBe(true);
  });

  it("stops safely (partial) if a row lacks sys_id (cannot advance)", async () => {
    const r = await paginate(async () => ({ rows: [{ number: "INC1" }], full: true }), { pageSize: 1, maxPages: 10 });
    expect(r.partial).toBe(true);
    expect(r.pagesFetched).toBe(1);
  });
});
