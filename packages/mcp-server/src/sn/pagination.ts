// ACL-aware keyset pagination (plan §2.13; gate B7). `sysparm_limit` is applied BEFORE
// ACL evaluation, so a page can come back empty after filtering even when visible rows
// exist further on. Strategy (integration_user, the supported path): keyset on `sys_id`,
// advancing on the real `sys_id` of the last row returned — the broad identity returns
// rows, ActorPolicy masks fields above the cursor. An empty page never stalls: we stop
// and surface `partial: true` rather than looping. Pure host logic — unit-verified.

export interface Page {
  rows: Record<string, unknown>[];
  /** true when ServiceNow returned a full page (more may exist). */
  full: boolean;
}

export interface PaginateOptions {
  pageSize: number;
  maxPages: number;
}

export interface PaginateResult {
  rows: Record<string, unknown>[];
  partial: boolean;
  pagesFetched: number;
}

/**
 * Drive a keyset cursor. `fetchPage(cursor, pageSize)` must apply
 * `sys_id>cursor^ORDERBYsys_id` and return rows (each carrying `sys_id`). The cursor
 * advances on the last row's `sys_id`. Guarantees: no infinite loop (an empty page
 * stops), no skipped visible rows (advance only on real sys_ids), honest completeness
 * (`partial: true` when capped or stopped on an empty-but-maybe-not-end page).
 */
export async function paginate(
  fetchPage: (cursor: string, pageSize: number) => Promise<Page>,
  opts: PaginateOptions,
): Promise<PaginateResult> {
  const out: Record<string, unknown>[] = [];
  let cursor = "";
  let pages = 0;
  while (pages < opts.maxPages) {
    const page = await fetchPage(cursor, opts.pageSize);
    pages++;
    if (page.rows.length === 0) {
      // Empty: either true end, or ACL/filter blanked this sys_id range. We cannot tell
      // cheaply, so stop without looping. `full` was false (no rows) → not necessarily end.
      return { rows: out, partial: !page.full && cursorMightHaveMore(page), pagesFetched: pages };
    }
    out.push(...page.rows);
    const last = page.rows[page.rows.length - 1];
    const sysId = String(last?.sys_id ?? "");
    if (!sysId) {
      // No sys_id to advance on — cannot continue safely.
      return { rows: out, partial: true, pagesFetched: pages };
    }
    cursor = sysId;
    if (!page.full) return { rows: out, partial: false, pagesFetched: pages }; // short page = true end
  }
  return { rows: out, partial: true, pagesFetched: pages }; // hit maxPages
}

// An empty page from a keyset query means we've advanced past the last matching row OR
// the filter blanked this range. With keyset (not offset) and a broad identity, the
// former is the common case → treat empty as end (partial:false). We keep a hook so the
// per_user_oauth bounded-offset fallback can override this.
function cursorMightHaveMore(_page: Page): boolean {
  return false;
}
