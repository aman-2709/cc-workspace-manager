// Run with: node --test tests/ui   (only the pure helpers are exercised; no DOM)
const test = require("node:test");
const assert = require("node:assert");
const {
  parseFragmentToken, shouldRotate, describeDiscovery, readSession, shouldClearOnUnauthorized, preferStored, STORAGE_KEY,
} = require("../../web/app.js");

const TOKEN = "A".repeat(43);

test("parseFragmentToken accepts only a well-formed bootstrap fragment", () => {
  assert.strictEqual(parseFragmentToken(`#bt=${TOKEN}`), TOKEN);
  for (const bad of ["", "#", "#bt=", "#bt=short", `#bt=${TOKEN}x`, `#x=${TOKEN}`, `bt=${TOKEN}`, `#bt=${TOKEN}&a=b`, `#bt=${"A".repeat(42)}!`, null, undefined]) {
    assert.strictEqual(parseFragmentToken(bad), null, String(bad));
  }
});

test("shouldRotate triggers at and after rotate_after only", () => {
  assert.strictEqual(shouldRotate(null, 5), false);
  assert.strictEqual(shouldRotate({ rotate_after: 100 }, 99), false);
  assert.strictEqual(shouldRotate({ rotate_after: 100 }, 100), true);
  assert.strictEqual(shouldRotate({ rotate_after: "x" }, 100), false);
});

test("describeDiscovery", () => {
  assert.strictEqual(describeDiscovery(null), "");
  assert.match(describeDiscovery({ phase: "scanning", dirs_visited: 12, projects_found: 3 }), /Scanning… 12 folders checked, 3 projects found/);
  assert.strictEqual(describeDiscovery({ phase: "idle", skipped: {}, last_success_at: null }), "No completed scan yet");
  assert.match(describeDiscovery({ phase: "idle", skipped: { permission: 2, vanished: 1 }, last_success_at: 1 }), /3 folders could not be read/);
});

test("readSession tolerates corrupt storage", () => {
  const mk = (v) => ({ getItem: (k) => (k === STORAGE_KEY ? v : null) });
  assert.deepStrictEqual(readSession(mk('{"token":"t"}')), { token: "t" });
  for (const bad of [null, "", "{", "[]", '{"token":1}', "null"]) assert.strictEqual(readSession(mk(bad)), null, String(bad));
});

test("a 401 clears the shared session only if the stored token is the rejected one", () => {
  assert.strictEqual(shouldClearOnUnauthorized(null, "a"), true);
  assert.strictEqual(shouldClearOnUnauthorized({ token: "a" }, "a"), true);
  assert.strictEqual(shouldClearOnUnauthorized({ token: "b" }, "a"), false, "another tab rotated");
  assert.strictEqual(shouldClearOnUnauthorized({ token: "b" }, null), false);
});

test("preferStored adopts a token another tab stored and keeps ours otherwise", () => {
  const ours = { token: "a", rotate_after: 1 };
  assert.strictEqual(preferStored(ours, null), ours);
  assert.strictEqual(preferStored(ours, { token: "a", rotate_after: 1 }), ours);
  assert.deepStrictEqual(preferStored(ours, { token: "b", rotate_after: 2 }), { token: "b", rotate_after: 2 });
  assert.deepStrictEqual(preferStored(null, { token: "c" }), { token: "c" });
  assert.strictEqual(preferStored(null, null), null);
});

test("describeDiscovery counts directories that changed during the walk as problems", () => {
  assert.match(describeDiscovery({ phase: "idle", skipped: { changed: 2 }, last_success_at: 1 }), /2 folders could not be read/);
});

// ---- M2 helpers -----------------------------------------------------------------------------------
const {
  readPrefs, buildQuery, withView, withSort, relativeTime, gitSummary, paginate, reconnectDelay, wsUrl, PREFS_KEY, DEFAULT_QUERY,
  plural, describeUnreadable, degradedSummary, truncatePath, calendarDaysAgo,
} = require("../../web/app.js");

const storage = (v) => ({ getItem: (k) => (k === PREFS_KEY ? v : null) });

test("view and theme preferences are read defensively", () => {
  assert.deepStrictEqual(readPrefs(storage(null)), { view: "cards", theme: "system" });
  assert.deepStrictEqual(readPrefs(storage('{"view":"table","theme":"dark"}')), { view: "table", theme: "dark" });
  assert.deepStrictEqual(readPrefs(storage('{"view":"<img>","theme":"neon"}')), { view: "cards", theme: "system" });
  assert.deepStrictEqual(readPrefs(storage("{")), { view: "cards", theme: "system" });
});

test("buildQuery encodes search, sort and filters and nothing else", () => {
  assert.strictEqual(buildQuery(DEFAULT_QUERY, 200), "sort=activity&order=desc&limit=200");
  const q = buildQuery({ ...DEFAULT_QUERY, q: "  my app&x=1 ", activity: "week", dirty: true, missing: true, ignored: true, sort: "name", order: "asc" }, 50, "CUR");
  const p = new URLSearchParams(q);
  assert.strictEqual(p.get("q"), "my app&x=1");
  assert.deepStrictEqual(
    [p.get("sort"), p.get("order"), p.get("activity"), p.get("dirty"), p.get("include_missing"), p.get("include_ignored"), p.get("limit"), p.get("cursor")],
    ["name", "asc", "week", "1", "1", "1", "50", "CUR"],
  );
  assert.strictEqual(new URLSearchParams(buildQuery({ ...DEFAULT_QUERY, activity: "all" }, 1)).has("activity"), false);
});

test("switching views preserves search, sort and filters (same query for both views)", () => {
  const s = { ...DEFAULT_QUERY, q: "x", sort: "commit", order: "desc", activity: "dormant", dirty: true, view: "cards", page: 3 };
  const t = withView(s, "table");
  assert.strictEqual(t.view, "table");
  assert.strictEqual(t.page, 0);
  assert.strictEqual(buildQuery(t, 200), buildQuery(s, 200));
  assert.strictEqual(withView(t, "cards").view, "cards");
  assert.strictEqual(withView(t, "bogus").view, "cards");
});

test("column sorting starts in the natural order and flips on the second click", () => {
  let s = { ...DEFAULT_QUERY, page: 2 };
  s = withSort(s, "name");
  assert.deepStrictEqual([s.sort, s.order, s.page], ["name", "asc", 0]);
  s = withSort(s, "name");
  assert.strictEqual(s.order, "desc");
  s = withSort(s, "commit");
  assert.deepStrictEqual([s.sort, s.order], ["commit", "desc"]);
});

test("relative times count calendar days, like the activity status", () => {
  const now = 1_800_000_000;
  assert.strictEqual(relativeTime(null, now), "unknown");
  assert.strictEqual(relativeTime(now - 5, now, 0), "just now");
  assert.strictEqual(relativeTime(now + 100, now, 0), "just now", "future times are not negative");
  assert.strictEqual(relativeTime(now - 300, now, 0), "5 min ago");
  assert.strictEqual(relativeTime(now - 7200, now, 0), "2 h ago");
  assert.strictEqual(relativeTime(now - 86400, now, 1), "yesterday");
  assert.strictEqual(relativeTime(now - 3 * 86400, now, 3), "3 days ago");
  assert.strictEqual(relativeTime(now - 21 * 86400, now, 21), "3 weeks ago");
  assert.strictEqual(relativeTime(now + 9999, now, -1), "just now", "a negative day count is today");
});

test("the 6/7-day boundary at a non-midnight time agrees with the bucket", () => {
  // The real-home report: 6.46 × 24 h ago is 7 calendar days ago, Inactive, not "6 days ago".
  const now = 1_782_828_000; // 2026-06-30 10:00 EDT
  const at = now - 155 * 3600; // 2026-06-23 23:00 EDT
  assert.strictEqual(relativeTime(at, now, 7), "7 days ago", "the server's calendar days win");
  assert.notStrictEqual(relativeTime(at, now, 7), "6 days ago");
  assert.strictEqual(relativeTime(now - 153 * 3600, now, 6), "6 days ago");
  // A minute after midnight, a change two minutes earlier was yesterday, as its bucket says.
  assert.strictEqual(relativeTime(now - 120, now, 1), "yesterday");
});

test("local calendar days in the browser (fallback without days_ago)", () => {
  const t = (y, m, d, h, min = 0) => new Date(y, m - 1, d, h, min).getTime() / 1000;
  assert.strictEqual(calendarDaysAgo(t(2026, 6, 23, 23), t(2026, 6, 30, 10)), 7);
  assert.strictEqual(calendarDaysAgo(t(2026, 6, 24, 0, 30), t(2026, 6, 30, 10)), 6);
  assert.strictEqual(calendarDaysAgo(t(2026, 6, 29, 23, 59), t(2026, 6, 30, 0, 1)), 1);
  assert.strictEqual(calendarDaysAgo(t(2026, 6, 30, 9), t(2026, 6, 30, 10)), 0);
  assert.strictEqual(calendarDaysAgo(t(2026, 7, 1, 9), t(2026, 6, 30, 10)), 0, "future: today");
  assert.strictEqual(relativeTime(t(2026, 6, 23, 23), t(2026, 6, 30, 10)), "7 days ago");
});

test("paths are shortened at a / boundary, keeping the end", () => {
  const p = "~/dev/clients/acme/services/api";
  assert.strictEqual(truncatePath(p, 100), p);
  assert.strictEqual(truncatePath(p, p.length), p);
  assert.strictEqual(truncatePath(p, p.length - 1), "…/clients/acme/services/api");
  assert.strictEqual(truncatePath(p, 16), "…/services/api");
  assert.strictEqual(truncatePath(p, 15), "…/services/api");
  assert.strictEqual(truncatePath(p, 13), "…/api");
  assert.strictEqual(truncatePath(p, 3), "…/api", "the last component is always whole");
  assert.strictEqual(truncatePath("/srv/code/x", 8), "…/code/x");
  assert.strictEqual(truncatePath("/srv/x", 6), "/srv/x");
  assert.strictEqual(truncatePath("a-very-long-name", 4), "a-very-long-name", "no / to cut at");
  for (const max of [5, 10, 20, 25]) {
    const out = truncatePath(p, max);
    assert.ok(out === p || out.startsWith("…/"), out);
    assert.ok(p.endsWith(out.replace(/^…/, "")), `${out} is a /-aligned tail`);
  }
});

test("folder counts are pluralized and the unreadable folders listed", () => {
  assert.strictEqual(plural(1, "folder"), "1 folder");
  assert.strictEqual(plural(0, "folder"), "0 folders");
  assert.match(describeDiscovery({ phase: "idle", skipped: { permission: 1 }, last_success_at: 1 }), /, 1 folder could not be read$/);
  assert.match(describeDiscovery({ phase: "scanning", dirs_visited: 1, projects_found: 1 }), /1 folder checked, 1 project found/);
  assert.strictEqual(describeUnreadable({ skipped: {} }), "");
  assert.strictEqual(describeUnreadable(null), "");
  const st = { skipped: { permission: 2, vanished: 1 }, unreadable: [{ path: "~/a", reason: "permission" }, { path: "~/b", reason: "vanished" }] };
  assert.strictEqual(describeUnreadable(st), "Could not be read in the last scan:\n~/a (permission)\n~/b (vanished)\n… and 1 more");
});

test("the degraded banner has a one-line summary", () => {
  assert.strictEqual(degradedSummary(null), "");
  assert.strictEqual(degradedSummary({ degraded: false, partial_projects: 3 }), "");
  assert.strictEqual(degradedSummary({ degraded: true, partial_projects: 1, polled_projects: 0 }), "Monitoring is degraded: 1 project partly watched.");
  assert.strictEqual(
    degradedSummary({ degraded: true, watcher: "inotify", partial_projects: 5, polled_projects: 2, recovering_overflow: true }),
    "Monitoring is degraded: 5 projects partly watched, 2 projects checked only at each scan, catching up after lost file events.",
  );
  assert.strictEqual(degradedSummary({ degraded: true, watcher: "unavailable", polled_projects: 1 }), "Monitoring is degraded: no inotify instance, 1 project checked only at each scan.");
  assert.ok(!degradedSummary({ degraded: true, partial_projects: 9 }).includes("\n"));
});

test("git summaries never invent values", () => {
  assert.strictEqual(gitSummary(null), "Git not checked yet");
  assert.strictEqual(gitSummary({ state: "not_git" }), "Not a Git repository");
  assert.strictEqual(gitSummary({ state: "ok", branch: "main", staged: 0, modified: 0, untracked: 0 }), "main: clean");
  assert.strictEqual(gitSummary({ state: "ok", branch: "main", staged: 1, modified: 2, untracked: 3, ahead: 1 }), "main: 1 staged, 2 modified, 3 untracked, 1 ahead");
  assert.strictEqual(gitSummary({ state: "ok", detached: true, staged: 0, modified: 0, untracked: 0 }), "detached HEAD: clean");
  assert.match(gitSummary({ state: "status_disabled_old_git", branch: "dev" }), /dev: status disabled, Git too old/);
  assert.match(gitSummary({ state: "unsafe_repository" }), /safe\.directory/);
  assert.strictEqual(gitSummary({ state: "partial_clone", branch: "main" }), "main: Git status unavailable (partial clone)");
  assert.strictEqual(gitSummary({ state: "partial_clone" }), "Git status unavailable (partial clone)");
});

test("table pagination clamps the page", () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  assert.deepStrictEqual(paginate(items, 0, 100).rows.length, 100);
  assert.deepStrictEqual([paginate(items, 2, 100).rows.length, paginate(items, 2, 100).pages], [50, 3]);
  assert.strictEqual(paginate(items, 9, 100).page, 2);
  assert.deepStrictEqual(paginate([], 0, 100), { rows: [], page: 0, pages: 1 });
});

test("reconnect back-off doubles up to 30 s and the socket URL is same-origin", () => {
  assert.deepStrictEqual([0, 1, 2, 3, 4, 5, 6, 20].map(reconnectDelay), [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
  assert.strictEqual(wsUrl({ host: "127.0.0.1:8765" }), "ws://127.0.0.1:8765/api/v1/ws");
});
