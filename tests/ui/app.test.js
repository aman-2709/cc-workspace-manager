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

test("relative times", () => {
  const now = 1_800_000_000;
  assert.strictEqual(relativeTime(null, now), "unknown");
  assert.strictEqual(relativeTime(now - 5, now), "just now");
  assert.strictEqual(relativeTime(now + 100, now), "just now", "future times are not negative");
  assert.strictEqual(relativeTime(now - 300, now), "5 min ago");
  assert.strictEqual(relativeTime(now - 7200, now), "2 h ago");
  assert.strictEqual(relativeTime(now - 86400, now), "yesterday");
  assert.strictEqual(relativeTime(now - 3 * 86400, now), "3 days ago");
  assert.strictEqual(relativeTime(now - 21 * 86400, now), "3 weeks ago");
});

test("git summaries never invent values", () => {
  assert.strictEqual(gitSummary(null), "Git not checked yet");
  assert.strictEqual(gitSummary({ state: "not_git" }), "Not a Git repository");
  assert.strictEqual(gitSummary({ state: "ok", branch: "main", staged: 0, modified: 0, untracked: 0 }), "main: clean");
  assert.strictEqual(gitSummary({ state: "ok", branch: "main", staged: 1, modified: 2, untracked: 3, ahead: 1 }), "main: 1 staged, 2 modified, 3 untracked, 1 ahead");
  assert.strictEqual(gitSummary({ state: "ok", detached: true, staged: 0, modified: 0, untracked: 0 }), "detached HEAD: clean");
  assert.match(gitSummary({ state: "status_disabled_old_git", branch: "dev" }), /dev: status disabled, Git too old/);
  assert.match(gitSummary({ state: "unsafe_repository" }), /safe\.directory/);
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
