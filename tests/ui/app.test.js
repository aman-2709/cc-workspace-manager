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
  assert.deepStrictEqual(readPrefs(storage(null)), { view: "cards", theme: "system", privacy: null });
  assert.deepStrictEqual(readPrefs(storage('{"view":"table","theme":"dark","privacy":true}')), { view: "table", theme: "dark", privacy: true });
  assert.deepStrictEqual(readPrefs(storage('{"view":"<img>","theme":"neon","privacy":"yes"}')), { view: "cards", theme: "system", privacy: null });
  assert.deepStrictEqual(readPrefs(storage("{")), { view: "cards", theme: "system", privacy: null });
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

// ---- M3 helpers -----------------------------------------------------------------------------------
const {
  withServerDefaults, privacySuffix, sessionSummary, resumeWarningText, durationText, promptStateText, describeScope, settingsPatch,
} = require("../../web/app.js");

test("buildQuery adds has_sessions and privacy only when set", () => {
  const p = new URLSearchParams(buildQuery({ ...DEFAULT_QUERY, sessions: true, sort: "session" }, 10, null, true));
  assert.deepStrictEqual([p.get("has_sessions"), p.get("privacy"), p.get("sort")], ["1", "1", "session"]);
  const q = new URLSearchParams(buildQuery(DEFAULT_QUERY, 10, null, false));
  assert.strictEqual(q.has("has_sessions") || q.has("privacy"), false);
  assert.strictEqual(privacySuffix(true), "?privacy=1");
  assert.strictEqual(privacySuffix(true, "&"), "&privacy=1");
  assert.strictEqual(privacySuffix(false), "");
});

test("server defaults apply only to choices the browser has not made", () => {
  const ui = { default_view: "table", theme: "dark", privacy: true };
  assert.deepStrictEqual(withServerDefaults({ view: "cards", theme: "system", privacy: null }, ui, {}), { view: "table", theme: "dark", privacy: true });
  assert.deepStrictEqual(
    withServerDefaults({ view: "cards", theme: "light", privacy: false }, ui, { view: "cards", theme: "light", privacy: false }),
    { view: "cards", theme: "light", privacy: false },
  );
  assert.deepStrictEqual(withServerDefaults({ view: "cards", theme: "system", privacy: null }, { default_view: "<x>", theme: "neon" }, {}), { view: "cards", theme: "system", privacy: null });
  assert.deepStrictEqual(withServerDefaults({ view: "cards", theme: "system", privacy: null }, null, {}), { view: "cards", theme: "system", privacy: null });
});

test("session summaries: title, untitled, hidden title and no session", () => {
  const now = Math.floor(new Date(2027, 0, 15, 12, 0, 0).getTime() / 1000); // local noon: same calendar day
  assert.strictEqual(sessionSummary({ count: 0, latest: null }, now), "No Claude Code session recorded");
  assert.strictEqual(sessionSummary(null, now), "No Claude Code session recorded");
  assert.strictEqual(sessionSummary({ count: 2, latest: { title: "Fix it", title_source: "ai_title", last_activity_at: now - 30 } }, now), "Fix it · just now · 2 sessions");
  assert.strictEqual(sessionSummary({ count: 1, latest: { title_source: null, last_activity_at: null } }, now), "Untitled session · time unknown · 1 session");
  assert.strictEqual(sessionSummary({ count: 1, latest: { title_source: "ai_title", last_activity_at: now - 7200 } }, now), "Latest session 2 h ago · 1 session", "privacy mode: no title");
});

test("resume warnings, durations and prompt states read as sentences", () => {
  assert.match(resumeWarningText("cwd_missing"), /no longer exists/);
  assert.strictEqual(resumeWarningText("future_code"), "future_code");
  assert.deepStrictEqual([durationText(40), durationText(600), durationText(3600), durationText(3660), durationText(200000), durationText(-1), durationText(null)],
    ["40 s", "10 min", "1 h", "1 h 1 min", "2 days", "", ""]);
  assert.strictEqual(promptStateText({ state: "found" }, "last prompt"), "");
  assert.match(promptStateText({ state: "hidden" }, "last prompt"), /hidden in privacy mode/);
  assert.match(promptStateText({ state: "none", whole_file: false }, "last prompt"), /4 MiB/);
  assert.match(promptStateText({ state: "none", whole_file: true }, "first prompt"), /No first prompt recorded/);
  assert.match(promptStateText({ state: "unreadable" }, "last prompt"), /could not be read/);
});

test("the discovery scope is explained in plain language, without hidden paths", () => {
  const st = {
    config: { discovery: { exclude: ["vendor/"], full_scan: false } },
    effective: { roots: ["~"], default_exclusions: ["node_modules", "_build"], home_only_exclusions: ["snap"], max_depth: 10, same_file_system: true },
  };
  const text = describeScope(st).join("\n");
  assert.match(text, /looks in: ~, up to 10 levels deep/);
  assert.match(text, /node_modules, _build, snap \(directly in home\)/);
  assert.match(text, /your exclusions\): vendor\//);
  assert.match(text, /only in the parent folders of projects found from sessions/);
  const priv = describeScope({ config: { discovery: { full_scan: true } }, effective: { default_exclusions: [], home_only_exclusions: [], max_depth: 3 } }).join("\n");
  assert.match(priv, /hidden in privacy mode/);
  assert.match(priv, /every root at every scan/);
  assert.deepStrictEqual(describeScope(null), []);
});

test("the settings form becomes a partial patch: numbers parsed, path lists split, hidden ones left out", () => {
  const p = settingsPatch({
    roots: " /a \n\n/b c\n", exclude: null, full_scan: true, scan_interval_secs: "120", missing_retention_days: "",
    max_depth: "4", same_file_system: false, budget: "0", inactive_after_days: "7", dormant_after_days: "30",
    store_prompt_text: false, port: "8765", default_view: "table", theme: "dark", ui_privacy: true,
  });
  assert.deepStrictEqual(p.discovery, { roots: ["/a", "/b c"], scan_interval_secs: 120, max_depth: 4, full_scan: true, same_file_system: false });
  assert.deepStrictEqual(p.watch, { budget: 0 });
  assert.deepStrictEqual(p.server, { port: 8765 });
  assert.deepStrictEqual(p.ui, { default_view: "table", theme: "dark", privacy: true });
  assert.deepStrictEqual(p.sessions, { store_prompt_text: false });
  assert.strictEqual("exclude" in p.discovery, false, "hidden in privacy mode: not sent");
});
