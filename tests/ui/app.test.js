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
