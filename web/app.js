// CC Workspace Manager: vanilla JS, no framework. Data reaches the DOM only via textContent and DOM APIs.
// (A repository test forbids HTML-string injection APIs in this directory.)
"use strict";

const STORAGE_KEY = "ccwm.session";
const API = "/api/v1";
const POLL_SCANNING_MS = 1000;
const POLL_IDLE_MS = 15000;
const PAGE_LIMIT = 200;

// ---- pure helpers (unit-tested with `node --test tests/ui`) ------------------------------------

function parseFragmentToken(hash) {
  const m = /^#bt=([A-Za-z0-9_-]{43})$/.exec(hash || "");
  return m ? m[1] : null;
}

function shouldRotate(session, nowSeconds) {
  return Boolean(session) && typeof session.rotate_after === "number" && nowSeconds >= session.rotate_after;
}

function describeDiscovery(status) {
  if (!status) return "";
  if (status.phase === "scanning") {
    return `Scanning… ${status.dirs_visited} folders checked, ${status.projects_found} projects found`;
  }
  const skipped = status.skipped || {};
  const problems = (skipped.permission || 0) + (skipped.vanished || 0) + (skipped.changed || 0) + (skipped.other || 0);
  const last = status.last_success_at ? `Last scan ${new Date(status.last_success_at * 1000).toLocaleString()}` : "No completed scan yet";
  return problems > 0 ? `${last} · ${problems} folders could not be read` : last;
}

function readSession(storage) {
  try {
    const s = JSON.parse(storage.getItem(STORAGE_KEY) || "null");
    return s && typeof s.token === "string" ? s : null;
  } catch (_) {
    return null;
  }
}

// Tabs share one session in localStorage. A 401 for token T clears the shared session only if the
// stored token is still T; if another tab has already rotated it, the newer token is adopted.
function shouldClearOnUnauthorized(stored, rejectedToken) {
  return !stored || stored.token === rejectedToken;
}

// The session this tab should use: the stored one if it differs from ours (another tab rotated or
// signed in), otherwise ours.
function preferStored(current, stored) {
  if (!stored) return current;
  if (!current || stored.token !== current.token) return stored;
  return current;
}

if (typeof module !== "undefined") {
  module.exports = {
    parseFragmentToken, shouldRotate, describeDiscovery, readSession, shouldClearOnUnauthorized, preferStored, STORAGE_KEY,
  };
}

// ---- browser-only code ------------------------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, String(v));
  }
  for (const c of children) if (c != null) el.append(c);
  return el;
}

function startApp() {
  const main = document.getElementById("main");
  const discoveryEl = document.getElementById("discovery");
  const signoutBtn = document.getElementById("signout");
  let session = readSession(window.localStorage);
  let lastKey = null;
  let timer = null;
  let rotating = null;

  const now = () => Math.floor(Date.now() / 1000);
  const show = (...nodes) => main.replaceChildren(...nodes);

  function saveSession(s) {
    session = { token: s.session_token, expires_at: s.expires_at, rotate_after: s.rotate_after };
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  }

  function clearSession() {
    session = null;
    window.localStorage.removeItem(STORAGE_KEY); // the storage event signs the other tabs out too
    if (timer) clearTimeout(timer);
    timer = null;
    lastKey = null;
    signoutBtn.hidden = true;
    discoveryEl.textContent = "";
  }

  function showUnauthenticated(message) {
    clearSession();
    show(
      h("section", { class: "state", "aria-labelledby": "t" },
        h("h2", { id: "t", text: "Not signed in" }),
        h("p", { text: message || "This page needs a sign-in link from the ccwm daemon." }),
        h("p", {}, "Run ", h("code", { text: "ccwm open" }), " in a terminal to sign in.")),
    );
  }

  async function rawFetch(path, opts = {}, token = session && session.token) {
    const headers = { Accept: "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(API + path, { method: opts.method || "GET", headers, body: opts.body, cache: "no-store", credentials: "omit" });
  }

  async function ensureFreshToken() {
    session = preferStored(session, readSession(window.localStorage)); // another tab may have rotated
    if (!shouldRotate(session, now())) return;
    if (!rotating) {
      rotating = rawFetch("/auth/rotate", { method: "POST" })
        .then(async (r) => { if (r.ok) saveSession(await r.json()); })
        .catch(() => {})
        .finally(() => { rotating = null; });
    }
    await rotating;
  }

  async function api(path, opts, retried = false) {
    await ensureFreshToken();
    const used = session && session.token;
    const r = await rawFetch(path, opts, used);
    if (r.status === 401) {
      const stored = readSession(window.localStorage);
      if (!retried && !shouldClearOnUnauthorized(stored, used)) {
        session = stored; // another tab holds a newer token: use it instead of signing everyone out
        return api(path, opts, true);
      }
      showUnauthenticated("Your session has expired or was revoked.");
      throw new Error("unauthenticated");
    }
    if (!r.ok) throw new Error(`request failed (${r.status})`);
    return r.status === 204 ? null : r.json();
  }

  async function loadAllProjects() {
    const items = [];
    let cursor = null;
    do {
      const qs = new URLSearchParams({ limit: String(PAGE_LIMIT) });
      if (cursor) qs.set("cursor", cursor);
      const page = await api(`/projects?${qs}`);
      items.push(...page.items);
      cursor = page.next_cursor;
    } while (cursor);
    return items;
  }

  function projectCard(p) {
    const sources = h("ul", { class: "badges", "aria-label": "Discovery sources" },
      ...p.sources.map((s) => h("li", { class: "badge", text: s })));
    return h("li", { class: "card" },
      h("h3", { text: p.name }),
      h("p", { class: "path", text: p.path }),
      sources,
      h("p", { class: "muted small", text: `First seen ${new Date(p.first_seen_at * 1000).toLocaleString()}` }));
  }

  function renderProjects(items, status) {
    if (items.length === 0) {
      const scanning = status && status.phase === "scanning";
      show(h("section", { class: "state", "aria-labelledby": "t" },
        h("h2", { id: "t", text: scanning ? "Looking for projects…" : "No projects found" }),
        h("p", { text: "A folder is a project when it contains a file named exactly CLAUDE.md (a symlink to a file inside the folder counts)." }),
        h("p", { text: "Hidden folders, node_modules, target, build, dist and similar generated folders are skipped, and symlinked folders are not followed." }),
        h("p", { text: `Searching: ${(status && status.roots && status.roots.length ? status.roots.map((r) => r.path) : ["your home folder"]).join(", ")}` })));
      return;
    }
    show(
      h("p", { class: "muted", text: `${items.length} project${items.length === 1 ? "" : "s"}` }),
      h("ul", { class: "cards" }, ...items.map(projectCard)));
  }

  async function refresh() {
    let status;
    try {
      status = await api("/discovery/status");
    } catch (e) {
      if (e.message === "unauthenticated") return;
      show(h("section", { class: "state", role: "alert" },
        h("h2", { text: "Cannot reach the ccwm daemon" }),
        h("p", { text: "It may have stopped. Retrying…" })));
      timer = setTimeout(refresh, POLL_SCANNING_MS * 3);
      return;
    }
    discoveryEl.textContent = describeDiscovery(status);
    const key = `${status.phase}:${status.projects_found}:${status.last_success_at}`;
    if (key !== lastKey) {
      try {
        renderProjects(await loadAllProjects(), status);
        lastKey = key;
      } catch (e) {
        if (e.message === "unauthenticated") return;
        show(h("section", { class: "state", role: "alert" },
          h("h2", { text: "Could not load projects" }),
          h("p", { text: e.message }),
          h("button", { type: "button", id: "retry", text: "Retry" })));
        document.getElementById("retry").addEventListener("click", () => { lastKey = null; refresh(); });
      }
    }
    timer = setTimeout(refresh, status.phase === "scanning" ? POLL_SCANNING_MS : POLL_IDLE_MS);
  }

  function start() {
    signoutBtn.hidden = false;
    show(h("p", { class: "muted", role: "status", text: "Loading…" }));
    refresh();
  }

  signoutBtn.addEventListener("click", async () => {
    try {
      await ensureFreshToken(); // an overdue token is accepted only for rotation
      await rawFetch("/auth/logout", { method: "POST" });
    } catch (_) { /* best effort */ }
    showUnauthenticated("You have signed out.");
  });

  // Keep tabs in step: adopt a token another tab rotated, follow sign-in and sign-out.
  window.addEventListener("storage", (e) => {
    if (e.key !== STORAGE_KEY && e.key !== null) return;
    const stored = readSession(window.localStorage);
    if (!stored) {
      if (session) showUnauthenticated("You were signed out in another tab.");
      return;
    }
    const wasSignedOut = !session;
    session = preferStored(session, stored);
    if (wasSignedOut) start();
  });

  const bootstrap = parseFragmentToken(window.location.hash);
  if (window.location.hash) {
    // Remove the single-use fragment from the address bar and history before doing anything else.
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  if (bootstrap) {
    show(h("p", { class: "muted", role: "status", text: "Signing in…" }));
    fetch(`${API}/auth/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ bootstrap_token: bootstrap }),
      cache: "no-store",
      credentials: "omit",
    })
      .then(async (r) => {
        if (!r.ok) throw new Error("expired");
        saveSession(await r.json());
        start();
      })
      .catch(() => showUnauthenticated("That sign-in link was invalid, already used, or expired."));
  } else if (session) {
    start();
  } else {
    showUnauthenticated();
  }
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startApp);
  else startApp();
}
