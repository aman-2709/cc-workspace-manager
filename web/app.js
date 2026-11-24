// CC Workspace Manager: vanilla JS, no framework. Data reaches the DOM only via textContent and DOM APIs.
// (A repository test forbids HTML-string injection APIs in this directory.)
"use strict";

const STORAGE_KEY = "ccwm.session";
const PREFS_KEY = "ccwm.prefs";
const API = "/api/v1";
const PAGE_LIMIT = 200;
const TABLE_PAGE = 100;
const SEARCH_DEBOUNCE_MS = 250;
const REFETCH_DEBOUNCE_MS = 400;
const ROTATION_CHECK_MS = 10 * 60 * 1000;
const WS_CLOSE_UNAUTHORIZED = 4401;

// ---- pure helpers (unit-tested with `node --test tests/ui`) ------------------------------------

function parseFragmentToken(hash) {
  const m = /^#bt=([A-Za-z0-9_-]{43})$/.exec(hash || "");
  return m ? m[1] : null;
}

function shouldRotate(session, nowSeconds) {
  return Boolean(session) && typeof session.rotate_after === "number" && nowSeconds >= session.rotate_after;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// Folders the last scan counted as unreadable (permission, vanished, changed, other).
function unreadableCount(status) {
  const skipped = (status && status.skipped) || {};
  return (skipped.permission || 0) + (skipped.vanished || 0) + (skipped.changed || 0) + (skipped.other || 0);
}

function describeDiscovery(status) {
  if (!status) return "";
  if (status.phase === "scanning") {
    return `Scanning… ${plural(status.dirs_visited, "folder")} checked, ${plural(status.projects_found, "project")} found`;
  }
  const problems = unreadableCount(status);
  const last = status.last_success_at ? `Last scan ${new Date(status.last_success_at * 1000).toLocaleString()}` : "No completed scan yet";
  return problems > 0 ? `${last}, ${plural(problems, "folder")} could not be read` : last;
}

// The tooltip listing the unreadable folders ("" when there are none).
function describeUnreadable(status) {
  const total = unreadableCount(status);
  if (!total) return "";
  const listed = (status.unreadable || []).map((u) => `${u.path} (${u.reason})`);
  const more = total > listed.length ? [`… and ${total - listed.length} more`] : [];
  return [`Could not be read in the last scan:`, ...listed, ...more].join("\n");
}

// The one-line summary of the degraded-monitoring banner (details are behind a toggle).
function degradedSummary(m) {
  if (!m || !m.degraded) return "";
  const parts = [];
  if (m.watcher === "unavailable") parts.push("no inotify instance");
  if (m.partial_projects) parts.push(`${plural(m.partial_projects, "project")} partly watched`);
  if (m.polled_projects) parts.push(`${plural(m.polled_projects, "project")} checked only at each scan`);
  if (m.recovering_overflow) parts.push("catching up after lost file events");
  return `Monitoring is degraded${parts.length ? `: ${parts.join(", ")}` : ""}.`;
}

// The tail of `path` that fits in `max` characters, cut at a "/" boundary ("…/dev/project").
// The last component is always kept whole (CSS clips it if even that does not fit).
function truncatePath(path, max) {
  if (typeof path !== "string" || path.length <= max) return path;
  const parts = path.split("/");
  let tail = parts.pop();
  while (parts.length > 0) {
    const next = `${parts[parts.length - 1]}/${tail}`;
    if (`…/${next}`.length > max) break;
    tail = next;
    parts.pop();
  }
  return parts.length > 0 ? `…/${tail}` : tail;
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

const DEFAULT_PREFS = { view: "cards", theme: "system" };

function readPrefs(storage) {
  try {
    const p = JSON.parse(storage.getItem(PREFS_KEY) || "{}") || {};
    return {
      view: p.view === "table" ? "table" : "cards",
      theme: ["light", "dark"].includes(p.theme) ? p.theme : "system",
    };
  } catch (_) {
    return { ...DEFAULT_PREFS };
  }
}

const DEFAULT_QUERY = { q: "", sort: "activity", order: "desc", activity: "all", dirty: false, missing: false, ignored: false };

// The query string for the current search, sort and filters. Both views use exactly this.
function buildQuery(state, limit, cursor) {
  const qs = new URLSearchParams();
  const q = (state.q || "").trim();
  if (q) qs.set("q", q);
  qs.set("sort", state.sort);
  qs.set("order", state.order);
  if (state.activity && state.activity !== "all") qs.set("activity", state.activity);
  if (state.dirty) qs.set("dirty", "1");
  if (state.missing) qs.set("include_missing", "1");
  if (state.ignored) qs.set("include_ignored", "1");
  qs.set("limit", String(limit));
  if (cursor) qs.set("cursor", cursor);
  return qs.toString();
}

// Switching views keeps search, sort and filters; only the table page resets.
function withView(state, view) {
  return { ...state, view: view === "table" ? "table" : "cards", page: 0 };
}

// Clicking a column header: a new sort starts in its natural order, the same one flips it.
function withSort(state, sort) {
  if (state.sort === sort) return { ...state, order: state.order === "asc" ? "desc" : "asc", page: 0 };
  return { ...state, sort, order: sort === "name" ? "asc" : "desc", page: 0 };
}

// Local calendar days from `at` to `now` (browser time zone), never negative.
function calendarDaysAgo(at, now) {
  const day = (t) => {
    const d = new Date(t * 1000);
    return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) / 86400000;
  };
  return Math.max(0, Math.round(day(now) - day(at)));
}

// "N days ago" counts calendar days, exactly like the activity status: `daysAgo` comes from the
// server's classifier (the same calculation as the bucket); without it, local calendar days.
function relativeTime(at, now, daysAgo) {
  if (typeof at !== "number") return "unknown";
  const s = Math.max(0, now - at);
  const d = typeof daysAgo === "number" ? Math.max(0, daysAgo) : calendarDaysAgo(at, now);
  if (d === 0) {
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    return `${Math.floor(s / 3600)} h ago`;
  }
  if (d === 1) return "yesterday";
  if (d < 14) return `${d} days ago`;
  if (d < 60) return `${Math.floor(d / 7)} weeks ago`;
  return new Date(at * 1000).toLocaleDateString();
}

const STATUS_LABEL = { today: "Today", recent: "Recent", inactive: "Inactive", dormant: "Dormant", unknown: "Unknown" };

function gitSummary(git) {
  if (!git) return "Git not checked yet";
  switch (git.state) {
    case "not_git": return "Not a Git repository";
    case "git_missing": return "Git is not installed";
    case "unsafe_repository": return "Git refused this repository (safe.directory)";
    case "status_disabled_old_git": return `${git.branch || "?"}: status disabled, Git too old to harden`;
    case "status_disabled_unsafe_config": return `${git.branch || "?"}: status disabled, unsafe filter configuration`;
    case "partial_clone": return git.branch ? `${git.branch}: Git status unavailable (partial clone)` : "Git status unavailable (partial clone)";
    case "timeout": return "Git timed out";
    case "error": return "Git could not read this repository";
    default: break;
  }
  const where = git.detached ? "detached HEAD" : (git.branch || "no branch");
  const parts = [];
  if (git.staged) parts.push(`${git.staged} staged`);
  if (git.modified) parts.push(`${git.modified} modified`);
  if (git.untracked) parts.push(`${git.untracked} untracked`);
  if (git.ahead) parts.push(`${git.ahead} ahead`);
  if (git.behind) parts.push(`${git.behind} behind`);
  return parts.length ? `${where}: ${parts.join(", ")}` : `${where}: clean`;
}

function paginate(items, page, size) {
  const pages = Math.max(1, Math.ceil(items.length / size));
  const p = Math.min(Math.max(0, page), pages - 1);
  return { rows: items.slice(p * size, (p + 1) * size), page: p, pages };
}

// Exponential back-off for reconnecting: 1 s, 2 s, 4 s … at most 30 s.
function reconnectDelay(attempt) {
  return Math.min(30000, 1000 * 2 ** Math.min(Math.max(0, attempt), 5));
}

function wsUrl(loc) {
  return `ws://${loc.host}${API}/ws`;
}

if (typeof module !== "undefined") {
  module.exports = {
    parseFragmentToken, shouldRotate, describeDiscovery, readSession, shouldClearOnUnauthorized, preferStored,
    readPrefs, buildQuery, withView, withSort, relativeTime, gitSummary, paginate, reconnectDelay, wsUrl,
    plural, describeUnreadable, degradedSummary, truncatePath, calendarDaysAgo,
    STORAGE_KEY, PREFS_KEY, DEFAULT_QUERY,
  };
}

// ---- browser-only code ------------------------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, String(v));
  }
  for (const c of children) if (c != null) el.append(c);
  return el;
}

function startApp() {
  const main = document.getElementById("main");
  const discoveryEl = document.getElementById("discovery");
  const bannersEl = document.getElementById("banners");
  const signoutBtn = document.getElementById("signout");
  const themeWrap = document.getElementById("theme-wrap");
  const themeSel = document.getElementById("theme");
  let session = readSession(window.localStorage);
  let prefs = readPrefs(window.localStorage);
  let state = { ...DEFAULT_QUERY, view: prefs.view, page: 0 };
  let items = [];
  let stats = null;
  let status = null;
  let monitoring = null;
  let rotating = null;
  let ws = null;
  let wsAttempt = 0;
  let wsTimer = null;
  let wsConnected = false;
  let refetchTimer = null;
  let rotationTimer = null;
  let loadSeq = 0;
  let ui = null; // the rendered toolbar/stats/content containers

  const now = () => Math.floor(Date.now() / 1000);
  const show = (...nodes) => { ui = null; main.replaceChildren(...nodes); };

  function applyTheme() {
    if (prefs.theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", prefs.theme);
    themeSel.value = prefs.theme;
  }
  function savePrefs() { window.localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); }
  applyTheme();
  themeSel.addEventListener("change", () => { prefs = { ...prefs, theme: themeSel.value }; savePrefs(); applyTheme(); });

  function saveSession(s) {
    session = { token: s.session_token, expires_at: s.expires_at, rotate_after: s.rotate_after };
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    reconnectSoon(0); // the socket is bound to a token: rebind it to the new one
  }

  function stopLive() {
    if (ws) { const w = ws; ws = null; w.onclose = null; w.close(); }
    clearTimeout(wsTimer); clearTimeout(refetchTimer); clearInterval(rotationTimer);
    wsConnected = false;
  }

  function clearSession() {
    session = null;
    window.localStorage.removeItem(STORAGE_KEY); // the storage event signs the other tabs out too
    stopLive();
    signoutBtn.hidden = true;
    themeWrap.hidden = true;
    discoveryEl.textContent = "";
    for (const a of ["title", "tabindex", "aria-description"]) discoveryEl.removeAttribute(a);
    bannersEl.replaceChildren();
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

  async function loadAll() {
    const all = [];
    let cursor = null;
    do {
      const page = await api(`/projects?${buildQuery(state, PAGE_LIMIT, cursor)}`);
      all.push(...page.items);
      cursor = page.next_cursor;
    } while (cursor);
    return all;
  }

  // ---- rendering ----------------------------------------------------------------------------

  function timeEl(activity) {
    const { at, kind } = activity;
    if (typeof at !== "number") return h("span", { text: "Last change unknown" });
    const exact = new Date(at * 1000).toLocaleString();
    const how = kind === "observed" ? "observed" : "inferred from file times";
    return h("time", {
      datetime: new Date(at * 1000).toISOString(), title: `${exact} (${how})`, tabindex: "0",
      "aria-label": `Last change ${exact}, ${how}`, text: `${relativeTime(at, now(), activity.days_ago)}${kind === "inferred" ? " (inferred)" : ""}`,
    });
  }

  // The visible text is fitted to the element's width by `fitPaths` (cut at a "/").
  function pathEl(p, tag = "p") {
    const shown = p.display_path || p.path;
    return h(tag, { class: "line path", title: p.path, "data-path": shown }, h("bdi", { text: shown }));
  }

  // Shorten every path in `root` to what fits, at a "/" boundary. The paths are monospace, so
  // one character width (measured once) gives the number of characters that fit.
  function fitPaths(root) {
    const els = root.querySelectorAll("[data-path]");
    if (els.length === 0) return;
    const probe = h("span", { class: "path probe", text: "0".repeat(32) });
    root.append(probe);
    const charWidth = probe.getBoundingClientRect().width / 32;
    probe.remove();
    for (const el of els) {
      const max = charWidth > 0 ? Math.max(1, Math.floor(el.clientWidth / charWidth)) : Infinity;
      el.firstChild.textContent = truncatePath(el.dataset.path, max);
    }
  }

  function ignoreButton(p) {
    return h("button", {
      type: "button", class: "link small",
      "aria-label": `${p.ignored ? "Stop ignoring" : "Ignore"} ${p.name}`,
      text: p.ignored ? "Un-ignore" : "Ignore",
      onclick: () => setIgnored(p, !p.ignored),
    });
  }

  function badges(p) {
    const list = [...p.sources.map((s) => h("li", { class: "badge", text: s }))];
    if (p.missing_since) list.push(h("li", { class: "badge warn", text: "missing" }));
    if (p.ignored) list.push(h("li", { class: "badge warn", text: "ignored" }));
    if (p.monitoring === "polled") list.push(h("li", { class: "badge warn", text: "polled", title: "Changes are found at the next scan, not live" }));
    if (p.monitoring === "partial") list.push(h("li", { class: "badge warn", text: "partly watched", title: "Some folders have no watch: changes there are found at the next scan" }));
    return h("ul", { class: "badges", "aria-label": "Details" }, ...list);
  }

  function card(p) {
    const status = p.activity.status;
    const git = p.git;
    const commit = git && git.commit;
    return h("li", { class: `card${p.missing_since ? " missing" : ""}`, "data-status": status },
      h("div", { class: "head" },
        h("h3", { class: "line", title: p.name, text: p.name }),
        h("span", { class: "small muted", text: STATUS_LABEL[status] || status })),
      pathEl(p),
      h("p", { class: "line small" }, timeEl(p.activity),
        p.activity.path ? h("span", { class: "muted", text: `, ${p.activity.path}` }) : null),
      ...(git && git.state === "not_git"
        ? [h("p", { class: "line small muted", text: gitSummary(git) })] // one line: nothing else to say
        : [
          h("p", { class: `line small${git && git.dirty ? " dirty" : ""}`, text: gitSummary(git) }),
          h("p", { class: "line small muted", title: commit && commit.subject ? commit.subject : "",
            text: commit && commit.subject ? `Latest commit: ${commit.subject}` : "No commit recorded" }),
        ]),
      h("div", { class: "foot" }, badges(p), ignoreButton(p)));
  }

  function sortHeader(label, sort, cls) {
    const current = state.sort === sort;
    const arrow = current ? (state.order === "asc" ? " ▲" : " ▼") : "";
    return h("th", { class: cls, scope: "col", "aria-sort": current ? (state.order === "asc" ? "ascending" : "descending") : "none" },
      h("button", { type: "button", "aria-current": current ? "true" : false, text: label + arrow,
        onclick: () => { state = withSort(state, sort); syncToolbar(); reload(); } }));
  }

  function table(rows) {
    return h("div", { class: "table-wrap" },
      h("table", {},
        h("thead", {}, h("tr", {},
          sortHeader("Name", "name", "col-name"),
          h("th", { class: "col-path", scope: "col", text: "Path" }),
          sortHeader("Last change", "activity", "col-mod"),
          h("th", { class: "col-status", scope: "col", text: "Activity" }),
          h("th", { class: "col-git", scope: "col", text: "Git" }),
          sortHeader("Latest commit", "commit", "col-commit"),
          h("th", { class: "col-act", scope: "col" }, h("span", { class: "sr-only", text: "Actions" })))),
        h("tbody", {}, ...rows.map((p) => h("tr", {},
          h("td", {}, h("span", { class: "line", title: p.name, text: p.name })),
          h("td", {}, pathEl(p, "span")),
          h("td", {}, h("span", { class: "line" }, timeEl(p.activity))),
          h("td", {}, h("span", { class: "line" }, h("span", { class: "dot", "data-status": p.activity.status }),
            STATUS_LABEL[p.activity.status] || p.activity.status)),
          h("td", {}, h("span", { class: `line${p.git && p.git.dirty ? " dirty" : ""}`, title: gitSummary(p.git), text: gitSummary(p.git) })),
          h("td", {}, h("span", { class: "line", title: (p.git && p.git.commit && p.git.commit.subject) || "",
            text: (p.git && p.git.commit && p.git.commit.subject) || "None" })),
          h("td", {}, ignoreButton(p)))))));
  }

  function statsList() {
    if (!stats) return h("ul", { class: "stats" });
    const item = (n, label) => h("li", {}, h("strong", { text: String(n) }), h("span", { class: "muted small", text: label }));
    return h("ul", { class: "stats", "aria-label": "Summary" },
      item(stats.total_projects, "projects"),
      item(stats.modified_today, "changed today"),
      item(stats.modified_this_week, "this week"),
      item(stats.inactive, "inactive"),
      item(stats.dormant, "dormant"),
      item(stats.uncommitted_changes, "with uncommitted changes"),
      stats.missing ? item(stats.missing, "missing") : null);
  }

  function buildToolbar() {
    const search = h("input", { type: "search", id: "q", placeholder: "Search name, path or branch", "aria-label": "Search projects", value: state.q });
    let searchTimer = null;
    search.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state = { ...state, q: search.value, page: 0 }; reload(); }, SEARCH_DEBOUNCE_MS);
    });
    const sort = h("select", { id: "sort", "aria-label": "Sort" },
      h("option", { value: "activity:desc", text: "Last change, newest first" }),
      h("option", { value: "activity:asc", text: "Last change, oldest first" }),
      h("option", { value: "commit:desc", text: "Latest commit, newest first" }),
      h("option", { value: "name:asc", text: "Name, A to Z" }),
      h("option", { value: "name:desc", text: "Name, Z to A" }));
    sort.addEventListener("change", () => {
      const [s, o] = sort.value.split(":");
      state = { ...state, sort: s, order: o, page: 0 };
      reload();
    });
    const activity = h("select", { id: "activity", "aria-label": "Activity" },
      ...[["all", "All activity"], ["today", "Changed today"], ["week", "This week"], ["inactive", "Inactive"], ["dormant", "Dormant"], ["unknown", "Unknown"]]
        .map(([v, t]) => h("option", { value: v, text: t })));
    activity.addEventListener("change", () => { state = { ...state, activity: activity.value, page: 0 }; reload(); });
    const check = (id, label, key) => {
      const box = h("input", { type: "checkbox", id });
      box.checked = state[key];
      box.addEventListener("change", () => { state = { ...state, [key]: box.checked, page: 0 }; reload(); });
      return h("label", { class: "inline small", for: id }, box, label);
    };
    const viewBtn = (v, label) => h("button", { type: "button", "aria-pressed": state.view === v ? "true" : "false", "data-view": v, text: label,
      onclick: () => {
        state = withView(state, v);
        prefs = { ...prefs, view: state.view }; savePrefs();
        syncToolbar(); renderContent();
      } });
    const refresh = h("button", { type: "button", id: "refresh", text: "Scan now",
      onclick: async () => {
        refresh.disabled = true;
        try { await api("/refresh", { method: "POST" }); } catch (_) { /* reported by the status line */ }
        setTimeout(() => { refresh.disabled = false; }, 2000);
      } });
    return h("div", { class: "toolbar", role: "search" },
      search, sort, activity,
      check("dirty", "Uncommitted changes", "dirty"),
      check("missing", "Show missing", "missing"),
      check("ignored", "Show ignored", "ignored"),
      h("span", { class: "group", role: "group", "aria-label": "View" }, viewBtn("cards", "Cards"), viewBtn("table", "Table")),
      refresh);
  }

  function syncToolbar() {
    if (!ui) return;
    const sort = ui.toolbar.querySelector("#sort");
    const key = `${state.sort}:${state.order}`;
    if ([...sort.options].some((o) => o.value === key)) sort.value = key;
    ui.toolbar.querySelector("#activity").value = state.activity;
    for (const b of ui.toolbar.querySelectorAll("[data-view]")) b.setAttribute("aria-pressed", b.dataset.view === state.view ? "true" : "false");
  }

  function ensureLayout() {
    if (ui) return;
    const toolbar = buildToolbar();
    const summary = h("div", {});
    const content = h("div", { id: "content" });
    main.replaceChildren(summary, toolbar, content);
    ui = { toolbar, summary, content };
    if (typeof ResizeObserver === "function") {
      let frame = 0;
      new ResizeObserver(() => {
        cancelAnimationFrame(frame);
        frame = requestAnimationFrame(() => fitPaths(content));
      }).observe(content);
    }
    syncToolbar();
  }

  function showDiscovery() {
    discoveryEl.textContent = describeDiscovery(status);
    const tip = describeUnreadable(status);
    if (tip) {
      discoveryEl.title = tip;
      discoveryEl.tabIndex = 0; // focusable, so the list is reachable without a mouse
      discoveryEl.setAttribute("aria-description", tip);
    } else {
      discoveryEl.removeAttribute("title");
      discoveryEl.removeAttribute("tabindex");
      discoveryEl.removeAttribute("aria-description");
    }
  }

  function renderStats() {
    if (ui) ui.summary.replaceChildren(statsList());
  }

  function emptyState() {
    const scanning = status && status.phase === "scanning";
    const filtered = (state.q || "").trim() || state.activity !== "all" || state.dirty;
    if (filtered) {
      return h("section", { class: "state" }, h("h2", { text: "No projects match" }),
        h("p", { text: "Change the search or the filters to see more projects." }));
    }
    return h("section", { class: "state", "aria-labelledby": "t" },
      h("h2", { id: "t", text: scanning ? "Looking for projects…" : "No projects found" }),
      h("p", { text: "A folder is a project when it contains a file named exactly CLAUDE.md (a symlink to a file inside the folder counts)." }),
      h("p", { text: "Hidden folders, node_modules, target, build, dist and similar generated folders are skipped, and symlinked folders are not followed." }),
      h("p", { text: `Searching: ${(status && status.roots && status.roots.length ? status.roots.map((r) => r.path) : ["your home folder"]).join(", ")}` }));
  }

  function renderContent() {
    ensureLayout();
    renderStats();
    if (items.length === 0) {
      ui.content.replaceChildren(emptyState());
      return;
    }
    const count = h("p", { class: "muted small", text: `${items.length} project${items.length === 1 ? "" : "s"}` });
    if (state.view === "table") {
      const pg = paginate(items, state.page, TABLE_PAGE);
      state = { ...state, page: pg.page };
      const pager = pg.pages > 1 ? h("nav", { class: "pager", "aria-label": "Pages" },
        h("button", { type: "button", text: "Previous", disabled: pg.page === 0, onclick: () => { state = { ...state, page: pg.page - 1 }; renderContent(); } }),
        h("span", { class: "small", text: `Page ${pg.page + 1} of ${pg.pages}` }),
        h("button", { type: "button", text: "Next", disabled: pg.page >= pg.pages - 1, onclick: () => { state = { ...state, page: pg.page + 1 }; renderContent(); } })) : null;
      ui.content.replaceChildren(count, table(pg.rows), pager || "");
    } else {
      ui.content.replaceChildren(count, h("ul", { class: "cards" }, ...items.map(card)));
    }
    fitPaths(ui.content);
  }

  function renderBanners() {
    const list = [];
    if (session && !wsConnected) {
      list.push(h("div", { class: "banner", role: "status" },
        h("p", { text: "Live updates are disconnected. Reconnecting…" })));
    }
    if (monitoring && monitoring.degraded) {
      // One line; the advice is behind a native disclosure toggle (keyboard accessible).
      list.push(h("details", { class: "banner" }, // #banners is aria-live already
        h("summary", {}, degradedSummary(monitoring), h("span", { class: "small muted", text: " Details" })),
        ...(monitoring.advice || []).map((a) => h("p", { class: "small", text: a }))));
    }
    bannersEl.replaceChildren(...list);
  }

  function showError(title, message) {
    ensureLayout();
    ui.content.replaceChildren(h("section", { class: "state", role: "alert" },
      h("h2", { text: title }), h("p", { text: message }),
      h("button", { type: "button", text: "Retry", onclick: () => reload() })));
  }

  // ---- data loading ---------------------------------------------------------------------------

  async function reload() {
    const seq = ++loadSeq;
    try {
      const [list, st] = await Promise.all([loadAll(), api("/stats")]);
      if (seq !== loadSeq) return; // a newer request superseded this one
      items = list;
      stats = st;
      renderContent();
    } catch (e) {
      if (e.message === "unauthenticated" || seq !== loadSeq) return;
      showError("Could not load projects", e.message);
    }
  }

  function scheduleRefetch() {
    clearTimeout(refetchTimer);
    refetchTimer = setTimeout(reload, REFETCH_DEBOUNCE_MS);
  }

  async function loadStatus() {
    try {
      status = await api("/discovery/status");
      showDiscovery();
      const svc = await api("/service/status");
      monitoring = svc.monitoring;
      renderBanners();
    } catch (_) { /* the socket or the next reload reports problems */ }
  }

  // ---- live updates ---------------------------------------------------------------------------

  function reconnectSoon(delay) {
    if (!session) return;
    clearTimeout(wsTimer);
    if (ws) { const w = ws; ws = null; w.onclose = null; w.close(); }
    wsConnected = false;
    wsTimer = setTimeout(connect, delay);
  }

  function connect() {
    if (!session) return;
    if (ws) { const w = ws; ws = null; w.onclose = null; w.close(); } // one socket per tab, always
    const sock = new WebSocket(wsUrl(window.location));
    ws = sock;
    sock.onopen = async () => {
      await ensureFreshToken();
      if (ws !== sock || !session) return;
      sock.send(JSON.stringify({ type: "auth", token: session.token }));
    };
    sock.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (_) { return; }
      switch (msg.type) {
        case "ready":
          wsAttempt = 0;
          wsConnected = true;
          renderBanners();
          reload(); // a fresh snapshot after every (re)connect
          loadStatus();
          break;
        case "project":
        case "project_removed":
        case "resync":
          scheduleRefetch();
          break;
        case "stats":
          stats = msg.stats;
          renderStats();
          break;
        case "discovery":
          status = msg.status;
          showDiscovery();
          break;
        case "monitoring":
          monitoring = msg.monitoring;
          renderBanners();
          break;
        default: break;
      }
    };
    sock.onclose = async (ev) => {
      if (ws !== sock) return;
      ws = null;
      wsConnected = false;
      renderBanners();
      if (ev.code === WS_CLOSE_UNAUTHORIZED) {
        // Rotated out or revoked: an API call tells which (a 401 signs this tab out).
        try { await api("/stats"); } catch (_) { return; }
      }
      wsTimer = setTimeout(connect, reconnectDelay(wsAttempt++));
    };
  }

  function start() {
    signoutBtn.hidden = false;
    themeWrap.hidden = false;
    show(h("p", { class: "muted", role: "status", text: "Loading…" }));
    reload();
    loadStatus();
    reconnectSoon(0);
    renderBanners();
    clearInterval(rotationTimer);
    rotationTimer = setInterval(() => { ensureFreshToken(); }, ROTATION_CHECK_MS);
  }

  async function setIgnored(p, ignored) {
    try {
      await api(`/projects/${encodeURIComponent(p.id)}/ignore`, { method: ignored ? "PUT" : "DELETE" });
      reload();
    } catch (e) {
      if (e.message !== "unauthenticated") showError("Could not change the project", e.message);
    }
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
    if (e.key === PREFS_KEY) { prefs = readPrefs(window.localStorage); applyTheme(); return; }
    if (e.key !== STORAGE_KEY && e.key !== null) return;
    const stored = readSession(window.localStorage);
    if (!stored) {
      if (session) showUnauthenticated("You were signed out in another tab.");
      return;
    }
    const wasSignedOut = !session;
    const changed = !session || stored.token !== session.token;
    session = preferStored(session, stored);
    if (wasSignedOut) start();
    else if (changed) reconnectSoon(0);
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
