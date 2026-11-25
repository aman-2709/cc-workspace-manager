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

// `privacy` is null until this browser chose (then the Settings default applies).
const DEFAULT_PREFS = { view: "cards", theme: "system", privacy: null };

function readPrefs(storage) {
  try {
    const p = JSON.parse(storage.getItem(PREFS_KEY) || "{}") || {};
    return {
      view: p.view === "table" ? "table" : "cards",
      theme: ["light", "dark"].includes(p.theme) ? p.theme : "system",
      privacy: typeof p.privacy === "boolean" ? p.privacy : null,
    };
  } catch (_) {
    return { ...DEFAULT_PREFS };
  }
}

// The browser's choices win over the Settings defaults (`ui` of GET /settings).
function withServerDefaults(prefs, ui, stored) {
  const s = stored || {};
  const out = { ...prefs };
  if (!ui) return out;
  if (s.view === undefined && (ui.default_view === "table" || ui.default_view === "cards")) out.view = ui.default_view;
  if (s.theme === undefined && ["system", "light", "dark"].includes(ui.theme)) out.theme = ui.theme;
  if (typeof s.privacy !== "boolean" && typeof ui.privacy === "boolean") out.privacy = ui.privacy;
  return out;
}

const DEFAULT_QUERY = { q: "", sort: "activity", order: "desc", activity: "all", dirty: false, missing: false, ignored: false, sessions: false };

// The query string for the current search, sort and filters. Both views use exactly this.
// In privacy mode the server omits hidden fields and does not search them.
function buildQuery(state, limit, cursor, privacy) {
  const qs = new URLSearchParams();
  const q = (state.q || "").trim();
  if (q) qs.set("q", q);
  qs.set("sort", state.sort);
  qs.set("order", state.order);
  if (state.activity && state.activity !== "all") qs.set("activity", state.activity);
  if (state.dirty) qs.set("dirty", "1");
  if (state.missing) qs.set("include_missing", "1");
  if (state.ignored) qs.set("include_ignored", "1");
  if (state.sessions) qs.set("has_sessions", "1");
  if (privacy) qs.set("privacy", "1");
  qs.set("limit", String(limit));
  if (cursor) qs.set("cursor", cursor);
  return qs.toString();
}

// `?privacy=1` for the detail and status endpoints.
function privacySuffix(privacy, sep = "?") {
  return privacy ? `${sep}privacy=1` : "";
}

// One line about a project's Claude Code sessions (cards and table).
function sessionSummary(sessions, now) {
  if (!sessions || !sessions.count) return "No Claude Code session recorded";
  const latest = sessions.latest || {};
  const when = typeof latest.last_activity_at === "number" ? relativeTime(latest.last_activity_at, now) : "time unknown";
  const count = plural(sessions.count, "session");
  if (latest.title) return `${latest.title} · ${when} · ${count}`;
  if (latest.title_source) return `Latest session ${when} · ${count}`; // title hidden (privacy mode)
  return `Untitled session · ${when} · ${count}`;
}

const RESUME_WARNINGS = {
  claude_not_found: "The claude command was not found on the daemon's PATH.",
  claude_unverified: "The claude command could not be verified (it may still work).",
  resume_unsupported: "This claude version does not list --resume in its help.",
  cwd_missing: "The session's working folder no longer exists.",
  no_cwd: "The session recorded no working folder.",
  continuation_not_indexed: "This session was continued in another session that ccwm has not indexed.",
};

function resumeWarningText(code) {
  return RESUME_WARNINGS[code] || code;
}

// "2 h 5 min", "40 s"; "" when unknown.
function durationText(seconds) {
  if (typeof seconds !== "number" || seconds < 0) return "";
  if (seconds < 60) return `${seconds} s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
  return `${Math.floor(h / 24)} days`;
}

// Why no prompt text is shown.
function promptStateText(p, kind) {
  if (!p) return "";
  switch (p.state) {
    case "found": return "";
    case "hidden": return `The ${kind} is hidden in privacy mode.`;
    case "unreadable": return "The session file could not be read (it may have been deleted).";
    default: return p.whole_file === false
      ? `No ${kind} found in the part of the session file that was read (4 MiB).`
      : `No ${kind} recorded in this session.`;
  }
}

// Plain-language discovery scope for the Settings page.
function describeScope(settings) {
  if (!settings) return [];
  const e = settings.effective || {};
  const c = (settings.config && settings.config.discovery) || {};
  const roots = e.roots ? e.roots.join(", ") : "your discovery roots (hidden in privacy mode)";
  const skipped = [...(e.default_exclusions || []), ...(e.home_only_exclusions || []).map((n) => `${n} (directly in home)`)];
  const lines = [
    `Projects come from your Claude Code sessions (the folder each session started in, or the Git repository or CLAUDE.md folder around it) and from folders that contain a file named exactly CLAUDE.md.`,
    `ccwm looks in: ${roots}, up to ${e.max_depth} levels deep${e.same_file_system ? ", without crossing into other file systems" : ""}. Symlinked folders are not followed.`,
    `Always skipped: hidden folders (names starting with "."), ${skipped.join(", ")}.`,
  ];
  if (c.exclude && c.exclude.length) lines.push(`Also skipped (your exclusions): ${c.exclude.join(", ")}.`);
  lines.push(c.full_scan
    ? "CLAUDE.md files are searched in every root at every scan (\"Scan entire home\" is on)."
    : "After the first scan, CLAUDE.md files are searched only in the parent folders of projects found from sessions; turn on \"Scan entire home\" to search everywhere at every scan.");
  return lines;
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

// Settings form values -> the PUT /settings patch (numbers parsed; path lists one per line).
// `null` entries (e.g. hidden in privacy mode) are left out.
function settingsPatch(v) {
  const int = (x) => (x === "" || x == null ? undefined : Number(x));
  const lines = (t) => (t == null ? undefined : String(t).split("\n").map((l) => l.trim()).filter(Boolean));
  const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, x]) => x !== undefined));
  return {
    server: clean({ port: int(v.port) }),
    discovery: clean({
      roots: lines(v.roots), exclude: lines(v.exclude), scan_interval_secs: int(v.scan_interval_secs),
      missing_retention_days: int(v.missing_retention_days), max_depth: int(v.max_depth),
      full_scan: v.full_scan, same_file_system: v.same_file_system,
    }),
    watch: clean({ budget: int(v.budget) }),
    activity: clean({ inactive_after_days: int(v.inactive_after_days), dormant_after_days: int(v.dormant_after_days) }),
    sessions: clean({ store_prompt_text: v.store_prompt_text }),
    ui: clean({ default_view: v.default_view, theme: v.theme, privacy: v.ui_privacy }),
  };
}

if (typeof module !== "undefined") {
  module.exports = {
    parseFragmentToken, shouldRotate, describeDiscovery, readSession, shouldClearOnUnauthorized, preferStored,
    readPrefs, buildQuery, withView, withSort, relativeTime, gitSummary, paginate, reconnectDelay, wsUrl,
    plural, describeUnreadable, degradedSummary, truncatePath, calendarDaysAgo,
    withServerDefaults, privacySuffix, sessionSummary, resumeWarningText, durationText, promptStateText,
    describeScope, settingsPatch,
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
  const privacyBtn = document.getElementById("privacy");
  const settingsBtn = document.getElementById("settings-btn");
  const detailDlg = document.getElementById("detail");
  let session = readSession(window.localStorage);
  let prefs = readPrefs(window.localStorage);
  let page = "projects"; // or "settings"
  let detailFor = null; // the project shown in the detail dialog
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
  const priv = () => prefs.privacy === true;
  function applyPrivacy() {
    privacyBtn.setAttribute("aria-pressed", priv() ? "true" : "false");
    privacyBtn.textContent = priv() ? "Privacy: on" : "Privacy: off";
    const q = document.getElementById("q");
    if (q) q.placeholder = priv() ? "Search name or branch" : "Search name, path or branch";
  }
  applyTheme();
  applyPrivacy();
  themeSel.addEventListener("change", () => { prefs = { ...prefs, theme: themeSel.value }; savePrefs(); applyTheme(); });
  privacyBtn.addEventListener("click", () => {
    prefs = { ...prefs, privacy: !priv() };
    savePrefs();
    privacyChanged();
  });

  // Privacy mode changed (here or in another tab): every payload is refetched in the new mode.
  function privacyChanged() {
    applyPrivacy();
    if (ws && wsConnected) ws.send(JSON.stringify({ type: "privacy", on: priv() }));
    if (page === "settings") showSettings();
    else { reload(); }
    loadStatus();
    if (detailFor && detailDlg.open) openDetail(detailFor);
  }

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
    privacyBtn.hidden = true;
    settingsBtn.hidden = true;
    if (detailDlg.open) detailDlg.close();
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
      const got = await api(`/projects?${buildQuery(state, PAGE_LIMIT, cursor, priv())}`);
      all.push(...got.items);
      cursor = got.next_cursor;
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
    if (!shown) return h(tag, { class: "line path", text: "Path hidden (privacy mode)" });
    return h(tag, { class: "line path", title: p.path, "data-path": shown }, h("bdi", { text: shown }));
  }

  // Table action: fetch the latest session's resume command and copy it (absent in privacy mode
  // and for projects without sessions).
  function copyResumeButton(p) {
    if (priv() || !p.sessions || !p.sessions.count) return null;
    const btn = h("button", { type: "button", class: "link small", "aria-label": `Copy the resume command of ${p.name}`, text: "Copy resume" });
    btn.addEventListener("click", async () => {
      try {
        const s = await api(`/projects/${encodeURIComponent(p.id)}/sessions?limit=1`);
        const cmd = s.items[0] && s.items[0].resume && s.items[0].resume.command;
        if (!cmd) { btn.textContent = "No command"; return; }
        await navigator.clipboard.writeText(cmd);
        btn.textContent = "Copied";
      } catch (e) {
        if (e.message === "unauthenticated") return;
        btn.textContent = "Open details to copy";
      }
      setTimeout(() => { btn.textContent = "Copy resume"; }, 2000);
    });
    return btn;
  }

  function detailsButton(p) {
    return h("button", { type: "button", class: "link small", "aria-label": `Details of ${p.name}`, text: "Details",
      onclick: () => openDetail(p) });
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
      h("p", { class: "line small muted", title: sessionSummary(p.sessions, now()), text: sessionSummary(p.sessions, now()) }),
      h("div", { class: "foot" }, badges(p), detailsButton(p), ignoreButton(p)));
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
          sortHeader("Latest session", "session", "col-session"),
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
          h("td", {}, h("span", { class: "line", title: sessionSummary(p.sessions, now()), text: sessionSummary(p.sessions, now()) })),
          h("td", {}, h("span", { class: "actions" }, detailsButton(p), copyResumeButton(p), ignoreButton(p))))))));
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
      item(stats.total_sessions, "sessions"),
      stats.missing ? item(stats.missing, "missing") : null);
  }

  function buildToolbar() {
    const search = h("input", { type: "search", id: "q", placeholder: priv() ? "Search name or branch" : "Search name, path or branch", "aria-label": "Search projects", value: state.q });
    let searchTimer = null;
    search.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state = { ...state, q: search.value, page: 0 }; reload(); }, SEARCH_DEBOUNCE_MS);
    });
    const sort = h("select", { id: "sort", "aria-label": "Sort" },
      h("option", { value: "activity:desc", text: "Last change, newest first" }),
      h("option", { value: "activity:asc", text: "Last change, oldest first" }),
      h("option", { value: "commit:desc", text: "Latest commit, newest first" }),
      h("option", { value: "session:desc", text: "Latest session, newest first" }),
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
      check("sessions", "Has sessions", "sessions"),
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
    const filtered = (state.q || "").trim() || state.activity !== "all" || state.dirty || state.sessions;
    if (filtered) {
      return h("section", { class: "state" }, h("h2", { text: "No projects match" }),
        h("p", { text: "Change the search or the filters to see more projects." }));
    }
    return h("section", { class: "state", "aria-labelledby": "t" },
      h("h2", { id: "t", text: scanning ? "Looking for projects…" : "No projects found" }),
      h("p", { text: "A folder is a project when a Claude Code session was started in it (or in a folder inside its Git repository), or when it contains a file named exactly CLAUDE.md (a symlink to a file inside the folder counts)." }),
      h("p", { text: "Hidden folders, node_modules, target, build, dist and similar generated folders are skipped, and symlinked folders are not followed." }),
      h("p", { text: `Searching: ${(status && status.roots && status.roots.length && status.roots[0].path ? status.roots.map((r) => r.path) : ["your home folder"]).join(", ")}` }));
  }

  function renderContent() {
    if (page !== "projects") return;
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
    if (page !== "projects") return;
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
      status = await api(`/discovery/status${privacySuffix(priv())}`);
      showDiscovery();
      const svc = await api(`/service/status${privacySuffix(priv())}`);
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
      sock.send(JSON.stringify({ type: "auth", token: session.token, privacy: priv() }));
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

  // Settings defaults (view, theme, privacy) for choices this browser has not made yet. Fetched
  // in privacy mode, so nothing hidden is requested before the privacy default is known.
  async function applyServerDefaults() {
    let stored = {};
    try { stored = JSON.parse(window.localStorage.getItem(PREFS_KEY) || "{}") || {}; } catch (_) { stored = {}; }
    if (stored.view !== undefined && stored.theme !== undefined && typeof stored.privacy === "boolean") return;
    try {
      const st = await api("/settings?privacy=1");
      prefs = withServerDefaults(prefs, st.config && st.config.ui, stored);
      state = { ...state, view: prefs.view };
    } catch (e) {
      if (e.message === "unauthenticated") throw e;
      if (prefs.privacy === null) prefs = { ...prefs, privacy: true }; // unknown default: hide
    }
    applyTheme();
    applyPrivacy();
  }

  async function start() {
    signoutBtn.hidden = false;
    themeWrap.hidden = false;
    privacyBtn.hidden = false;
    settingsBtn.hidden = false;
    page = "projects";
    show(h("p", { class: "muted", role: "status", text: "Loading…" }));
    try { await applyServerDefaults(); } catch (_) { return; }
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
      if (page === "settings") showSettings(); else reload();
    } catch (e) {
      if (e.message !== "unauthenticated") showError("Could not change the project", e.message);
    }
  }

  // ---- detail panel -------------------------------------------------------------------------

  const when = (t) => (typeof t === "number" ? new Date(t * 1000).toLocaleString() : "unknown");
  const field = (label, value) => h("div", { class: "field" }, h("dt", { text: label }), h("dd", {}, value));

  function fileList(title, files, count) {
    if (!count) return null;
    const shown = files || [];
    return h("details", { class: "files" },
      h("summary", { text: `${title} (${count})` }),
      h("ul", {}, ...shown.map((f) => h("li", { class: "path", text: f }))),
      count > shown.length ? h("p", { class: "small muted", text: `… and ${count - shown.length} more` }) : null);
  }

  function promptBlock(label, p) {
    if (!p) return null;
    if (p.state !== "found") return field(label, h("span", { class: "muted", text: promptStateText(p, label.toLowerCase()) }));
    return field(label, h("div", {},
      h("pre", { class: "prompt", text: p.text }),
      h("p", { class: "small muted", text: `${p.at ? `${when(p.at)}. ` : ""}Read from the session file just now, redacted${p.truncated ? ", shortened to 2,000 characters" : ""}; not stored.` })));
  }

  async function copyText(input, button) {
    const text = input.value;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch (_) {
      input.focus();
      input.select();
      button.textContent = "Press Ctrl+C";
    }
    setTimeout(() => { button.textContent = "Copy"; }, 2000);
  }

  function resumeBlock(r) {
    if (!r) return null;
    const parts = [];
    if (r.command) {
      const input = h("input", { type: "text", readonly: true, class: "command", "aria-label": "Resume command", value: r.command });
      const copy = h("button", { type: "button", text: "Copy" });
      copy.addEventListener("click", () => copyText(input, copy));
      parts.push(h("div", { class: "copy-row" }, input, copy));
      parts.push(h("p", { class: "small muted", text: "ccwm only shows this command for you to copy; it never runs it." }));
    } else {
      parts.push(h("p", { class: "muted", text: priv() ? "Hidden in privacy mode." : "No resume command: the session has no valid id or working folder." }));
    }
    if (r.via_continuation) parts.push(h("p", { class: "small", text: `This session was continued in a later one; the command resumes that session (${r.session_id}).` }));
    if (r.warnings && r.warnings.length) {
      parts.push(h("ul", { class: "warnings" }, ...r.warnings.map((w) => h("li", { text: resumeWarningText(w) }))));
    }
    return field("Resume", h("div", {}, ...parts));
  }

  function detailView(d, s) {
    const g = d.git;
    const gd = d.git_detail || {};
    const head = gd.head;
    const files = gd.files || {};
    const latest = s.items[0];
    const close = h("button", { type: "button", class: "close", "aria-label": "Close details", text: "Close" });
    close.addEventListener("click", () => detailDlg.close());
    const sections = [
      h("header", { class: "detail-head" }, h("h2", { id: "detail-title", text: d.name }), close),
      d.missing_since ? h("p", { class: "banner", text: `This project's folder was not found (missing since ${when(d.missing_since)}).` }) : null,
      h("section", {}, h("h3", { text: "Project" }), h("dl", {},
        field("Path", h("span", { class: "path", text: d.path || "Hidden in privacy mode" })),
        field("Found from", h("span", { text: d.sources.map((x) => (x === "session" ? "Claude Code sessions" : "CLAUDE.md")).join(" and ") })),
        field("Last change", timeEl(d.activity)))),
      h("section", {}, h("h3", { text: "Git" }), h("dl", {},
        field("Status", h("span", { class: g && g.dirty ? "dirty" : "", text: gitSummary(g) })),
        g && g.upstream ? field("Upstream", h("span", { text: `${g.upstream}${typeof g.ahead === "number" ? `, ${g.ahead} ahead, ${g.behind} behind` : ""}` })) : null,
        head ? field("Latest commit", h("span", { text: `${head.short} ${head.subject || ""} (${head.author ? `${head.author}, ` : ""}${when(head.time)})` })) : null,
        gd.remote_url ? field("Remote", h("span", { class: "path", text: gd.remote_url })) : null),
        fileList("Staged", files.staged, g && g.staged),
        fileList("Modified", files.modified, g && g.modified),
        fileList("Untracked", files.untracked, g && g.untracked)),
    ];
    if (!latest) {
      sections.push(h("section", {}, h("h3", { text: "Claude Code" }), h("p", { class: "muted", text: "No Claude Code session recorded for this project." })));
    } else {
      const title = latest.title
        ? h("span", {}, latest.title, h("span", { class: "small muted", text: " — AI title (recorded by Claude Code)" }))
        : h("span", { class: "muted", text: latest.title_source ? "Hidden in privacy mode" : "Untitled session" });
      sections.push(h("section", {}, h("h3", { text: "Latest session" }), h("dl", {},
        field("Title", title),
        field("Started", h("span", { text: when(latest.started_at) })),
        field("Last activity", h("span", { text: `${when(latest.last_activity_at)}${durationText(latest.duration_s) ? ` (${durationText(latest.duration_s)} after the start)` : ""}` })),
        field("Sessions", h("span", { text: String(s.total) })),
        latest.version ? field("Claude Code", h("span", { text: latest.version })) : null,
        latest.cwd_changed ? field("Note", h("span", { class: "small", text: "The session changed folder after it started; resume uses the first folder." })) : null,
        promptBlock("Last prompt", latest.last_prompt),
        latest.first_prompt ? promptBlock("First prompt", latest.first_prompt) : null,
        resumeBlock(latest.resume))));
    }
    return h("div", { class: "detail" }, ...sections);
  }

  async function openDetail(p) {
    detailFor = p;
    detailDlg.replaceChildren(h("p", { class: "muted", role: "status", text: "Loading…" }));
    if (!detailDlg.open) detailDlg.showModal();
    const id = encodeURIComponent(p.id);
    try {
      const [d, s] = await Promise.all([
        api(`/projects/${id}${privacySuffix(priv())}`),
        api(`/projects/${id}/sessions?limit=1${privacySuffix(priv(), "&")}`),
      ]);
      if (detailFor !== p) return;
      detailDlg.replaceChildren(detailView(d, s));
    } catch (e) {
      if (e.message === "unauthenticated") return;
      const close = h("button", { type: "button", text: "Close", onclick: () => detailDlg.close() });
      detailDlg.replaceChildren(h("p", { role: "alert", text: `Could not load the details: ${e.message}` }), close);
    }
  }
  detailDlg.addEventListener("close", () => { detailFor = null; });

  // ---- settings page ------------------------------------------------------------------------

  const RESTART_LABELS = {
    "server.port": "port", "discovery.roots": "roots", "discovery.exclude": "exclusions",
    "discovery.max_depth": "depth", "discovery.same_file_system": "same file system",
    "watch.budget": "watch budget", "watch.debounce_ms": "debounce", "activity.events_per_project": "events kept",
    "git.allow_unhardened_status": "unhardened Git status", "sessions.dir": "session folder",
  };

  function input(id, label, value, attrs = {}, restart = false) {
    const el = h("input", { id, ...attrs });
    if (attrs.type === "checkbox") el.checked = Boolean(value); else el.value = value == null ? "" : String(value);
    const text = `${label}${restart ? " (requires restart)" : ""}`;
    return attrs.type === "checkbox"
      ? h("label", { class: "inline", for: id }, el, text)
      : h("label", { class: "stack", for: id }, h("span", { text }), el);
  }

  function area(id, label, lines, hidden, hint) {
    const el = h("textarea", { id, rows: "3", spellcheck: "false", disabled: hidden });
    el.value = hidden ? "" : (lines || []).join("\n");
    if (hidden) el.placeholder = "Hidden in privacy mode";
    return h("label", { class: "stack", for: id }, h("span", { text: `${label} (requires restart)` }), el,
      h("span", { class: "small muted", text: hidden ? "Turn privacy mode off to see or change this." : hint }));
  }

  function settingsView(st) {
    const c = st.config;
    const hidden = priv();
    const msg = h("p", { role: "status", class: "small" });
    const restartNote = (keys) => (keys && keys.length
      ? `Saved. Takes effect after a restart of the daemon: ${keys.map((k) => RESTART_LABELS[k] || k).join(", ")}.`
      : "");
    msg.textContent = restartNote(st.restart_required);
    const form = h("form", { class: "settings", novalidate: true },
      h("fieldset", {}, h("legend", { text: "Discovery" }),
        h("ul", { class: "scope" }, ...describeScope(st).map((l) => h("li", { class: "small", text: l }))),
        area("s-roots", "Roots (one folder per line; empty = your home folder)", c.discovery.roots, hidden || c.discovery.roots === undefined,
          "Absolute paths. Folders outside the startup roots become readable only after a restart (sandbox)."),
        area("s-exclude", "Extra exclusions (gitignore syntax, one per line)", c.discovery.exclude, hidden || c.discovery.exclude === undefined, "Relative to each root, e.g. vendor/ or /archive."),
        input("s-full", "Scan entire home at every scan (otherwise only the folders around session projects, after the first scan)", c.discovery.full_scan, { type: "checkbox" }),
        input("s-interval", "Seconds between scans", c.discovery.scan_interval_secs, { type: "number", min: "60", max: "86400" }),
        input("s-retention", "Days before a missing project is forgotten", c.discovery.missing_retention_days, { type: "number", min: "1", max: "3650" }),
        input("s-depth", "Folder levels searched below a root", c.discovery.max_depth, { type: "number", min: "1", max: "64" }, true),
        input("s-samefs", "Stay on the root's file system", c.discovery.same_file_system, { type: "checkbox" }, true)),
      h("fieldset", {}, h("legend", { text: "Monitoring and activity" }),
        input("s-budget", "Watch budget (0 = automatic: 25 % of the kernel limit)", c.watch.budget, { type: "number", min: "0", max: "1048576" }, true),
        input("s-inactive", "Inactive after (calendar days)", c.activity.inactive_after_days, { type: "number", min: "1", max: "3649" }),
        input("s-dormant", "Dormant after (calendar days)", c.activity.dormant_after_days, { type: "number", min: "2", max: "3650" })),
      h("fieldset", {}, h("legend", { text: "Claude Code sessions" }),
        input("s-store", "Store prompt text (the last prompt, redacted, cached in ccwm's database; turning this off deletes it)", c.sessions.store_prompt_text, { type: "checkbox" }),
        clearIndexButton()),
      h("fieldset", {}, h("legend", { text: "Server and appearance" }),
        input("s-port", "Port on 127.0.0.1", c.server.port, { type: "number", min: "1024", max: "65535" }, true),
        h("label", { class: "stack", for: "s-view" }, h("span", { text: "Default view" }),
          select("s-view", c.ui.default_view, [["cards", "Cards"], ["table", "Table"]])),
        h("label", { class: "stack", for: "s-theme" }, h("span", { text: "Default theme" }),
          select("s-theme", c.ui.theme, [["system", "System"], ["light", "Light"], ["dark", "Dark"]])),
        input("s-privacy", "Privacy mode on by default (for browsers that have not chosen)", c.ui.privacy, { type: "checkbox" })),
      h("div", { class: "form-actions" }, h("button", { type: "submit", text: "Save" }), msg));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const val = (id) => form.querySelector(`#${id}`);
      const patch = settingsPatch({
        roots: hidden || val("s-roots").disabled ? null : val("s-roots").value,
        exclude: hidden || val("s-exclude").disabled ? null : val("s-exclude").value,
        full_scan: val("s-full").checked, scan_interval_secs: val("s-interval").value,
        missing_retention_days: val("s-retention").value, max_depth: val("s-depth").value,
        same_file_system: val("s-samefs").checked, budget: val("s-budget").value,
        inactive_after_days: val("s-inactive").value, dormant_after_days: val("s-dormant").value,
        store_prompt_text: val("s-store").checked, port: val("s-port").value,
        default_view: val("s-view").value, theme: val("s-theme").value, ui_privacy: val("s-privacy").checked,
      });
      msg.textContent = "Saving…";
      try {
        const r = await rawSettingsPut(patch);
        msg.textContent = restartNote(r.restart_required) || "Saved.";
      } catch (e) {
        if (e.message !== "unauthenticated") msg.textContent = `Not saved: ${e.message}`;
      }
    });
    const ignored = h("section", {}, h("h3", { text: "Ignored projects" }),
      st.ignored.length
        ? h("ul", { class: "ignored" }, ...st.ignored.map((p) => h("li", {},
          h("span", { text: p.name }), p.display_path ? h("span", { class: "path small", text: ` ${p.display_path}` }) : null, " ",
          h("button", { type: "button", class: "link small", text: "Un-ignore", onclick: () => setIgnored({ id: p.id, name: p.name, ignored: true }, false) }))))
        : h("p", { class: "muted small", text: "No project is ignored." }));
    const back = h("button", { type: "button", text: "Back to projects", onclick: () => showProjects() });
    return h("section", { class: "settings-page", "aria-labelledby": "settings-title" },
      h("div", { class: "detail-head" }, h("h2", { id: "settings-title", text: "Settings" }), back),
      h("p", { class: "small muted", text: "Saved to config.toml (comments there are not kept). Changes marked \"requires restart\" apply when the daemon restarts." }),
      form, ignored);
  }

  function select(id, value, options) {
    const el = h("select", { id }, ...options.map(([v, t]) => h("option", { value: v, text: t })));
    el.value = value;
    return el;
  }

  function clearIndexButton() {
    const note = h("span", { class: "small muted", role: "status" });
    const btn = h("button", { type: "button", text: "Clear session index" });
    let armed = false;
    btn.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        btn.textContent = "Click again to clear";
        note.textContent = "Deletes ccwm's derived session data only; your Claude Code files are never touched.";
        setTimeout(() => { armed = false; btn.textContent = "Clear session index"; }, 5000);
        return;
      }
      armed = false;
      btn.textContent = "Clear session index";
      try {
        await api("/session-index/clear", { method: "POST" });
        note.textContent = "Cleared. The index is rebuilt from the session files at the next scan.";
      } catch (e) {
        if (e.message !== "unauthenticated") note.textContent = `Not cleared: ${e.message}`;
      }
    });
    return h("div", { class: "inline" }, btn, note);
  }

  // PUT /settings: the server's validation message is shown as is.
  async function rawSettingsPut(patch) {
    await ensureFreshToken();
    const r = await rawFetch("/settings", { method: "PUT", body: JSON.stringify(patch) });
    if (r.status === 401) { showUnauthenticated("Your session has expired or was revoked."); throw new Error("unauthenticated"); }
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((body.error && body.error.message) || `request failed (${r.status})`);
    return body;
  }

  async function showSettings() {
    page = "settings";
    settingsBtn.setAttribute("aria-current", "page");
    show(h("p", { class: "muted", role: "status", text: "Loading settings…" }));
    try {
      const st = await api(`/settings${privacySuffix(priv())}`);
      if (page !== "settings") return;
      show(settingsView(st));
    } catch (e) {
      if (e.message !== "unauthenticated") show(h("p", { role: "alert", text: `Could not load the settings: ${e.message}` }));
    }
  }

  function showProjects() {
    page = "projects";
    settingsBtn.removeAttribute("aria-current");
    ui = null;
    renderContent();
    reload();
  }

  settingsBtn.addEventListener("click", () => (page === "settings" ? showProjects() : showSettings()));

  signoutBtn.addEventListener("click", async () => {
    try {
      await ensureFreshToken(); // an overdue token is accepted only for rotation
      await rawFetch("/auth/logout", { method: "POST" });
    } catch (_) { /* best effort */ }
    showUnauthenticated("You have signed out.");
  });

  // Keep tabs in step: adopt a token another tab rotated, follow sign-in and sign-out.
  window.addEventListener("storage", (e) => {
    if (e.key === PREFS_KEY) {
      const before = priv();
      prefs = readPrefs(window.localStorage);
      applyTheme();
      if (priv() !== before) privacyChanged();
      return;
    }
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
