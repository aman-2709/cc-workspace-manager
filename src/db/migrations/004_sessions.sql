-- M3: Claude Code session index (REQUIREMENTS.md §7, §14). Aggregates only: no transcript, no
-- assistant text, no tool input or output. Prompt text only in `prompt_text`, and only while the
-- opt-in "Store prompt text" setting is on (redacted).
CREATE TABLE sessions (
  id               TEXT PRIMARY KEY CHECK (length(id) = 36),
  -- NULL: unassigned (see `unassigned`) or not resolved yet / its project was purged.
  project_id       TEXT REFERENCES projects(id) ON DELETE SET NULL,
  file_path        TEXT NOT NULL UNIQUE,
  first_cwd        TEXT,
  last_cwd         TEXT,
  started_at       INTEGER,   -- minimum conversational timestamp
  last_activity_at INTEGER,   -- maximum conversational timestamp
  title            TEXT,      -- latest ai-title, redacted
  git_branch       TEXT,
  version          TEXT,
  entrypoint       TEXT,
  continued_in     TEXT CHECK (continued_in IS NULL OR length(continued_in) = 36),
  derived_from     TEXT,      -- JSON array of session ids
  is_sidechain     INTEGER NOT NULL DEFAULT 0,
  unassigned       TEXT,      -- why the cwd names no project (home, temporary, nonexistent, …)
  prompt_text      TEXT,      -- opt-in cache of the last prompt (redacted, truncated)
  prompt_at        INTEGER
) WITHOUT ROWID;
CREATE INDEX sessions_project ON sessions (project_id, last_activity_at);

-- Incremental parsing (§7.2): identity, size and mtime of the file, and the byte offset just
-- after the last complete line; plus the line counters since the last reset.
CREATE TABLE session_file_checkpoints (
  session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
  dev        INTEGER NOT NULL,
  ino        INTEGER NOT NULL,
  size       INTEGER NOT NULL,
  offset     INTEGER NOT NULL,
  mtime_ns   INTEGER NOT NULL,
  lines      INTEGER NOT NULL DEFAULT 0,
  malformed  INTEGER NOT NULL DEFAULT 0,
  oversized  INTEGER NOT NULL DEFAULT 0,
  unknown    INTEGER NOT NULL DEFAULT 0,
  foreign_id INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- Per-project session summary, maintained by the writer whenever sessions change (sort/filter).
ALTER TABLE projects ADD COLUMN session_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE projects ADD COLUMN session_at INTEGER;
CREATE INDEX projects_session ON projects (session_at, sort_key, id);
