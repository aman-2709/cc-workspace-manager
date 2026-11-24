-- M2: activity tracking, missing state, ignore, Git cache.

-- SHA-256 of the CLAUDE.md content (bounded read), used to recognise a moved non-Git project.
ALTER TABLE projects ADD COLUMN marker_hash BLOB CHECK (marker_hash IS NULL OR length(marker_hash) = 32);
-- When a project was last not found; NULL = present. Purged after the retention period.
ALTER TABLE projects ADD COLUMN missing_since INTEGER;
-- Latest meaningful modification (Unix seconds), how it was learned, and the file (relative path).
ALTER TABLE projects ADD COLUMN activity_at INTEGER;
ALTER TABLE projects ADD COLUMN activity_kind TEXT CHECK (activity_kind IN ('inferred', 'observed'));
ALTER TABLE projects ADD COLUMN activity_path TEXT;
CREATE INDEX projects_activity ON projects (activity_at, sort_key, id);
CREATE INDEX projects_missing ON projects (missing_since);

-- Ignored projects, by canonical path (§4.5): the project row stays, hidden from lists.
CREATE TABLE ignored_paths (
  canonical_path TEXT PRIMARY KEY,
  ignored_at     INTEGER NOT NULL
) WITHOUT ROWID;

-- Bounded list of recent file events per project (activity.events_per_project).
CREATE TABLE file_events (
  id         INTEGER PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  at         INTEGER NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN ('create', 'modify', 'delete', 'rename')),
  path       TEXT NOT NULL
);
CREATE INDEX file_events_project ON file_events (project_id, id);

-- Last Git inspection per project. NULL counts mean "status not run" (unknown, never 0).
CREATE TABLE git_cache (
  project_id   TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  fetched_at   INTEGER NOT NULL,
  state        TEXT NOT NULL,
  branch       TEXT,
  detached     INTEGER NOT NULL DEFAULT 0,
  upstream     TEXT,
  ahead        INTEGER,
  behind       INTEGER,
  staged       INTEGER,
  modified     INTEGER,
  untracked    INTEGER,
  files        TEXT,     -- JSON {"staged":[…],"modified":[…],"untracked":[…]}, each capped at 200
  head_commit  TEXT,
  head_subject TEXT,
  head_author  TEXT,
  head_time    INTEGER,
  remote_url   TEXT      -- sanitized: no credentials
) WITHOUT ROWID;
CREATE INDEX git_cache_head_time ON git_cache (head_time);
CREATE INDEX git_cache_head_commit ON git_cache (head_commit);
