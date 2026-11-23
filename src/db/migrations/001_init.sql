CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE projects (
  id             TEXT PRIMARY KEY CHECK (length(id) = 32),
  canonical_path TEXT NOT NULL UNIQUE,
  name           TEXT NOT NULL,
  first_seen_at  INTEGER NOT NULL,
  last_seen_at   INTEGER NOT NULL
);
CREATE INDEX projects_name ON projects (lower(name), id);

CREATE TABLE project_sources (
  project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source        TEXT NOT NULL CHECK (source IN ('marker', 'session')),
  first_seen_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, source)
) WITHOUT ROWID;

CREATE TABLE auth_sessions (
  id               TEXT PRIMARY KEY,
  token_hash       BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  prev_token_hash  BLOB UNIQUE CHECK (prev_token_hash IS NULL OR length(prev_token_hash) = 32),
  prev_valid_until INTEGER,
  created_at       INTEGER NOT NULL,
  last_used_at     INTEGER NOT NULL,
  rotated_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL
);
