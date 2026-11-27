-- v0.2: the open sessions of the activity indicator (REQUIREMENTS.md §21.7), so a daemon restart
-- can restore those whose process still runs (in the state `unknown`). No project (resolved
-- again at start), no activity state (never guessed after a restart), no interactive flag (read
-- again from the process). Written when a session opens, changes process or closes.
CREATE TABLE open_sessions (
  session_id TEXT PRIMARY KEY CHECK (length(session_id) = 36),
  pid INTEGER NOT NULL CHECK (pid BETWEEN 2 AND 4194304),
  pid_start INTEGER NOT NULL CHECK (pid_start >= 0), -- /proc/<pid>/stat field 22 (clock ticks after boot)
  boot_id TEXT NOT NULL,                             -- /proc/sys/kernel/random/boot_id
  first_cwd TEXT NOT NULL CHECK (length(CAST(first_cwd AS BLOB)) <= 4096), -- as received; never logged
  opened_at INTEGER NOT NULL
) WITHOUT ROWID;
