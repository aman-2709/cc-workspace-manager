-- L8: the keyset cursor and ORDER BY must use the same normalization. SQLite's lower() folds ASCII
-- only, Rust's to_lowercase() folds Unicode; the key is now computed once, in Rust, and stored.
ALTER TABLE projects ADD COLUMN sort_key TEXT NOT NULL DEFAULT '';
DROP INDEX projects_name;
CREATE INDEX projects_sort ON projects (sort_key, id);
CREATE INDEX auth_sessions_lru ON auth_sessions (last_used_at, created_at);
