-- M3.1: a session whose first cwd names no project (excluded, outside the roots, home, a
-- temporary directory) is read only up to that cwd; `partial` marks such a checkpoint, so the file
-- is read again from byte 0 if the session can belong to a project later (other roots after a
-- restart).
ALTER TABLE session_file_checkpoints ADD COLUMN partial INTEGER NOT NULL DEFAULT 0;
