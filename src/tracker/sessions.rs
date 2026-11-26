//! Session ingest (REQUIREMENTS.md §4.3–§4.5, §7.2): list the session files, parse what is new
//! in each (incremental checkpoints), resolve the first recorded cwd of new and unassigned
//! sessions to a project root, register those projects (source `session`), and store the
//! aggregates. Files that disappeared are dropped from the index; their projects stay.

use super::Tracker;
use crate::claude::locate::{self, Listing, SessionFile, PROJECTS_DIR};
use crate::claude::parse::{self, Outcome};
use crate::claude::resume;
use crate::db::queries::{self, SessionState};
use crate::db::writer::{ProjectUpsert, SessionStore, Source, Upserted};
use crate::discovery::resolve::{Context, Unassigned};
use crate::discovery::status::UnassignedFolder;
use crate::error::Result;
use crate::watch::Cmd;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Sessions are stored in batches of this many (one writer command each).
const STORE_BATCH: usize = 256;

/// What the blocking part produced.
struct Scanned {
    /// `None`: the `projects/` directory could not be listed at all.
    listing: Option<Listing>,
    /// The directory does not exist (as opposed to being unreadable).
    absent: bool,
    parsed: Vec<(SessionFile, parse::Checkpoint, parse::Aggregate)>,
    /// Files skipped because another file has the same session id.
    duplicates: u64,
}

impl Tracker {
    /// Ingest every session (`dirs = None`) or only those in the given `<encoded-dir>`s. Returns
    /// the session projects that were upserted (callers enroll the inserted and revived ones).
    pub(crate) async fn ingest_sessions(
        self: &Arc<Self>,
        dirs: Option<Vec<PathBuf>>,
    ) -> Result<Vec<Upserted>> {
        let Some(cfg) = self.settings.sessions.clone() else {
            return Ok(Vec::new());
        };
        let _guard = self.session_lock.lock().await;
        let projects_dir = cfg.config_dir.join(PROJECTS_DIR);
        let full = dirs
            .as_ref()
            .is_none_or(|d| d.iter().any(|p| p == &projects_dir));
        let states: HashMap<String, SessionState> = self
            .reader
            .with(queries::session_states)
            .await?
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect();
        let tracked = self.tracked().await?;
        let ctx = Arc::new(self.resolve_context(&cfg, &tracked));
        let mut scanned = {
            let (dir, states, ctx) = (projects_dir.clone(), states.clone(), Arc::clone(&ctx));
            tokio::task::spawn_blocking(move || {
                scan(&dir, if full { None } else { dirs }, &states, &ctx)
            })
            .await
            .map_err(|e| crate::error::Error::new(format!("session scan failed: {e}")))?
        };

        let gone = gone_files(scanned.listing.as_ref(), scanned.absent, full, &states);
        let mut affected = Vec::new();
        if !gone.is_empty() {
            affected.extend(self.writer.delete_sessions(gone).await?);
        }

        // Resolve new sessions, and re-try unassigned ones (a cwd may have appeared since).
        let parsed_ids: HashSet<String> = scanned.parsed.iter().map(|p| p.0.id.clone()).collect();
        let mut wanted: Vec<(String, Option<String>)> = scanned
            .parsed
            .iter()
            .filter(|(f, _, _)| states.get(&f.id).is_none_or(|s| s.project_id.is_none()))
            .map(|(f, _, a)| (f.id.clone(), a.first_cwd.clone()))
            .collect();
        wanted.extend(
            states
                .values()
                .filter(|s| s.project_id.is_none() && !parsed_ids.contains(&s.id))
                .map(|s| (s.id.clone(), s.aggregate.first_cwd.clone())),
        );
        let resolved: HashMap<String, std::result::Result<PathBuf, Unassigned>> = {
            tokio::task::spawn_blocking(move || {
                // Many sessions share a cwd: resolve each distinct one once.
                let mut by_cwd: HashMap<Option<String>, std::result::Result<PathBuf, Unassigned>> =
                    HashMap::new();
                wanted
                    .into_iter()
                    .map(|(id, cwd)| {
                        let r = by_cwd
                            .entry(cwd)
                            .or_insert_with_key(|c| ctx.resolve(c.as_deref()))
                            .clone();
                        (id, r)
                    })
                    .collect()
            })
            .await
            .unwrap_or_default()
        };
        let roots: Vec<String> = {
            let mut v: Vec<String> = resolved
                .values()
                .filter_map(|r| r.as_ref().ok()?.to_str().map(str::to_string))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let upserts: Vec<ProjectUpsert> = roots
            .iter()
            .map(|p| ProjectUpsert {
                canonical_path: p.clone(),
                name: Path::new(p)
                    .file_name()
                    .map_or_else(|| p.clone(), |n| n.to_string_lossy().into_owned()),
                source: Source::Session,
                marker_hash: None,
            })
            .collect();
        let upserted = if upserts.is_empty() {
            Vec::new()
        } else {
            self.writer
                .upsert_projects(upserts, self.clock.now())
                .await?
                .rows
        };
        let id_of: HashMap<&str, &str> = upserted
            .iter()
            .map(|u| (u.canonical_path.as_str(), u.id.as_str()))
            .collect();
        let assignment = |id: &str| -> (Option<String>, Option<&'static str>) {
            match resolved.get(id) {
                Some(Ok(root)) => (
                    root.to_str()
                        .and_then(|r| id_of.get(r))
                        .map(|i| (*i).to_string()),
                    None,
                ),
                Some(Err(u)) => (None, Some(u.as_str())),
                None => (None, None),
            }
        };

        // Store the parsed sessions; existing assigned ones keep their project.
        let mut stores = Vec::with_capacity(scanned.parsed.len());
        for (f, checkpoint, aggregate) in std::mem::take(&mut scanned.parsed) {
            let (project_id, unassigned) = match states.get(&f.id) {
                Some(s) if s.project_id.is_some() => (s.project_id.clone(), None),
                _ => assignment(&f.id),
            };
            stores.push(SessionStore {
                file_path: f.path.to_string_lossy().into_owned(),
                id: f.id,
                project_id,
                unassigned,
                aggregate,
                checkpoint,
            });
        }
        while !stores.is_empty() {
            let rest = stores.split_off(stores.len().min(STORE_BATCH));
            affected.extend(self.writer.store_sessions(stores).await?);
            stores = rest;
        }
        let assignments: Vec<(String, Option<String>, Option<&'static str>)> = states
            .values()
            .filter(|s| s.project_id.is_none() && !parsed_ids.contains(&s.id))
            .filter_map(|s| {
                let (p, u) = assignment(&s.id);
                let changed = p.is_some() || u != s.unassigned.as_deref();
                changed.then(|| (s.id.clone(), p, u))
            })
            .collect();
        if !assignments.is_empty() {
            affected.extend(self.writer.assign_sessions(assignments).await?);
        }
        affected.sort();
        affected.dedup();
        for id in &affected {
            self.notifier.project(id);
        }
        for u in upserted.iter().filter(|u| u.inserted || u.revived) {
            self.notifier.project(&u.id);
        }

        if full {
            if let Some(l) = &scanned.listing {
                let mut dirs = vec![projects_dir.clone()];
                dirs.extend(l.dirs.iter().cloned());
                let _ = self.monitor.send(Cmd::WatchSessions(dirs)).await;
            }
        }
        self.update_session_status(&scanned, full).await;
        Ok(upserted)
    }

    fn resolve_context(
        &self,
        cfg: &super::SessionSettings,
        tracked: &[queries::Tracked],
    ) -> Context {
        let home = std::fs::canonicalize(&self.settings.scan.home)
            .unwrap_or_else(|_| self.settings.scan.home.clone());
        Context {
            roots: self.root_exclusions(),
            known: tracked
                .iter()
                .filter(|t| !t.missing)
                .map(|t| PathBuf::from(&t.path))
                .collect(),
            max_depth: self.settings.scan.max_depth,
            same_file_system: self.settings.scan.same_file_system,
            home,
            temp_dirs: cfg.temp_dirs.clone(),
        }
    }

    async fn update_session_status(&self, scanned: &Scanned, full: bool) {
        let (listing, absent) = (&scanned.listing, scanned.absent);
        let counts = self.reader.with(queries::session_counts).await;
        let (files, skipped) = listing
            .as_ref()
            .map_or((0, 0), |l| (l.files.len() as u64, l.skipped));
        let cut = listing.as_ref().is_some_and(Listing::truncated);
        let home = self.settings.scan.home.clone();
        self.status.update(|s| {
            let st = &mut s.sessions;
            // Logged when it starts and when it ends, not at every ingest (v0.1.1 review I2:
            // that was at every change of a session file). A partial listing can only add it.
            if full || cut {
                match (st.listing_cut, cut) {
                    (false, true) => tracing::warn!(
                        limit = locate::MAX_FILES,
                        "more session files than one listing holds: the rest is not indexed, and sessions in the folders the limit cut off are not dropped from the index as gone"
                    ),
                    (true, false) => {
                        tracing::info!("the session files fit in one listing again");
                    }
                    _ => {}
                }
                st.listing_cut = cut;
            }
            if full {
                st.state = match (listing, absent) {
                    (Some(l), _) if l.errors == 0 => "ok",
                    (Some(_), _) => "partly_unreadable",
                    (None, true) => "missing",
                    (None, false) => "unreadable",
                };
                st.files = files;
                st.skipped_entries = skipped;
                st.duplicate_ids = scanned.duplicates;
            }
            if let Ok(c) = &counts {
                st.indexed = c.indexed;
                st.malformed_lines = c.malformed;
                st.oversized_lines = c.oversized;
                st.unknown_records = c.unknown;
                st.unassigned = c
                    .unassigned
                    .iter()
                    .filter_map(|(k, n)| Unassigned::parse(k).map(|u| (u.as_str(), *n)))
                    .collect();
                st.unassigned_folders = c
                    .unassigned_folders
                    .iter()
                    .filter_map(|(k, cwd, n)| {
                        Some(UnassignedFolder {
                            reason: Unassigned::parse(k)?.as_str(),
                            folder: cwd
                                .as_deref()
                                .map(|c| crate::view::display_path(&resume::display(c), &home)),
                            sessions: *n,
                        })
                    })
                    .collect();
            }
        });
        self.notifier.status();
    }
}

/// The indexed session files (`states`) that are gone: absent from a directory that was listed,
/// or in a directory that no longer exists (`full` ingest), or everything when `projects/` itself
/// is gone (`absent`). Nothing when the listing is unknown (`None`, not `absent`) or was cut off
/// at the file limit: a file missing from an incomplete listing may still exist (v0.1.0 review
/// I8).
fn gone_files(
    listing: Option<&Listing>,
    absent: bool,
    full: bool,
    states: &HashMap<String, SessionState>,
) -> Vec<String> {
    let all = || states.values().map(|s| s.file_path.clone()).collect();
    match listing {
        Some(l) => {
            let present: HashSet<&Path> = l.files.iter().map(|f| f.path.as_path()).collect();
            // Only directories listed completely: in one the file limit cut off, an absent
            // file may be one the listing left out (v0.1.0 review I8, v0.1.1 review I2).
            let cut: HashSet<&Path> = l.cut.iter().map(PathBuf::as_path).collect();
            let listed: HashSet<&Path> = l
                .dirs
                .iter()
                .map(PathBuf::as_path)
                .filter(|d| !cut.contains(d))
                .collect();
            states
                .values()
                .filter(|s| {
                    let p = Path::new(&s.file_path);
                    let parent = p.parent().unwrap_or(p);
                    !present.contains(p) && (listed.contains(parent) || (full && !parent.exists()))
                })
                .map(|s| s.file_path.clone())
                .collect()
        }
        None if absent => all(),
        None => Vec::new(),
    }
}

/// List and parse (blocking). A session that is not assigned to a project stops being read
/// once its first cwd shows it never can be ([`Context::never_a_project`]).
fn scan(
    projects: &Path,
    dirs: Option<Vec<PathBuf>>,
    states: &HashMap<String, SessionState>,
    ctx: &Context,
) -> Scanned {
    let (mut listing, absent) = match dirs {
        None => match locate::list_all(projects) {
            Some(l) => (Some(l), false),
            None => (None, std::fs::symlink_metadata(projects).is_err()),
        },
        Some(d) => (Some(locate::list_some(projects, &d)), false),
    };
    let duplicates = listing.as_mut().map_or(0, |l| {
        locate::dedupe(&mut l.files, |id| {
            states.get(id).map(|s| PathBuf::from(&s.file_path))
        })
    });
    let verdicts = std::cell::RefCell::new(HashMap::<String, bool>::new());
    let never = |cwd: &str| -> bool {
        if let Some(v) = verdicts.borrow().get(cwd) {
            return *v;
        }
        let v = ctx.never_a_project(cwd);
        verdicts.borrow_mut().insert(cwd.to_string(), v);
        v
    };
    let mut parsed = Vec::new();
    for f in listing.iter().flat_map(|l| l.files.iter()) {
        let state = states
            .get(&f.id)
            .filter(|s| Path::new(&s.file_path) == f.path);
        let prev = state.map(|s| (&s.checkpoint, &s.aggregate));
        let assigned = state.is_some_and(|s| s.project_id.is_some());
        let stop: &dyn Fn(&str) -> bool = if assigned { &parse::read_all } else { &never };
        let Some(mut file) = locate::open(f) else {
            continue;
        };
        match parse::parse(&mut file, &f.id, prev, stop) {
            Ok(Outcome::Updated {
                checkpoint,
                aggregate,
                ..
            }) => parsed.push((f.clone(), checkpoint, *aggregate)),
            Ok(Outcome::Unchanged) => {}
            Err(e) => tracing::debug!(error = %e, "a session file could not be read"),
        }
    }
    Scanned {
        listing,
        absent,
        parsed,
        duplicates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const IDS: [&str; 3] = [
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    ];

    fn indexed(files: &[PathBuf]) -> HashMap<String, SessionState> {
        files
            .iter()
            .zip(IDS)
            .map(|(path, id)| {
                let state = SessionState {
                    id: id.to_string(),
                    file_path: path.to_string_lossy().into_owned(),
                    project_id: None,
                    unassigned: None,
                    aggregate: parse::Aggregate::default(),
                    checkpoint: parse::Checkpoint::default(),
                };
                (id.to_string(), state)
            })
            .collect()
    }

    /// v0.1.1 review I2: a listing that the file limit cut off still knows the folders it listed
    /// completely. A session deleted from one of those is gone; the folder the limit cut off
    /// keeps all of its sessions (one may only have been left out). Whichever folder is listed
    /// first, the one with the deleted file is complete: it holds no session file any more.
    #[test]
    fn a_cut_off_listing_still_finds_the_sessions_gone_from_folders_it_listed_completely() {
        let t = tempfile::tempdir().unwrap();
        let projects = fs::canonicalize(t.path()).unwrap().join(PROJECTS_DIR);
        let (a, b) = (projects.join("-synthetic-a"), projects.join("-synthetic-b"));
        let files = [
            a.join(format!("{}.jsonl", IDS[0])),
            b.join(format!("{}.jsonl", IDS[1])),
            b.join(format!("{}.jsonl", IDS[2])),
        ];
        for f in &files {
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, "{}\n").unwrap();
        }
        let states = indexed(&files);
        fs::remove_file(&files[0]).unwrap();
        let cut = locate::list_all_capped(&projects, 1).unwrap();
        assert!(cut.truncated());
        assert_eq!(
            cut.cut,
            std::slice::from_ref(&b),
            "only the folder the limit was reached in"
        );
        for full in [true, false] {
            assert_eq!(
                gone_files(Some(&cut), false, full, &states),
                [files[0].to_string_lossy().into_owned()],
                "full {full}"
            );
        }
    }

    /// v0.1.0 review I8: the sessions a listing left out at its file limit are still there; they
    /// must not be dropped from the index as gone. Controls: a complete listing does find a
    /// deleted file, a vanished directory and a vanished `projects/`.
    #[test]
    fn sessions_missing_from_a_listing_cut_off_at_the_limit_are_not_gone() {
        let t = tempfile::tempdir().unwrap();
        let projects = fs::canonicalize(t.path()).unwrap().join(PROJECTS_DIR);
        let dir = projects.join("-synthetic-dev-x");
        fs::create_dir_all(&dir).unwrap();
        let files: Vec<PathBuf> = IDS
            .iter()
            .map(|id| dir.join(format!("{id}.jsonl")))
            .collect();
        for f in &files {
            fs::write(f, "{}\n").unwrap();
        }
        let states = indexed(&files);
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let path = |i: usize| files[i].to_string_lossy().into_owned();

        // Every file exists; the listing holds only two of the three.
        let cut = locate::list_all_capped(&projects, 2).unwrap();
        assert!(cut.truncated() && cut.files.len() == 2);
        for full in [true, false] {
            assert!(gone_files(Some(&cut), false, full, &states).is_empty());
        }
        // Control: the same listing without the mark would drop the third session.
        let unmarked = Listing {
            cut: Vec::new(),
            ..locate::list_all_capped(&projects, 2).unwrap()
        };
        assert_eq!(gone_files(Some(&unmarked), false, true, &states).len(), 1);

        // A complete listing: nothing is gone until a file is deleted.
        let complete = locate::list_all(&projects).unwrap();
        assert!(gone_files(Some(&complete), false, true, &states).is_empty());
        fs::remove_file(&files[1]).unwrap();
        let complete = locate::list_all(&projects).unwrap();
        assert_eq!(gone_files(Some(&complete), false, true, &states), [path(1)]);
        // …but not when that listing is cut off: the deleted file may be one it left out.
        let cut = locate::list_all_capped(&projects, 1).unwrap();
        assert!(gone_files(Some(&cut), false, true, &states).is_empty());

        // The directory vanished: gone in a full ingest only (a partial one did not look there).
        fs::remove_dir_all(&dir).unwrap();
        let empty = locate::list_all(&projects).unwrap();
        assert_eq!(
            sorted(gone_files(Some(&empty), false, true, &states)),
            sorted(vec![path(0), path(1), path(2)])
        );
        assert!(gone_files(Some(&empty), false, false, &states).is_empty());
        // `projects/` itself: everything when it is absent, nothing when it is only unreadable.
        assert_eq!(gone_files(None, true, true, &states).len(), 3);
        assert!(gone_files(None, false, true, &states).is_empty());
    }
}
