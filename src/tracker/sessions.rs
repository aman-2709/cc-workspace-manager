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

        // Files that are gone: in a directory that was listed completely, or in a directory that
        // no longer exists (full ingest), or everything when `projects/` itself is gone.
        let gone: Vec<String> = match &scanned.listing {
            Some(l) => {
                let present: HashSet<&Path> = l.files.iter().map(|f| f.path.as_path()).collect();
                let listed: HashSet<&Path> = l.dirs.iter().map(PathBuf::as_path).collect();
                states
                    .values()
                    .filter(|s| {
                        let p = Path::new(&s.file_path);
                        let parent = p.parent().unwrap_or(p);
                        !present.contains(p)
                            && (listed.contains(parent) || (full && !parent.exists()))
                    })
                    .map(|s| s.file_path.clone())
                    .collect()
            }
            None if scanned.absent => states.values().map(|s| s.file_path.clone()).collect(),
            None => Vec::new(),
        };
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
        let home = self.settings.scan.home.clone();
        self.status.update(|s| {
            let st = &mut s.sessions;
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
