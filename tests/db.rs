//! Writer thread + reader pool behaviour against a real temporary SQLite file.

use cc_workspace_manager::auth::tokens::hash_token;
use cc_workspace_manager::db::queries::{self, Filters, ListParams, Order, SortBy};
use cc_workspace_manager::db::reader::Reader;
use cc_workspace_manager::db::writer::{
    Activity, ActivityKind, EventKind, FileEvent, ProjectUpsert, Source, Writer,
};
use std::path::Path;

fn up(path: &str, source: Source) -> ProjectUpsert {
    let name = path.rsplit('/').next().unwrap().to_string();
    ProjectUpsert {
        canonical_path: path.to_string(),
        name,
        source,
        marker_hash: None,
    }
}

async fn open(dir: &Path) -> (Writer, Reader) {
    let db = dir.join("t.db");
    let w = Writer::spawn(&db).unwrap();
    let r = Reader::open(&db, 2).unwrap();
    (w, r)
}

fn params(limit: u32) -> ListParams {
    ListParams {
        filters: Filters::default(),
        sort: SortBy::Name,
        order: Order::Asc,
        limit,
        after: None,
    }
}

#[tokio::test]
async fn upsert_keeps_ids_merges_sources_and_updates_last_seen() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let s = w
        .upsert_projects(
            vec![up("/h/a", Source::Marker), up("/h/b", Source::Marker)],
            100,
        )
        .await
        .unwrap();
    assert_eq!((s.inserted, s.updated), (2, 0));
    let first = r
        .with(|c| queries::list_projects(c, &params(10)))
        .await
        .unwrap()
        .0;
    let s = w
        .upsert_projects(vec![up("/h/a", Source::Session)], 200)
        .await
        .unwrap();
    assert_eq!((s.inserted, s.updated), (0, 1));
    let again = r
        .with(|c| queries::list_projects(c, &params(10)))
        .await
        .unwrap()
        .0;
    assert_eq!(again.len(), 2);
    assert_eq!(first[0].id, again[0].id, "id is stable across upserts");
    assert_eq!(again[0].sources, ["marker", "session"]);
    assert_eq!(again[0].first_seen_at, 100);
}

#[tokio::test]
async fn keyset_pagination_walks_every_row_once_in_both_directions() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let batch: Vec<_> = ["Zed", "alpha", "Beta", "gamma", "beta", "delta", "Eps"]
        .iter()
        .map(|n| up(&format!("/h/{n}"), Source::Marker))
        .collect();
    w.upsert_projects(batch, 1).await.unwrap();
    for order in [Order::Asc, Order::Desc] {
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let p = ListParams {
                order,
                limit: 3,
                after: after.clone(),
                ..params(3)
            };
            let (rows, total) = r
                .with(move |c| queries::list_projects(c, &p))
                .await
                .unwrap();
            assert_eq!(total, 7);
            if rows.is_empty() {
                break;
            }
            let last = rows.last().unwrap();
            after = Some((last.k1, last.sort_key.clone(), last.id.clone()));
            seen.extend(rows.into_iter().map(|r| r.name));
        }
        assert_eq!(seen.len(), 7, "{order:?}: {seen:?}");
        let mut lowered: Vec<_> = seen.iter().map(|n| n.to_lowercase()).collect();
        let sorted = {
            let mut s = lowered.clone();
            s.sort();
            if order == Order::Desc {
                s.reverse();
            }
            s
        };
        assert_eq!(lowered.as_mut_slice(), sorted.as_slice());
    }
}

#[tokio::test]
async fn search_matches_name_or_path_and_escapes_wildcards() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    w.upsert_projects(
        vec![
            up("/h/100%_done", Source::Marker),
            up("/h/other", Source::Marker),
            up("/work/x/app", Source::Marker),
        ],
        1,
    )
    .await
    .unwrap();
    let q = |s: &str| {
        let p = ListParams {
            filters: Filters {
                q: Some(s.to_string()),
                ..Filters::default()
            },
            ..params(10)
        };
        async {
            r.with(move |c| queries::list_projects(c, &p))
                .await
                .unwrap()
        }
    };
    assert_eq!(q("%").await.1, 1, "a literal percent only");
    assert_eq!(q("_d").await.1, 1);
    assert_eq!(q("OTHER").await.1, 1, "case-insensitive");
    assert_eq!(q("/work/x").await.1, 1, "path match");
    assert_eq!(q("zzz").await.1, 0);
    assert_eq!(q("'; DROP TABLE projects; --").await.1, 0);
    assert_eq!(r.with(queries::count_projects).await.unwrap(), 3);
}

#[tokio::test]
async fn session_lifecycle_create_find_rotate_grace_delete_and_revoke_all() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let (h1, h2) = (hash_token("one"), hash_token("two"));
    let s = w.create_session(h1, 1000, 5000).await.unwrap();
    let found = r
        .with(move |c| queries::find_session(c, &h1, 1001))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (found.id.as_str(), found.via_previous, found.expires_at),
        (s.id.as_str(), false, 5000)
    );

    // rotate: new token valid immediately, old token valid until the grace deadline only
    let rotated = w
        .rotate_session(h1, h2, 2000, 2060, 6000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rotated.id, s.id);
    let cur = r
        .with(move |c| queries::find_session(c, &h2, 2001))
        .await
        .unwrap()
        .unwrap();
    assert!(!cur.via_previous && cur.rotated_at == 2000);
    let old_in_grace = r
        .with(move |c| queries::find_session(c, &h1, 2059))
        .await
        .unwrap()
        .unwrap();
    assert!(old_in_grace.via_previous);
    assert!(
        r.with(move |c| queries::find_session(c, &h1, 2060))
            .await
            .unwrap()
            .is_none(),
        "grace is exclusive"
    );
    // the old token can no longer rotate (it is not the current one)
    assert!(w
        .rotate_session(h1, hash_token("three"), 2010, 2070, 7000)
        .await
        .unwrap()
        .is_none());
    // unknown token
    assert!(w
        .rotate_session(hash_token("nope"), hash_token("x"), 2010, 2070, 7000)
        .await
        .unwrap()
        .is_none());

    // delete removes the session including its previous token
    assert!(w.delete_session(h2).await.unwrap());
    assert!(!w.delete_session(h2).await.unwrap());
    assert!(r
        .with(move |c| queries::find_session(c, &h1, 2001))
        .await
        .unwrap()
        .is_none());

    for i in 0..3 {
        w.create_session(hash_token(&format!("s{i}")), 1, 9999)
            .await
            .unwrap();
    }
    assert_eq!(w.revoke_all().await.unwrap(), 3);
    assert_eq!(r.with(queries::count_sessions).await.unwrap(), 0);
}

#[tokio::test]
async fn touch_extends_expiry_and_expired_sessions_are_purged() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let h = hash_token("t");
    let s = w.create_session(h, 100, 1000).await.unwrap();
    w.touch_session(s.id.clone(), 500, 1500);
    w.flush().await.unwrap();
    let rec = r
        .with(move |c| queries::find_session(c, &h, 501))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((rec.last_used_at, rec.expires_at), (500, 1500));
    w.touch_session(s.id, 600, 900); // never shortens
    w.flush().await.unwrap();
    assert_eq!(
        r.with(move |c| queries::find_session(c, &h, 601))
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        1500
    );
    assert_eq!(w.purge_expired_sessions(1500).await.unwrap(), 1);
}

#[tokio::test]
async fn meta_roundtrip_and_commands_are_durable_after_shutdown() {
    let t = tempfile::tempdir().unwrap();
    let db = t.path().join("t.db");
    {
        let w = Writer::spawn(&db).unwrap();
        w.set_meta("k", "v1").await.unwrap();
        w.set_meta("k", "v2").await.unwrap();
        w.upsert_projects(vec![up("/h/a", Source::Marker)], 1)
            .await
            .unwrap();
        w.shutdown().await.unwrap();
        assert!(w.flush().await.is_err(), "writer is stopped after shutdown");
        w.shutdown().await.unwrap(); // idempotent
    }
    let r = Reader::open(&db, 1).unwrap();
    assert_eq!(
        r.with(|c| queries::get_meta(c, "k"))
            .await
            .unwrap()
            .as_deref(),
        Some("v2")
    );
    assert_eq!(r.with(queries::count_projects).await.unwrap(), 1);
}

#[tokio::test]
async fn many_concurrent_writes_all_land_and_one_bad_command_does_not_poison_the_batch() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let w = std::sync::Arc::new(w);
    let mut tasks = Vec::new();
    for i in 0..200 {
        let w = w.clone();
        tasks.push(tokio::spawn(async move {
            w.upsert_projects(vec![up(&format!("/h/p{i}"), Source::Marker)], 1)
                .await
                .unwrap();
        }));
    }
    // A duplicate token hash violates UNIQUE: that command fails alone.
    let dup = hash_token("dup");
    w.create_session(dup, 1, 100).await.unwrap();
    assert!(w.create_session(dup, 1, 100).await.is_err());
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(r.with(queries::count_projects).await.unwrap(), 200);
    assert_eq!(r.with(queries::count_sessions).await.unwrap(), 1);
}

#[test]
fn blocking_upsert_works_from_a_plain_thread() {
    let t = tempfile::tempdir().unwrap();
    let w = Writer::spawn(&t.path().join("t.db")).unwrap();
    let s = w
        .upsert_projects_blocking(vec![up("/h/a", Source::Marker)], 5)
        .unwrap();
    assert_eq!(s.inserted, 1);
    w.set_meta_blocking("x", "y").unwrap();
}

// ---- M2: activity, Git cache, missing, moves, ignore ---------------------------------------------

async fn ids(w: &Writer, paths: &[&str]) -> Vec<String> {
    let batch = paths.iter().map(|p| up(p, Source::Marker)).collect();
    w.upsert_projects(batch, 1)
        .await
        .unwrap()
        .rows
        .into_iter()
        .map(|r| r.id)
        .collect()
}

fn act(at: i64, kind: ActivityKind, path: &str) -> Activity {
    Activity {
        at,
        kind,
        path: Some(path.to_string()),
    }
}

async fn row(r: &Reader, id: &str) -> queries::ProjectRow {
    let id = id.to_string();
    r.with(move |c| queries::get_project(c, &id))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn activity_only_moves_forward_and_events_are_bounded() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let id = ids(&w, &["/h/a"]).await.remove(0);
    assert!(w
        .record_activity(&id, act(100, ActivityKind::Inferred, "x"), vec![], 3)
        .await
        .unwrap());
    assert!(
        !w.record_activity(&id, act(50, ActivityKind::Observed, "old"), vec![], 3)
            .await
            .unwrap(),
        "an older time never replaces a newer one"
    );
    let ev = |i: i64| FileEvent {
        at: 200 + i,
        kind: EventKind::Modify,
        path: format!("f{i}"),
    };
    assert!(w
        .record_activity(
            &id,
            act(205, ActivityKind::Observed, "f5"),
            (0..6).map(ev).collect(),
            3
        )
        .await
        .unwrap());
    let p = row(&r, &id).await;
    assert_eq!(
        (
            p.activity_at,
            p.activity_kind.as_deref(),
            p.activity_path.as_deref()
        ),
        (Some(205), Some("observed"), Some("f5"))
    );
    let id2 = id.clone();
    let events = r
        .with(move |c| queries::file_events(c, &id2))
        .await
        .unwrap();
    let names: Vec<&str> = events.iter().map(|e| e.2.as_str()).collect();
    assert_eq!(
        names,
        ["f5", "f4", "f3"],
        "only the newest `keep` events stay"
    );
    // At the same second, a walk (inferred) never downgrades an observation…
    assert!(!w
        .record_activity(&id, act(205, ActivityKind::Inferred, "other"), vec![], 3)
        .await
        .unwrap());
    assert_eq!(
        row(&r, &id).await.activity_kind.as_deref(),
        Some("observed")
    );
    // …but an observation upgrades an inference.
    let id_b = ids(&w, &["/h/b"]).await.remove(0);
    w.record_activity(&id_b, act(300, ActivityKind::Inferred, "f"), vec![], 3)
        .await
        .unwrap();
    assert!(w
        .record_activity(&id_b, act(300, ActivityKind::Observed, "f"), vec![], 3)
        .await
        .unwrap());
    assert_eq!(
        row(&r, &id_b).await.activity_kind.as_deref(),
        Some("observed")
    );
    // A later observation in the same second names the newer file…
    assert!(w
        .record_activity(&id_b, act(300, ActivityKind::Observed, "g"), vec![], 3)
        .await
        .unwrap());
    assert_eq!(row(&r, &id_b).await.activity_path.as_deref(), Some("g"));
    // …and a directory-only observation (no file) keeps it.
    let dir_only = Activity {
        at: 300,
        kind: ActivityKind::Observed,
        path: None,
    };
    assert!(!w.record_activity(&id_b, dir_only, vec![], 3).await.unwrap());
    assert_eq!(row(&r, &id_b).await.activity_path.as_deref(), Some("g"));
    assert!(
        !w.record_activity(
            "0123456789abcdef0123456789abcdef",
            act(1, ActivityKind::Observed, "x"),
            vec![ev(1)],
            3
        )
        .await
        .unwrap(),
        "unknown projects are ignored"
    );
}

fn git_info(
    head: Option<&str>,
    remote: Option<&str>,
    dirty: bool,
) -> cc_workspace_manager::git::Info {
    use cc_workspace_manager::git::{parse::Commit, Info, State, WorkTree};
    Info {
        state: State::Ok,
        branch: Some("main".into()),
        detached: false,
        upstream: None,
        ahead: None,
        behind: None,
        worktree: Some(WorkTree {
            staged: 0,
            modified: u32::from(dirty),
            untracked: 0,
            files: Default::default(),
        }),
        head: head.map(|h| Commit {
            hash: h.to_string(),
            subject: "s".into(),
            author: "a".into(),
            time: 7,
        }),
        remote_url: remote.map(str::to_string),
    }
}

async fn list(r: &Reader, p: ListParams) -> (Vec<String>, u64) {
    let (rows, total) = r
        .with(move |c| queries::list_projects(c, &p))
        .await
        .unwrap();
    (rows.into_iter().map(|r| r.name).collect(), total)
}

#[tokio::test]
async fn git_cache_dirty_filter_and_branch_search() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let v = ids(&w, &["/h/clean", "/h/dirty", "/h/nogit"]).await;
    w.store_git(&v[0], git_info(Some(&"a".repeat(40)), None, false), 5)
        .await
        .unwrap();
    w.store_git(&v[1], git_info(Some(&"b".repeat(40)), None, true), 5)
        .await
        .unwrap();
    let dirty = ListParams {
        filters: Filters {
            dirty: true,
            ..Filters::default()
        },
        ..params(10)
    };
    assert_eq!(list(&r, dirty).await.0, ["dirty"]);
    let by_branch = ListParams {
        filters: Filters {
            q: Some("mai".into()),
            ..Filters::default()
        },
        ..params(10)
    };
    assert_eq!(
        list(&r, by_branch).await.0,
        ["clean", "dirty"],
        "search covers the branch"
    );
    let g = row(&r, &v[1]).await.git.unwrap();
    assert_eq!(
        (g.state.as_str(), g.modified, g.head_time),
        ("ok", Some(1), Some(7))
    );
    assert!(row(&r, &v[2]).await.git.is_none());
    // A Git row for a project that no longer exists is not created.
    w.store_git(
        "0123456789abcdef0123456789abcdef",
        git_info(None, None, false),
        1,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn activity_sort_puts_unknown_last_in_both_orders_and_pages_with_keysets() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let names = ["a", "b", "c", "d", "e", "f", "g"];
    let v = ids(
        &w,
        &names
            .iter()
            .map(|n| format!("/h/{n}"))
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .await;
    // b and d share a time (tie broken by name); f and g have none.
    for (i, at) in [(0, 30), (1, 20), (2, 10), (3, 20), (4, 40)] {
        w.record_activity(&v[i], act(at, ActivityKind::Inferred, "x"), vec![], 1)
            .await
            .unwrap();
    }
    for (order, want) in [
        (Order::Desc, ["e", "a", "b", "d", "c", "f", "g"]),
        (Order::Asc, ["c", "b", "d", "a", "e", "f", "g"]),
    ] {
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let p = ListParams {
                sort: SortBy::Activity,
                order,
                limit: 2,
                after: after.clone(),
                filters: Filters::default(),
            };
            let (rows, _) = r
                .with(move |c| queries::list_projects(c, &p))
                .await
                .unwrap();
            let Some(last) = rows.last() else { break };
            after = Some((last.k1, last.sort_key.clone(), last.id.clone()));
            seen.extend(rows.iter().map(|r| r.name.clone()));
        }
        assert_eq!(seen, want, "{order:?}");
    }
}

#[tokio::test]
async fn commit_sort_and_activity_range_filters() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let v = ids(&w, &["/h/old", "/h/new", "/h/none"]).await;
    let mut old = git_info(Some(&"a".repeat(40)), None, false);
    old.head.as_mut().unwrap().time = 1;
    w.store_git(&v[0], old, 1).await.unwrap();
    w.store_git(&v[1], git_info(Some(&"b".repeat(40)), None, false), 1)
        .await
        .unwrap();
    let p = ListParams {
        sort: SortBy::Commit,
        order: Order::Desc,
        ..params(10)
    };
    assert_eq!(list(&r, p).await.0, ["new", "old", "none"]);

    w.record_activity(&v[0], act(100, ActivityKind::Inferred, "x"), vec![], 1)
        .await
        .unwrap();
    w.record_activity(&v[1], act(200, ActivityKind::Inferred, "x"), vec![], 1)
        .await
        .unwrap();
    let range = |from, until, unknown| ListParams {
        filters: Filters {
            activity: Some(cc_workspace_manager::activity::Range {
                from,
                until,
                unknown,
            }),
            ..Filters::default()
        },
        ..params(10)
    };
    assert_eq!(list(&r, range(Some(150), None, false)).await.0, ["new"]);
    assert_eq!(list(&r, range(None, Some(150), false)).await.0, ["old"]);
    assert_eq!(
        list(&r, range(Some(100), Some(200), false)).await.0,
        ["old"],
        "until is exclusive"
    );
    assert_eq!(list(&r, range(None, None, true)).await.0, ["none"]);
}

#[tokio::test]
async fn missing_projects_are_hidden_revived_by_upsert_and_purged_after_retention() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let v = ids(&w, &["/h/a", "/h/b"]).await;
    assert_eq!(w.mark_missing(v.clone(), 100).await.unwrap(), v);
    assert!(
        w.mark_missing(v.clone(), 200).await.unwrap().is_empty(),
        "idempotent; the first time is kept"
    );
    assert_eq!(row(&r, &v[0]).await.missing_since, Some(100));
    assert_eq!(list(&r, params(10)).await.1, 0, "hidden by default");
    let with_missing = ListParams {
        filters: Filters {
            include_missing: true,
            ..Filters::default()
        },
        ..params(10)
    };
    assert_eq!(list(&r, with_missing).await.1, 2);
    let s = w
        .upsert_projects(vec![up("/h/a", Source::Marker)], 300)
        .await
        .unwrap();
    assert!(s.rows[0].revived && !s.rows[0].inserted);
    assert_eq!(row(&r, &v[0]).await.missing_since, None);
    assert!(w.purge_missing(99).await.unwrap().is_empty(), "not yet");
    assert_eq!(w.purge_missing(100).await.unwrap(), [v[1].clone()]);
    let gone = v[1].clone();
    assert!(r
        .with(move |c| queries::get_project(c, &gone))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn ignore_hides_and_follows_moves_and_move_keeps_the_id() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let v = ids(&w, &["/h/a", "/h/b"]).await;
    assert!(w.set_ignored("/h/a", true, 1).await.unwrap());
    assert!(!w.set_ignored("/h/a", true, 2).await.unwrap(), "idempotent");
    assert_eq!(list(&r, params(10)).await.0, ["b"]);
    let with_ignored = ListParams {
        filters: Filters {
            include_ignored: true,
            ..Filters::default()
        },
        ..params(10)
    };
    assert_eq!(list(&r, with_ignored.clone()).await.0, ["a", "b"]);
    // Move a to a new path where a duplicate row was already registered.
    let dup = ids(&w, &["/h/moved-a"]).await.remove(0);
    let removed = w
        .move_project(&v[0], "/h/moved-a", "moved-a", 5)
        .await
        .unwrap();
    assert_eq!(removed, Some(dup));
    let p = row(&r, &v[0]).await;
    assert_eq!(
        (p.path.as_str(), p.name.as_str()),
        ("/h/moved-a", "moved-a")
    );
    assert!(p.ignored, "the ignore moved with the project");
    assert!(w.set_ignored("/h/moved-a", false, 6).await.unwrap());
    assert_eq!(list(&r, params(10)).await.0, ["b", "moved-a"]);
}

#[tokio::test]
async fn stats_use_day_boundaries_and_exclude_missing_and_ignored() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let v = ids(
        &w,
        &["/h/t", "/h/r", "/h/i", "/h/d", "/h/u", "/h/m", "/h/ig"],
    )
    .await;
    let b = cc_workspace_manager::activity::Boundaries {
        today: 1000,
        recent: 800,
        inactive: 500,
    };
    for (i, at) in [
        (0, 1000),
        (1, 800),
        (2, 799),
        (3, 499),
        (5, 1000),
        (6, 1000),
    ] {
        w.record_activity(&v[i], act(at, ActivityKind::Inferred, "x"), vec![], 1)
            .await
            .unwrap();
    }
    w.store_git(&v[0], git_info(None, None, true), 1)
        .await
        .unwrap();
    w.mark_missing(vec![v[5].clone()], 1).await.unwrap();
    w.set_ignored("/h/ig", true, 1).await.unwrap();
    let c = r.with(move |c| queries::stat_counts(c, &b)).await.unwrap();
    assert_eq!(
        (c.total, c.today, c.week, c.inactive, c.dormant, c.unknown, c.dirty, c.missing),
        (5, 1, 2, 1, 1, 1, 1, 1)
    );
}

#[tokio::test]
async fn move_sources_match_on_git_head_and_remote_or_marker_hash() {
    let t = tempfile::tempdir().unwrap();
    let (w, r) = open(t.path()).await;
    let hashed = |p: &str, h: u8| ProjectUpsert {
        marker_hash: Some([h; 32]),
        ..up(p, Source::Marker)
    };
    let rows = w
        .upsert_projects(
            vec![
                hashed("/h/gone-git", 1),
                hashed("/h/gone-plain", 2),
                hashed("/h/new", 2),
            ],
            1,
        )
        .await
        .unwrap()
        .rows;
    let (gone_git, gone_plain, new) = (rows[0].id.clone(), rows[1].id.clone(), rows[2].id.clone());
    let head = "c".repeat(40);
    w.store_git(
        &gone_git,
        git_info(Some(&head), Some("https://h/x"), false),
        1,
    )
    .await
    .unwrap();
    w.mark_missing(vec![gone_git.clone(), gone_plain.clone()], 2)
        .await
        .unwrap();
    let find = |head: Option<String>, remote: Option<&'static str>| {
        let new = new.clone();
        let r = r.clone();
        async move {
            r.with(move |c| queries::move_sources(c, &new, head.as_deref(), remote))
                .await
                .unwrap()
        }
    };
    assert_eq!(
        find(Some(head.clone()), Some("https://h/x")).await,
        [gone_git]
    );
    assert!(
        find(Some(head.clone()), Some("https://other/x"))
            .await
            .is_empty(),
        "remote differs"
    );
    assert!(
        find(Some(head), None).await.is_empty(),
        "remote must match, even when absent"
    );
    assert_eq!(
        find(None, None).await,
        [gone_plain],
        "same marker hash, no Git"
    );
}
