//! Writer thread + reader pool behaviour against a real temporary SQLite file.

use cc_workspace_manager::auth::tokens::hash_token;
use cc_workspace_manager::db::queries::{self, ListParams, Order};
use cc_workspace_manager::db::reader::Reader;
use cc_workspace_manager::db::writer::{ProjectUpsert, Source, Writer};
use std::path::Path;

fn up(path: &str, source: Source) -> ProjectUpsert {
    let name = path.rsplit('/').next().unwrap().to_string();
    ProjectUpsert {
        canonical_path: path.to_string(),
        name,
        source,
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
        q: None,
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
                q: None,
                order,
                limit: 3,
                after: after.clone(),
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
            after = Some((last.name.to_lowercase(), last.id.clone()));
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
            q: Some(s.to_string()),
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
