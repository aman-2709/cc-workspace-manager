//! The JSON shape of projects in REST responses and WebSocket events (ARCHITECTURE.md §8).
//! Built from database rows plus what only the running daemon knows (time zone, monitoring).
//! Unknown values are `null`, never `0` or an invented string.

use crate::activity::{Classifier, Status};
use crate::db::queries::{GitRow, ProjectRow};
use crate::watch::{Monitoring, PollReason};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ActivityView {
    pub status: Status,
    pub at: Option<i64>,
    /// `inferred` (file times from a walk) or `observed` (live events).
    pub kind: Option<String>,
    /// The latest modified file, relative to the project.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommitView {
    pub subject: Option<String>,
    pub time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitView {
    pub state: String,
    pub branch: Option<String>,
    pub detached: bool,
    pub upstream: Option<String>,
    pub ahead: Option<i64>,
    pub behind: Option<i64>,
    pub staged: Option<i64>,
    pub modified: Option<i64>,
    pub untracked: Option<i64>,
    /// Uncommitted changes (staged, modified or untracked); `null` if status was not run.
    pub dirty: Option<bool>,
    pub commit: Option<CommitView>,
    pub checked_at: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectView {
    pub id: String,
    pub name: String,
    /// Canonical absolute path.
    pub path: String,
    /// `~/…` when the project is inside the home directory, else the absolute path.
    pub display_path: String,
    pub sources: Vec<String>,
    pub first_seen_at: i64,
    pub activity: ActivityView,
    /// `null` until Git was inspected.
    pub git: Option<GitView>,
    pub missing_since: Option<i64>,
    pub ignored: bool,
    /// `watched`, `polled`, or `null` when not monitored (ignored, missing, not yet set up).
    pub monitoring: Option<Monitoring>,
    pub monitoring_reason: Option<PollReason>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HeadView {
    pub hash: String,
    pub short: String,
    pub subject: Option<String>,
    pub author: Option<String>,
    pub time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitDetail {
    pub head: Option<HeadView>,
    /// Sanitized: credentials removed.
    pub remote_url: Option<String>,
    /// Staged / modified / untracked files, each capped at 200 (counts are in `git`).
    pub files: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectDetail {
    #[serde(flatten)]
    pub project: ProjectView,
    pub git_detail: Option<GitDetail>,
}

/// `~` for the home directory itself, `~/rel` inside it, the path unchanged elsewhere.
pub fn display_path(path: &str, home: &Path) -> String {
    let p = Path::new(path);
    if home.as_os_str().len() <= 1 {
        return path.to_string(); // no meaningful home ("/" or empty)
    }
    match p.strip_prefix(home) {
        Ok(rel) if rel.as_os_str().is_empty() => "~".to_string(),
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.to_string(),
    }
}

fn git_view(g: &GitRow) -> GitView {
    let counts = [g.staged, g.modified, g.untracked];
    let dirty = if counts.iter().all(Option::is_some) {
        Some(counts.iter().flatten().sum::<i64>() > 0)
    } else {
        None
    };
    GitView {
        state: g.state.clone(),
        branch: g.branch.clone(),
        detached: g.detached,
        upstream: g.upstream.clone(),
        ahead: g.ahead,
        behind: g.behind,
        staged: g.staged,
        modified: g.modified,
        untracked: g.untracked,
        dirty,
        commit: (g.head_subject.is_some() || g.head_time.is_some()).then(|| CommitView {
            subject: g.head_subject.clone(),
            time: g.head_time,
        }),
        checked_at: g.fetched_at,
    }
}

pub fn project_view(
    row: &ProjectRow,
    classifier: &Classifier,
    now: i64,
    home: &Path,
    monitoring: Option<(Monitoring, Option<PollReason>)>,
) -> ProjectView {
    ProjectView {
        id: row.id.clone(),
        name: row.name.clone(),
        path: row.path.clone(),
        display_path: display_path(&row.path, home),
        sources: row.sources.clone(),
        first_seen_at: row.first_seen_at,
        activity: ActivityView {
            status: classifier.status(row.activity_at, now),
            at: row.activity_at,
            kind: row.activity_kind.clone(),
            path: row.activity_path.clone(),
        },
        git: row.git.as_ref().map(git_view),
        missing_since: row.missing_since,
        ignored: row.ignored,
        monitoring: monitoring.map(|m| m.0),
        monitoring_reason: monitoring.and_then(|m| m.1),
    }
}

pub fn git_detail(g: &GitRow) -> GitDetail {
    GitDetail {
        head: g.head_commit.as_ref().map(|h| HeadView {
            short: h.chars().take(12).collect(),
            hash: h.clone(),
            subject: g.head_subject.clone(),
            author: g.head_author.clone(),
            time: g.head_time,
        }),
        remote_url: g.remote_url.clone(),
        files: g
            .files
            .as_deref()
            .and_then(|f| serde_json::from_str(f).ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_paths_are_home_relative() {
        let home = Path::new("/home/u");
        assert_eq!(display_path("/home/u/dev/x", home), "~/dev/x");
        assert_eq!(display_path("/home/u", home), "~");
        assert_eq!(
            display_path("/home/user2/x", home),
            "/home/user2/x",
            "prefix of a name"
        );
        assert_eq!(display_path("/srv/code", home), "/srv/code");
        assert_eq!(display_path("/srv/code", Path::new("/")), "/srv/code");
    }

    fn git(staged: Option<i64>) -> GitRow {
        GitRow {
            fetched_at: 5,
            state: "ok".into(),
            branch: Some("main".into()),
            detached: false,
            upstream: None,
            ahead: None,
            behind: None,
            staged,
            modified: staged.map(|_| 0),
            untracked: staged.map(|_| 0),
            head_commit: Some("a".repeat(40)),
            head_subject: Some("s".into()),
            head_author: Some("A".into()),
            head_time: Some(9),
            remote_url: None,
            files: Some(r#"{"staged":["x"],"modified":[],"untracked":[]}"#.into()),
        }
    }

    #[test]
    fn dirty_is_unknown_without_status_and_detail_shortens_the_hash() {
        assert_eq!(git_view(&git(Some(0))).dirty, Some(false));
        assert_eq!(git_view(&git(Some(2))).dirty, Some(true));
        assert_eq!(git_view(&git(None)).dirty, None);
        let d = git_detail(&git(Some(1)));
        assert_eq!(d.head.unwrap().short.len(), 12);
        assert_eq!(d.files.unwrap()["staged"][0], "x");
    }
}
