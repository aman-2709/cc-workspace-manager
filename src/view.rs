//! The JSON shape of projects in REST responses and WebSocket events (ARCHITECTURE.md §8).
//! Built from database rows plus what only the running daemon knows (time zone, monitoring).
//! Unknown values are `null`, never `0` or an invented string.
//!
//! **Privacy mode** (REQUIREMENTS.md §10) is applied here, on the server: [`Privacy::On`] omits
//! absolute paths, user names (Git authors), remote URLs, session titles, prompts, cwds and
//! resume commands from the payload itself, so they never reach the browser.

use crate::activity::{Classifier, Status};
use crate::db::queries::{GitRow, ProjectRow, SessionSummary};
use crate::watch::{Monitoring, PollReason};
use serde::Serialize;
use std::path::Path;

/// Whether a payload is for a client in privacy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Privacy {
    #[default]
    Off,
    On,
}

impl Privacy {
    pub fn from_flag(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    /// `v` unless privacy mode is on.
    pub fn keep<T>(self, v: Option<T>) -> Option<T> {
        match self {
            Self::Off => v,
            Self::On => None,
        }
    }
}

/// How a session's title was obtained (shown next to it).
pub const TITLE_SOURCE_AI: &str = "ai_title";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LatestSessionView {
    /// The most recent session's recorded title (redacted); omitted in privacy mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// `ai_title`: an AI-generated title recorded by Claude Code; `null` when none is recorded.
    pub title_source: Option<&'static str>,
    pub last_activity_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionsView {
    pub count: u64,
    pub latest: Option<LatestSessionView>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ActivityView {
    pub status: Status,
    pub at: Option<i64>,
    /// Local calendar days since `at` (0 = today; never negative), from the same calculation as
    /// `status`, so the UI's "N days ago" always agrees with the bucket. `null` when unknown.
    pub days_ago: Option<i64>,
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
    /// Canonical absolute path (omitted in privacy mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `~/…` when the project is inside the home directory, else the absolute path (omitted in
    /// privacy mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_path: Option<String>,
    pub sources: Vec<String>,
    pub first_seen_at: i64,
    pub activity: ActivityView,
    /// `null` until Git was inspected.
    pub git: Option<GitView>,
    pub missing_since: Option<i64>,
    pub ignored: bool,
    /// `watched`, `partial` (root live, some subtrees checked at each scan), `polled` (checked
    /// at each scan), or `null` when not monitored (ignored, missing, not yet set up).
    pub monitoring: Option<Monitoring>,
    pub monitoring_reason: Option<PollReason>,
    pub sessions: SessionsView,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HeadView {
    pub hash: String,
    pub short: String,
    pub subject: Option<String>,
    /// Omitted in privacy mode (a user name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitDetail {
    pub head: Option<HeadView>,
    /// Sanitized: credentials removed. Omitted in privacy mode.
    #[serde(skip_serializing_if = "Option::is_none")]
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

fn sessions_view(s: &SessionSummary, privacy: Privacy) -> SessionsView {
    SessionsView {
        count: s.count,
        latest: (s.count > 0).then(|| LatestSessionView {
            title_source: s.latest_title.as_ref().map(|_| TITLE_SOURCE_AI),
            title: privacy.keep(s.latest_title.clone()),
            last_activity_at: s.latest_at,
        }),
    }
}

pub fn project_view(
    row: &ProjectRow,
    classifier: &Classifier,
    now: i64,
    home: &Path,
    monitoring: Option<(Monitoring, Option<PollReason>)>,
    privacy: Privacy,
) -> ProjectView {
    ProjectView {
        id: row.id.clone(),
        name: row.name.clone(),
        path: privacy.keep(Some(row.path.clone())),
        display_path: privacy.keep(Some(display_path(&row.path, home))),
        sources: row.sources.clone(),
        first_seen_at: row.first_seen_at,
        activity: ActivityView {
            status: classifier.status(row.activity_at, now),
            at: row.activity_at,
            days_ago: row
                .activity_at
                .and_then(|at| classifier.days_ago(at, now))
                .map(|d| d.max(0)),
            kind: row.activity_kind.clone(),
            path: row.activity_path.clone(),
        },
        git: row.git.as_ref().map(git_view),
        missing_since: row.missing_since,
        ignored: row.ignored,
        monitoring: monitoring.map(|m| m.0),
        monitoring_reason: monitoring.and_then(|m| m.1),
        sessions: sessions_view(&row.sessions, privacy),
    }
}

pub fn git_detail(g: &GitRow, privacy: Privacy) -> GitDetail {
    GitDetail {
        head: g.head_commit.as_ref().map(|h| HeadView {
            short: h.chars().take(12).collect(),
            hash: h.clone(),
            subject: g.head_subject.clone(),
            author: privacy.keep(g.head_author.clone()),
            time: g.head_time,
        }),
        remote_url: privacy.keep(g.remote_url.clone()),
        files: g
            .files
            .as_deref()
            .and_then(|f| serde_json::from_str(f).ok()),
    }
}

/// A prompt read on demand (redacted, truncated), or why there is none.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PromptView {
    /// `found`, `none` (no genuine prompt in the window read), `unreadable` (the session file
    /// could not be read) or `hidden` (privacy mode).
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub truncated: bool,
    pub at: Option<i64>,
    /// The whole file was searched (`false`: only the 4 MiB window at its start or end).
    pub whole_file: Option<bool>,
}

impl PromptView {
    pub fn hidden() -> Self {
        Self {
            state: "hidden",
            text: None,
            truncated: false,
            at: None,
            whole_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResumeView {
    /// The session the command resumes: the latest recorded continuation, if any.
    pub session_id: String,
    /// `cd -- '<first recorded cwd>' && claude --resume <id>`; `null` without a valid id or cwd,
    /// and omitted in privacy mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The cwd the command changes to (omitted in privacy mode; escaped when it holds control or
    /// bidi characters, see `resume::display`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// With `continuation_other_project` / `continuation_unassigned`: the first cwd of the
    /// continuation that was not followed (omitted otherwise and in privacy mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_cwd: Option<String>,
    /// The command resumes a later session this one was continued in.
    pub via_continuation: bool,
    /// `claude_not_found`, `claude_unverified`, `resume_unsupported`, `cwd_missing`, `no_cwd`,
    /// `cwd_unsafe_characters`, `continuation_not_indexed`, `continuation_other_project`,
    /// `continuation_unassigned`.
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionView {
    pub id: String,
    pub started_at: Option<i64>,
    pub last_activity_at: Option<i64>,
    /// Seconds between the first and last recorded activity (only when both are known).
    pub duration_s: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub title_source: Option<&'static str>,
    pub git_branch: Option<String>,
    /// Claude Code version that wrote the session.
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_cwd: Option<String>,
    /// The session changed directory after it started.
    pub cwd_changed: bool,
    pub last_prompt: PromptView,
    /// Only when the session has no recorded title (labelled "first prompt").
    pub first_prompt: Option<PromptView>,
    pub resume: ResumeView,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionList {
    pub items: Vec<SessionView>,
    /// Sessions of the project in the index.
    pub total: u64,
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
        let d = git_detail(&git(Some(1)), Privacy::Off);
        assert_eq!(d.head.as_ref().unwrap().short.len(), 12);
        assert_eq!(d.head.unwrap().author.as_deref(), Some("A"));
        assert_eq!(d.files.unwrap()["staged"][0], "x");
        let private = serde_json::to_value(git_detail(&git(Some(1)), Privacy::On)).unwrap();
        assert!(private["head"].get("author").is_none(), "{private}");
        assert!(private.get("remote_url").is_none());
        assert_eq!(
            private["head"]["subject"], "s",
            "commit subjects are not hidden"
        );
    }

    #[test]
    fn days_ago_comes_from_the_same_calendar_calculation_as_the_status() {
        use jiff::tz::TimeZone;
        let c = Classifier::new(
            TimeZone::posix("EST5EDT,M3.2.0,M11.1.0").unwrap(),
            &crate::config::ActivityConfig::default(),
        );
        // 2026-06-30 10:00 EDT; the change was 2026-06-23 23:00 EDT (6.46 × 24 h earlier).
        let now = 1_782_828_000;
        let row = |at: Option<i64>| ProjectRow {
            id: "a".repeat(32),
            sort_key: "p".into(),
            k1: 0,
            name: "p".into(),
            path: "/home/u/p".into(),
            sources: vec!["marker".into()],
            first_seen_at: 0,
            activity_at: at,
            activity_kind: Some("observed".into()),
            activity_path: None,
            missing_since: None,
            ignored: false,
            git: None,
            sessions: SessionSummary::default(),
        };
        let v = project_view(
            &row(Some(now - 155 * 3600)),
            &c,
            now,
            Path::new("/home/u"),
            None,
            Privacy::Off,
        );
        assert_eq!(v.activity.days_ago, Some(7));
        assert_eq!(v.activity.status, Status::Inactive);
        let v = project_view(
            &row(Some(now + 3600)),
            &c,
            now,
            Path::new("/home/u"),
            None,
            Privacy::Off,
        );
        assert_eq!(
            v.activity.days_ago,
            Some(0),
            "future times count as today, never negative"
        );
        assert_eq!(v.activity.status, Status::Today);
        let v = project_view(
            &row(None),
            &c,
            now,
            Path::new("/home/u"),
            None,
            Privacy::Off,
        );
        assert_eq!(
            (v.activity.days_ago, v.activity.status),
            (None, Status::Unknown)
        );
    }
}
