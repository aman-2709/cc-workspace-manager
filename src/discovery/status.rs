//! Shared, cheaply clonable discovery status (what `/discovery/status` returns).

use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Idle,
    Scanning,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Skipped {
    pub permission: u64,
    pub vanished: u64,
    pub excluded: u64,
    pub non_utf8: u64,
    pub rejected_markers: u64,
    pub other: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RootStatus {
    pub path: String,
    /// `ok`, `missing`, `unreadable`, `not_a_directory`, `forbidden` or `non_utf8`.
    pub state: &'static str,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DiscoverySnapshot {
    pub phase: Phase,
    pub dirs_visited: u64,
    pub projects_found: u64,
    pub skipped: Skipped,
    pub roots: Vec<RootStatus>,
    pub last_success_at: Option<i64>,
    pub next_scan_at: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct SharedStatus(Arc<Mutex<DiscoverySnapshot>>);

impl SharedStatus {
    pub fn snapshot(&self) -> DiscoverySnapshot {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn update(&self, f: impl FnOnce(&mut DiscoverySnapshot)) {
        if let Ok(mut g) = self.0.lock() {
            f(&mut g);
        }
    }
}
