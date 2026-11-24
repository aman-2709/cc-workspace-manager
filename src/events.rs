//! Live updates (REQUIREMENTS.md §9 "Live updates", §12 `/ws`).
//!
//! Producers (tracker, service) report *what changed* through a bounded [`Notifier`]; one
//! publisher task coalesces changes for [`COALESCE`], builds the messages once (project views,
//! stats, discovery and monitoring status) and broadcasts them as pre-serialized JSON on the
//! [`Hub`]. A WebSocket client that falls behind the bounded broadcast buffer gets `resync` and
//! fetches a fresh snapshot; if the change queue itself overflows, every client gets `resync`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

pub const CHANGE_QUEUE: usize = 4096;
pub const BROADCAST_BUFFER: usize = 256;
/// Changes are collected this long before messages are built.
pub const COALESCE: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The project was added or changed (send its current view).
    Project(String),
    /// The project row no longer exists.
    Removed(String),
    /// Discovery progress or monitoring state changed.
    Status,
}

#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::Sender<Change>,
    lost: Arc<AtomicBool>,
}

impl Notifier {
    pub fn channel() -> (Self, mpsc::Receiver<Change>) {
        let (tx, rx) = mpsc::channel(CHANGE_QUEUE);
        (
            Self {
                tx,
                lost: Arc::new(AtomicBool::new(false)),
            },
            rx,
        )
    }

    fn send(&self, c: Change) {
        if self.tx.try_send(c).is_err() && !self.tx.is_closed() {
            self.lost.store(true, Ordering::Relaxed);
        }
    }

    pub fn project(&self, id: &str) {
        self.send(Change::Project(id.to_string()));
    }
    pub fn removed(&self, id: &str) {
        self.send(Change::Removed(id.to_string()));
    }
    pub fn status(&self) {
        self.send(Change::Status);
    }

    /// True (once) if changes were dropped because the queue was full.
    pub fn take_lost(&self) -> bool {
        self.lost.swap(false, Ordering::Relaxed)
    }
}

/// A coalesced batch of changes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Batch {
    pub changed: BTreeSet<String>,
    pub removed: BTreeSet<String>,
    pub status: bool,
}

impl Batch {
    pub fn add(&mut self, c: Change) {
        match c {
            Change::Project(id) => {
                self.removed.remove(&id);
                self.changed.insert(id);
            }
            Change::Removed(id) => {
                self.changed.remove(&id);
                self.removed.insert(id);
            }
            Change::Status => self.status = true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.removed.is_empty() && !self.status
    }
}

/// Wait for the first change, then collect for [`COALESCE`]. `None` when every producer is gone.
pub async fn next_batch(rx: &mut mpsc::Receiver<Change>) -> Option<Batch> {
    let first = rx.recv().await?;
    let mut b = Batch::default();
    b.add(first);
    let deadline = tokio::time::Instant::now() + COALESCE;
    loop {
        tokio::select! {
            c = rx.recv() => match c {
                Some(c) => b.add(c),
                None => break,
            },
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    Some(b)
}

/// Outgoing messages, serialized once and shared by every client.
#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<Arc<str>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(BROADCAST_BUFFER).0,
        }
    }
}

impl Hub {
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<str>> {
        self.tx.subscribe()
    }

    pub fn send(&self, msg: &serde_json::Value) {
        let _ = self.tx.send(Arc::from(msg.to_string()));
    }

    pub fn clients(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// Resolve once `stop` is (or becomes) true, or its sender is gone. (`wait_for`'s guard is not
/// `Send`, so it must not be held across the select arms of a spawned task.)
pub async fn until_stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|s| *s).await;
}

pub fn resync() -> serde_json::Value {
    serde_json::json!({ "type": "resync" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_coalesce_and_later_changes_win() {
        let mut b = Batch::default();
        b.add(Change::Project("a".into()));
        b.add(Change::Project("a".into()));
        b.add(Change::Removed("a".into()));
        b.add(Change::Removed("b".into()));
        b.add(Change::Project("b".into()));
        assert_eq!(b.changed.iter().collect::<Vec<_>>(), ["b"]);
        assert_eq!(b.removed.iter().collect::<Vec<_>>(), ["a"]);
        assert!(!b.status && !b.is_empty());
        b.add(Change::Status);
        assert!(b.status);
    }

    #[tokio::test]
    async fn next_batch_collects_for_the_window_and_overflow_is_flagged() {
        let (n, mut rx) = Notifier::channel();
        n.project("x");
        n.status();
        let b = next_batch(&mut rx).await.unwrap();
        assert!(b.changed.contains("x") && b.status);
        for i in 0..CHANGE_QUEUE + 10 {
            n.project(&i.to_string());
        }
        assert!(n.take_lost());
        assert!(!n.take_lost(), "reported once");
        drop(n);
        while rx.try_recv().is_ok() {}
        assert!(next_batch(&mut rx).await.is_none());
    }
}
