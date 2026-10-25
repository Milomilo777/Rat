//! Alert queue: one prompt per (app, registrable domain of host) until answered,
//! re-validated against the policy every tick. Port of AlertCenter.swift.

use crate::ingest::ConnectionDetails;
use crate::Policy;
use rat_core::{Lifetime, Verdict};
use rat_types::Protocol;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

/// One queued connection prompt (AlertCenter.swift:8-21). The dedup key is
/// `app|registrableDomain(host)` (:20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub app: String,
    pub app_name: String,
    /// Display host (the address itself when no name is known).
    pub host: String,
    pub remote: SocketAddr,
    pub proto: Protocol,
    pub details: ConnectionDetails,
    pub reported_ms: u64,
}

impl Alert {
    pub fn key(&self) -> String {
        format!("{}|{}", self.app, crate::registrable_domain(&self.host))
    }
}

/// Settings > Alert equivalents (AlertCenter.swift:89-102): 0 = never time out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCenterConfig {
    pub timeout_ms: u64,
    pub timeout_verdict: Verdict,
}

impl Default for AlertCenterConfig {
    fn default() -> Self {
        Self { timeout_ms: 0, timeout_verdict: Verdict::Allow }
    }
}

impl AlertCenterConfig {
    pub fn timeout(&self) -> Option<Duration> {
        if self.timeout_ms == 0 { None } else { Some(Duration::from_millis(self.timeout_ms)) }
    }
}

/// Outcomes of answering, for the caller's rule bookkeeping (AlertCenter.swift:68-77).
#[derive(Debug, Clone)]
pub struct Answer {
    pub alert: Alert,
    pub verdict: Verdict,
    pub lifetime: Lifetime,
}

#[derive(Debug, Default)]
pub struct AlertCenter {
    config: AlertCenterConfig,
    queue: VecDeque<Alert>,
    answered_or_queued: HashSet<String>,
    current: Option<Alert>,
    current_since_ms: u64,
}

impl AlertCenter {
    pub fn new(config: AlertCenterConfig) -> Self {
        Self { config, ..Default::default() }
    }

    /// One alert per key until answered (AlertCenter.swift:44-49). Returns true when queued.
    pub fn report(&mut self, alert: Alert) -> bool {
        todo!("R3 report dedup")
    }

    /// Drops queued + current alerts the policy no longer considers unanswered (:52-66).
    pub fn revalidate(&mut self, policy: &dyn Policy) {
        todo!("R3 revalidate")
    }

    /// The alert being presented, if any (:42 pendingCount / current).
    pub fn current(&self) -> Option<&Alert> {
        self.current.as_ref()
    }

    pub fn pending_count(&self) -> usize {
        todo!("R3 pending count")
    }

    /// Answers the current alert; a `Once` answer forgets the key so the same
    /// (app, host) may prompt again later (:73).
    pub fn answer_current(&mut self, verdict: Verdict, lifetime: Lifetime) -> Option<Answer> {
        todo!("R3 answer")
    }

    /// Presents the next pending alert and resolves the current one when its
    /// timeout expires with the configured default verdict (:79-102).
    /// Returns the timeout answer when one fired.
    pub fn tick(&mut self, now_ms: u64) -> Option<Answer> {
        todo!("R5 timeout")
    }
}
