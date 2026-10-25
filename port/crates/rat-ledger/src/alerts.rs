//! Alert queue: one prompt per (app, registrable domain of host) until answered,
//! re-validated against the policy every tick. Port of AlertCenter.swift.

use crate::ingest::ConnectionDetails;
use crate::Policy;
use rat_core::{Lifetime, Verdict};
use rat_types::Protocol;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;

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
        Self {
            timeout_ms: 0,
            timeout_verdict: Verdict::Allow,
        }
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
        Self {
            config,
            ..Default::default()
        }
    }

    /// One alert per key until answered (AlertCenter.swift:44-49). Returns true when queued.
    pub fn report(&mut self, alert: Alert) -> bool {
        if !self.answered_or_queued.insert(alert.key()) {
            return false;
        }
        self.queue.push_back(alert);
        true
    }

    /// False when rules, a policy button or the mode already answer this alert
    /// (Ledger.swift:109-113 wires this to the engine).
    fn still_pending(policy: &dyn Policy, a: &Alert) -> bool {
        policy.evaluate(&a.app, &a.remote, Some(&a.host)) == Verdict::Ask
    }

    /// Drops queued + current alerts the policy no longer considers unanswered
    /// (AlertCenter.swift:52-66); a dropped key may prompt again later.
    pub fn revalidate(&mut self, policy: &dyn Policy) {
        let mut kept = VecDeque::new();
        for a in std::mem::take(&mut self.queue) {
            if Self::still_pending(policy, &a) {
                kept.push_back(a);
            } else {
                self.answered_or_queued.remove(&a.key());
            }
        }
        self.queue = kept;
        if let Some(c) = self.current.take() {
            if Self::still_pending(policy, &c) {
                self.current = Some(c);
            } else {
                self.answered_or_queued.remove(&c.key());
            }
        }
    }

    /// The alert being presented, if any.
    pub fn current(&self) -> Option<&Alert> {
        self.current.as_ref()
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len() + usize::from(self.current.is_some())
    }

    /// Answers the current alert; a `Once` answer forgets the key so the same
    /// (app, host) may prompt again later (AlertCenter.swift:73).
    pub fn answer_current(&mut self, verdict: Verdict, lifetime: Lifetime) -> Option<Answer> {
        let alert = self.current.take()?;
        if lifetime == Lifetime::Once {
            self.answered_or_queued.remove(&alert.key());
        }
        Some(Answer {
            alert,
            verdict,
            lifetime,
        })
    }

    /// Presents the next queued alert when idle, then resolves the current one
    /// when its timeout expires with the configured default verdict
    /// (AlertCenter.swift:79-102). Returns the timeout answer when one fired.
    pub fn tick(&mut self, now_ms: u64) -> Option<Answer> {
        if self.current.is_none() {
            if let Some(next) = self.queue.pop_front() {
                self.current = Some(next);
                self.current_since_ms = now_ms;
            }
        }
        if let (Some(_), true) = (&self.current, self.config.timeout_ms > 0) {
            if now_ms.saturating_sub(self.current_since_ms) >= self.config.timeout_ms {
                return self.answer_current(self.config.timeout_verdict, Lifetime::Once);
            }
        }
        None
    }
}
