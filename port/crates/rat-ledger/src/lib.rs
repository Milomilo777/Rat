//! Platform-independent port of the macOS app's `Ledger` + `AlertCenter` logic
//! (App/Model/Ledger.swift, App/Model/AlertCenter.swift on main b56220e).
//! Spec: ZCODE/specs/port-ledger.md.

pub mod alerts;
pub mod answers;
pub mod ingest;
pub mod shared;

pub use alerts::{Alert, AlertCenter, AlertCenterConfig};
pub use answers::{rule_from_answer, AnswerScope};
pub use ingest::{
    AppEntry, ConnectionDetails, EnforcementPlan, IngestSummary, Ledger, LedgerConfig, RemoteEntry,
    RemoteKey,
};
pub use shared::{is_shared_service, note as shared_service_note};

use rat_core::Verdict;
use std::net::SocketAddr;

/// Decides what happens to a connection. Spec signature (supervisor instruction);
/// `app` is the executable path, `host` the display name when one is known.
pub trait Policy {
    fn evaluate(&self, app: &str, remote: &SocketAddr, host: Option<&str>) -> Verdict;
}

/// Adapter: rat-core's rule engine behind the [`Policy`] trait.
/// LIMITATION (spec, reuse decision 2): the trait carries no protocol, so the
/// engine is probed with TCP.
pub struct RuleEnginePolicy(pub rat_core::RuleEngine);

impl Policy for RuleEnginePolicy {
    fn evaluate(&self, app: &str, remote: &SocketAddr, host: Option<&str>) -> Verdict {
        let conn = rat_core::AppConnection::new(
            rat_core::AppIdentity::new(None, None, app.to_string()),
            host.map(str::to_string),
            remote.ip().to_string(),
            remote.port(),
            rat_types::Protocol::Tcp,
        );
        self.0.evaluate(&conn)
    }
}

/// Naive registrable domain (App/Model/Geo.swift:144-148): last two labels,
/// unchanged for shorter hosts and IP literals.
pub fn registrable_domain(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}
