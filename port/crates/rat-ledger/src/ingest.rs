//! Connection ingestion: app grouping, byte totals/rates, verdict counting and
//! the derived enforcement plan. Port of Ledger.swift's ingest/refreshEnforcement.

use crate::alerts::{Alert, AlertCenter, AlertCenterConfig};
use crate::Policy;
use rat_core::Verdict;
use rat_types::{Connection, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

/// Ledger.swift:230: don't alert for sockets that already existed at launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConfig {
    pub warmup_ms: u64,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self { warmup_ms: 12_000 }
    }
}

/// v1.2.0 per-connection details (Ledger.swift:31-48): the process behind the
/// socket (an app's helper or the system service), the network owner from the
/// ASN database, VPN/proxy route marks and the usual service on the port.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionDetails {
    pub process: Option<String>,
    pub service_name: Option<String>,
    pub network_owner: Option<String>,
    pub vpn_mark: Option<String>,
    pub proxy_mark: Option<String>,
    /// The "system service" row equivalent: a socket held by a shared service host.
    pub shared_service: bool,
}

/// Identity of one remote as shown in the UI (dedup like Ledger.swift:320-321).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RemoteKey {
    pub address: IpAddr,
    pub port: u16,
    pub proto: Protocol,
    /// The process behind the socket, when known.
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub key: RemoteKey,
    /// Display host: the name when one is known, else the address string.
    pub host: String,
    pub details: ConnectionDetails,
    pub total_in: u64,
    pub total_out: u64,
    pub rate_in: f64,
    pub rate_out: f64,
}

/// Ledger.swift:50-61 AppEntry, keyed by executable path on Windows/Linux (spec R1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppEntry {
    pub app: String,
    pub pids: HashSet<u32>,
    pub remotes: Vec<RemoteEntry>,
    pub listening: usize,
    /// Last 14 (rx, tx) rate samples (Ledger.swift:289).
    pub rates: VecDeque<(f64, f64)>,
    pub total_in: u64,
    pub total_out: u64,
    pub last_active_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngestSummary {
    pub denied: usize,
    pub unconfirmed: usize,
    pub listening: usize,
}

/// What the enforcement layer should block (Ledger.swift:384-389): whole apps by
/// path and the LOCAL ports of rule-denied sockets. Never server addresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub denied_apps: BTreeSet<String>,
    pub denied_local_ports: BTreeSet<u16>,
}

/// Per-connection byte-counter baseline identity (socket reuse detection, R2).
type ConnId = (u32, SocketAddr, Option<SocketAddr>, Protocol);

pub struct Ledger {
    config: LedgerConfig,
    pub alerts: AlertCenter,
    apps: BTreeMap<String, AppEntry>,
    baselines: HashMap<ConnId, (u64, u64)>,
    last_tick_ms: Option<u64>,
    started_ms: Option<u64>,
    session_in: u64,
    session_out: u64,
    rate_in: f64,
    rate_out: f64,
    plan: EnforcementPlan,
}

impl Ledger {
    pub fn new(config: LedgerConfig, alerts: AlertCenterConfig) -> Self {
        todo!("R1 construct")
    }

    /// Ingest one sample (Ledger.swift:226-354): groups by exe path, accumulates
    /// byte totals/rates per app and remote (never negative on counter reset),
    /// counts verdicts, reports Ask connections as alerts after warmup, and
    /// recomputes the enforcement plan (denied apps + denied local ports).
    pub fn ingest(
        &mut self,
        policy: &dyn Policy,
        now_ms: u64,
        conns: &[Connection],
        details: &dyn Fn(&Connection) -> ConnectionDetails,
    ) -> IngestSummary {
        todo!("R1/R2/R4/R6 ingest")
    }

    pub fn apps(&self) -> impl Iterator<Item = &AppEntry> {
        self.apps.values()
    }

    pub fn app(&self, path: &str) -> Option<&AppEntry> {
        self.apps.get(path)
    }

    /// Session totals and current whole-system rates (Ledger.swift:274-275).
    pub fn session(&self) -> (u64, u64) {
        (self.session_in, self.session_out)
    }

    pub fn rates(&self) -> (f64, f64) {
        (self.rate_in, self.rate_out)
    }

    /// The enforcement plan derived from the latest ingest (R4: always derived,
    /// never accumulated — removing a rule shrinks it on the next ingest).
    pub fn enforcement(&self) -> &EnforcementPlan {
        &self.plan
    }

    fn report_alert(
        &mut self,
        conn: &Connection,
        app: &str,
        host: &str,
        details: &ConnectionDetails,
        now_ms: u64,
    ) {
        let _ = (conn, app, host, details, now_ms);
        let _ = Alert { app: String::new(), app_name: String::new(), host: String::new(), remote: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0), proto: Protocol::Tcp, details: ConnectionDetails::default(), reported_ms: 0 };
        todo!("R3 report")
    }
}
