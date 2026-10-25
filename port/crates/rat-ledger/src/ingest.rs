//! Connection ingestion: app grouping, byte totals/rates, verdict counting and
//! the derived enforcement plan. Port of Ledger.swift's ingest/refreshEnforcement.

use crate::alerts::{Alert, AlertCenter, AlertCenterConfig};
use crate::{registrable_domain, Policy};
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
    /// Reverse-DNS display name (Ledger.swift:322 `names.name(for:)`); filled by
    /// the daemon's details closure once rat-names is wired.
    #[serde(default)]
    pub host_name: Option<String>,
    /// GeoIP country of the remote (feeds the Summary's country list).
    #[serde(default)]
    pub country: Option<String>,
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

/// Swift probes whole-app denial with TEST-NET-3 (Ledger.swift:411).
const PROBE: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)), 443);

/// Loopback/private/link-local remotes are listed but never judged or enforced
/// (Ledger.swift:329 `guard !isLocalAddress(...)`, App/Model/Geo.swift:150-152).
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
    }
}

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
    /// System-wide (timestamp_ms, rx, tx) per refresh, capped at 2400 points
    /// (Ledger.swift:276-277) — the live feed for chart ranges up to an hour.
    history: VecDeque<(u64, f64, f64)>,
    /// System totals per minute, keyed by `timestamp_ms / 60_000`, pruned past
    /// a week (Ledger.swift:279-281, :180) — the feed for day/week charts.
    buckets: BTreeMap<u64, (f64, f64)>,
}

impl Ledger {
    pub fn new(config: LedgerConfig, alerts: AlertCenterConfig) -> Self {
        Self {
            config,
            alerts: AlertCenter::new(alerts),
            apps: BTreeMap::new(),
            baselines: HashMap::new(),
            last_tick_ms: None,
            started_ms: None,
            session_in: 0,
            session_out: 0,
            rate_in: 0.0,
            rate_out: 0.0,
            plan: EnforcementPlan::default(),
            history: VecDeque::new(),
            buckets: BTreeMap::new(),
        }
    }

    /// App key (R1): the executable path; `<unknown>` when the monitor could not see one.
    fn app_key(c: &Connection) -> String {
        c.process
            .exe
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    /// Ingest one sample (Ledger.swift:226-354): groups by exe path (R1),
    /// accumulates byte totals/rates per app and remote — never negative on a
    /// counter reset (R2) — counts verdicts, reports Ask connections as alerts
    /// after warmup (R3), rebuilds remotes with their v1.2.0 details (R6) and
    /// recomputes the enforcement plan (R4).
    pub fn ingest(
        &mut self,
        policy: &dyn Policy,
        now_ms: u64,
        conns: &[Connection],
        details: &dyn Fn(&Connection) -> ConnectionDetails,
    ) -> IngestSummary {
        let started = *self.started_ms.get_or_insert(now_ms);
        let warmed_up = now_ms.saturating_sub(started) >= self.config.warmup_ms;

        let dt = match self.last_tick_ms {
            Some(t) => (now_ms.saturating_sub(t)) as f64 / 1000.0,
            None => 0.2,
        };
        let dt = dt.max(0.2);
        self.last_tick_ms = Some(now_ms);

        // R1: group the sample by executable path.
        let mut listening_by_app: BTreeMap<String, usize> = BTreeMap::new();
        let mut conns_by_app: BTreeMap<String, Vec<&Connection>> = BTreeMap::new();
        let mut listening_total = 0usize;
        for c in conns {
            let app = Self::app_key(c);
            let entry = self.apps.entry(app.clone()).or_insert_with(|| AppEntry {
                app: app.clone(),
                ..Default::default()
            });
            entry.pids.insert(c.process.pid);
            if c.listening {
                *listening_by_app.entry(app).or_insert(0) += 1;
                listening_total += 1;
            } else {
                conns_by_app.entry(app).or_default().push(c);
            }
        }

        // R2: deltas from the previous sample. The baseline is ALWAYS updated
        // (Swift's `defer { previous[t.pid] = t }`); a delta is accumulated only
        // when both counters are monotonic, so a reused socket can never produce
        // a negative rate.
        let mut rx_by_app: HashMap<String, f64> = HashMap::new();
        let mut tx_by_app: HashMap<String, f64> = HashMap::new();
        let mut remote_deltas: BTreeMap<String, HashMap<RemoteKey, (f64, f64)>> = BTreeMap::new();
        for c in conns {
            let (Some(bytes_in), Some(bytes_out)) = (c.bytes_in, c.bytes_out) else {
                continue;
            };
            let id = (c.process.pid, c.local, c.remote, c.protocol);
            let prev = self.baselines.insert(id, (bytes_in, bytes_out));
            let Some((prev_in, prev_out)) = prev else {
                continue; // first sighting: baseline only
            };
            if bytes_in < prev_in || bytes_out < prev_out {
                continue; // counter went backwards (socket reused): skip this sample
            }
            let (d_in, d_out) = ((bytes_in - prev_in) as f64, (bytes_out - prev_out) as f64);
            let app = Self::app_key(c);
            *rx_by_app.entry(app.clone()).or_insert(0.0) += d_in;
            *tx_by_app.entry(app.clone()).or_insert(0.0) += d_out;
            if let Some(remote) = c.remote {
                let key = RemoteKey {
                    address: remote.ip(),
                    port: remote.port(),
                    proto: c.protocol,
                    process: Some(c.process.name.clone()),
                };
                let acc = remote_deltas
                    .entry(app)
                    .or_default()
                    .entry(key)
                    .or_insert((0.0, 0.0));
                acc.0 += d_in;
                acc.1 += d_out;
            }
        }
        let total_rx: f64 = rx_by_app.values().sum();
        let total_tx: f64 = tx_by_app.values().sum();
        self.session_in += total_rx as u64;
        self.session_out += total_tx as u64;
        self.rate_in = total_rx / dt;
        self.rate_out = total_tx / dt;

        // Chart feeds (Ledger.swift:276-281): a live system point per refresh
        // (capped at 2400) and per-minute buckets, pruned past a week.
        self.history.push_back((now_ms, total_rx, total_tx));
        if self.history.len() > 2400 {
            self.history.pop_front();
        }
        let minute = now_ms / 60_000;
        let week_of_minutes = 7 * 24 * 60;
        let b = self.buckets.entry(minute).or_insert((0.0, 0.0));
        b.0 += total_rx;
        b.1 += total_tx;
        let cutoff = minute.saturating_sub(week_of_minutes);
        self.buckets.retain(|&m, _| m >= cutoff);

        // R6 + R2 per app: rebuild remotes from the current sample (Swift :347
        // `e.remotes = remotes`), merging this tick's per-remote deltas.
        let mut denied = 0usize;
        let mut unconfirmed = 0usize;
        let mut denied_local_ports: BTreeSet<u16> = BTreeSet::new();
        for (app, sample) in &conns_by_app {
            let mut remotes: Vec<RemoteEntry> = Vec::new();
            let mut seen: HashSet<RemoteKey> = HashSet::new();
            for c in sample {
                let Some(remote) = c.remote else { continue };
                let key = RemoteKey {
                    address: remote.ip(),
                    port: remote.port(),
                    proto: c.protocol,
                    process: Some(c.process.name.clone()),
                };
                if !seen.insert(key.clone()) {
                    continue;
                }
                let (d_in, d_out) = remote_deltas
                    .get(app)
                    .and_then(|m| m.get(&key))
                    .copied()
                    .unwrap_or((0.0, 0.0));
                let d = details(c);
                // Display host: the name when one is known, else the address
                // string (Ledger.swift:300,322).
                let host = d.host_name.clone().unwrap_or_else(|| remote.to_string());
                remotes.push(RemoteEntry {
                    host,
                    details: d,
                    total_in: d_in as u64,
                    total_out: d_out as u64,
                    rate_in: d_in / dt,
                    rate_out: d_out / dt,
                    key,
                });
            }

            // R4: verdict per outbound remote; local remotes are listed but never
            // judged (Ledger.swift:329). Only the LOCAL port of a denied socket is
            // ever blocked (:330-332), never the server address.
            for c in sample {
                let Some(remote) = c.remote else { continue };
                if is_local(remote.ip()) {
                    continue;
                }
                match policy.evaluate(app, &remote, None) {
                    Verdict::Deny => {
                        denied += 1;
                        if c.local.port() != 0 {
                            denied_local_ports.insert(c.local.port());
                        }
                    }
                    Verdict::Ask => {
                        unconfirmed += 1;
                        if warmed_up {
                            self.alerts.report(Alert {
                                app: app.clone(),
                                app_name: c.process.name.clone(),
                                host: remote.to_string(),
                                remote,
                                proto: c.protocol,
                                details: details(c),
                                reported_ms: now_ms,
                            });
                        }
                    }
                    Verdict::Allow => {}
                }
            }

            if let Some(entry) = self.apps.get_mut(app) {
                let rx = rx_by_app.get(app).copied().unwrap_or(0.0);
                let tx = tx_by_app.get(app).copied().unwrap_or(0.0);
                entry.listening = listening_by_app.get(app).copied().unwrap_or(0);
                entry.remotes = remotes;
                entry.total_in += rx as u64;
                entry.total_out += tx as u64;
                entry.rates.push_back((rx, tx));
                if entry.rates.len() > 14 {
                    entry.rates.pop_front();
                }
                if rx + tx > 0.0 {
                    entry.last_active_ms = now_ms;
                }
            }
        }

        // R4: whole-app denial, probed like Swift's 203.0.113.9:443 check
        // (Ledger.swift:411). Through the Policy seam the probe IS the answer:
        // an app with an allow rule probes as Allow.
        let denied_apps: BTreeSet<String> = self
            .apps
            .keys()
            .filter(|app| policy.evaluate(app, &PROBE, None) == Verdict::Deny)
            .cloned()
            .collect();

        self.plan = EnforcementPlan {
            denied_apps,
            denied_local_ports,
        };

        // The daemon loop re-validates queued alerts after every pass
        // (Ledger.swift:210).
        self.alerts.revalidate(policy);

        IngestSummary {
            denied,
            unconfirmed,
            listening: listening_total,
        }
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

    /// Live system history points `(timestamp_ms, rx, tx)`, oldest first —
    /// the feed for [`crate::chart_layout`] ranges up to an hour.
    pub fn history(&self) -> impl Iterator<Item = (u64, f64, f64)> + '_ {
        self.history.iter().copied()
    }

    /// Per-minute system buckets `(minute_index, rx, tx)` — the feed for
    /// day/week chart ranges. Multiply the key by 60_000 for a timestamp.
    pub fn buckets(&self) -> impl Iterator<Item = (u64, f64, f64)> + '_ {
        self.buckets.iter().map(|(&m, &(rx, tx))| (m, rx, tx))
    }

    pub fn rates(&self) -> (f64, f64) {
        (self.rate_in, self.rate_out)
    }

    /// The enforcement plan derived from the latest ingest (R4: always derived,
    /// never accumulated — removing a rule shrinks it on the next ingest).
    pub fn enforcement(&self) -> &EnforcementPlan {
        &self.plan
    }

    /// Summary: registrable domains by remote count (Ledger.swift:424-428).
    /// Swift sorts by count only (ties come out in dictionary order); here ties
    /// break by name ascending so the order is deterministic.
    pub fn domains(&self) -> Vec<(String, usize)> {
        let mut d: BTreeMap<String, usize> = BTreeMap::new();
        for app in self.apps.values() {
            for r in &app.remotes {
                *d.entry(registrable_domain(&summary_host(&r.host)))
                    .or_default() += 1;
            }
        }
        sorted_by_count(d)
    }

    /// Summary: ASN network owners by remote count (Ledger.swift:431-435).
    pub fn networks(&self) -> Vec<(String, usize)> {
        let mut d: BTreeMap<String, usize> = BTreeMap::new();
        for app in self.apps.values() {
            for r in &app.remotes {
                if let Some(owner) = &r.details.network_owner {
                    *d.entry(owner.clone()).or_default() += 1;
                }
            }
        }
        sorted_by_count(d)
    }

    /// Summary: countries by remote count (Ledger.swift:437-441).
    pub fn countries(&self) -> Vec<(String, usize)> {
        let mut d: BTreeMap<String, usize> = BTreeMap::new();
        for app in self.apps.values() {
            for r in &app.remotes {
                if let Some(country) = &r.details.country {
                    *d.entry(country.clone()).or_default() += 1;
                }
            }
        }
        sorted_by_count(d)
    }
}

/// The host part of a `RemoteEntry::host`: strip the `:port` (or `[v6]:port`)
/// when the string is an address-with-port, keep names as they are.
fn summary_host(host: &str) -> String {
    if let Ok(sa) = host.parse::<SocketAddr>() {
        return sa.ip().to_string();
    }
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(str::to_string)
        .unwrap_or_else(|| host.to_string())
}

/// Count-descending, name-ascending order shared by the summary lists.
fn sorted_by_count(d: BTreeMap<String, usize>) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = d.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}
