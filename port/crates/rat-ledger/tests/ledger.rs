//! rat-ledger acceptance tests (spec ZCODE/specs/port-ledger.md, R1..R6).
//! Fake policy + fake samples + explicit time; no real clock, no real names.

use rat_core::{Lifetime, Verdict};
use rat_ledger::{
    registrable_domain, Alert, AlertCenter, AlertCenterConfig, ConnectionDetails, Ledger,
    LedgerConfig, Policy,
};
use rat_types::{Connection, ProcessInfo, Protocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

// ---------- helpers ----------

fn addr(a: [u8; 4], p: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), p)
}

fn conn(pid: u32, exe: &str, local: SocketAddr, remote: SocketAddr) -> Connection {
    Connection {
        process: ProcessInfo {
            pid,
            exe: Some(PathBuf::from(exe)),
            name: exe.rsplit('/').next().unwrap_or(exe).to_string(),
            user: None,
        },
        protocol: Protocol::Tcp,
        local,
        remote: Some(remote),
        listening: false,
        bytes_in: None,
        bytes_out: None,
    }
}

fn counters(mut c: Connection, bytes_in: u64, bytes_out: u64) -> Connection {
    c.bytes_in = Some(bytes_in);
    c.bytes_out = Some(bytes_out);
    c
}

/// First matching (app, host-suffix) rule wins; "" suffix matches any host.
struct FakePolicy {
    rules: Vec<(String, String, Verdict)>,
    default: Verdict,
}

impl Policy for FakePolicy {
    fn evaluate(&self, app: &str, remote: &SocketAddr, host: Option<&str>) -> Verdict {
        let host_str = host.unwrap_or("");
        for (a, suffix, v) in &self.rules {
            if a == app
                && (suffix.is_empty()
                    || host_str.ends_with(suffix.as_str())
                    || remote.ip().to_string().ends_with(suffix.as_str()))
            {
                return *v;
            }
        }
        self.default
    }
}

fn ask_policy() -> FakePolicy {
    FakePolicy {
        rules: vec![],
        default: Verdict::Ask,
    }
}

fn allow_policy() -> FakePolicy {
    FakePolicy {
        rules: vec![],
        default: Verdict::Allow,
    }
}

fn ledger_warm() -> Ledger {
    Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default())
}

fn no_details(_: &Connection) -> ConnectionDetails {
    ConnectionDetails::default()
}

fn local_remote(port: u16) -> SocketAddr {
    addr([127, 0, 0, 1], port)
}

fn net_remote(port: u16) -> SocketAddr {
    addr([1, 2, 3, 4], port)
}

// ---------- R1: grouping ----------

#[test]
fn test_r1_groups_pids_by_exe_path() {
    let mut l = ledger_warm();
    let c1 = conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443));
    let c2 = conn(11, "/usr/bin/curl", local_remote(51001), net_remote(443));
    let c3 = conn(12, "/usr/bin/wget", local_remote(51002), net_remote(443));
    let p = allow_policy();
    l.ingest(&p, 1000, &[c1, c2, c3], &no_details);
    let apps: Vec<_> = l.apps().cloned().collect();
    assert_eq!(apps.len(), 2, "two executables -> two app entries");
    let curl = l.app("/usr/bin/curl").expect("curl entry");
    assert_eq!(
        curl.pids,
        [10, 11].into_iter().collect(),
        "both pids under one exe path"
    );
    assert!(l.app("/usr/bin/wget").is_some());
}

#[test]
fn test_r1_listening_counted_per_app() {
    let mut l = ledger_warm();
    let mut listener = conn(
        20,
        "/usr/bin/python",
        local_remote(8000),
        local_remote(8000),
    );
    listener.listening = true;
    listener.remote = None;
    let out = conn(21, "/usr/bin/python", local_remote(51010), net_remote(443));
    let p = allow_policy();
    let s = l.ingest(&p, 1000, &[listener, out], &no_details);
    assert_eq!(s.listening, 1);
    assert_eq!(l.app("/usr/bin/python").unwrap().listening, 1);
}

#[test]
fn test_r1_missing_exe_groups_unknown() {
    let mut l = ledger_warm();
    let mut c = conn(30, "/usr/bin/curl", local_remote(51020), net_remote(443));
    c.process.exe = None;
    let p = allow_policy();
    l.ingest(&p, 1000, &[c], &no_details);
    assert!(
        l.app("<unknown>").is_some(),
        "missing exe falls into the <unknown> group"
    );
}

// ---------- R2: totals + rates, never negative ----------

#[test]
fn test_r2_totals_and_rates_accumulate() {
    let mut l = ledger_warm();
    let c = |i, o| {
        counters(
            conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443)),
            i,
            o,
        )
    };
    let p = allow_policy();
    l.ingest(&p, 1000, &[c(100, 50)], &no_details); // baseline only
    l.ingest(&p, 2000, &[c(300, 150)], &no_details); // +200/+100 over 1s
    let e = l.app("/usr/bin/curl").unwrap();
    assert_eq!(e.total_in, 200);
    assert_eq!(e.total_out, 100);
    let (rin, rout) = l.rates();
    assert!((rin - 200.0).abs() < 1e-9, "rate in {rin}");
    assert!((rout - 100.0).abs() < 1e-9, "rate out {rout}");
    assert_eq!(l.session(), (200, 100));
}

#[test]
fn test_r2_counter_reset_never_negative() {
    let mut l = ledger_warm();
    let c = |i, o| {
        counters(
            conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443)),
            i,
            o,
        )
    };
    let p = allow_policy();
    l.ingest(&p, 1000, &[c(500, 500)], &no_details);
    l.ingest(&p, 2000, &[c(100, 100)], &no_details); // reuse: counter went backwards
    let (rin, rout) = l.rates();
    assert!(
        rin >= 0.0 && rout >= 0.0,
        "no negative rates after reset: {rin}/{rout}"
    );
    let e = l.app("/usr/bin/curl").unwrap();
    assert_eq!(e.total_in, 0, "reset sample contributes nothing");
    l.ingest(&p, 3000, &[c(150, 150)], &no_details); // +50 from the new baseline
    assert_eq!(l.app("/usr/bin/curl").unwrap().total_in, 50);
}

#[test]
fn test_r2_per_remote_totals() {
    let mut l = ledger_warm();
    let a = |i| {
        counters(
            conn(
                10,
                "/usr/bin/curl",
                local_remote(51000),
                addr([1, 1, 1, 1], 443),
            ),
            i,
            i,
        )
    };
    let b = |i| {
        counters(
            conn(
                10,
                "/usr/bin/curl",
                local_remote(51001),
                addr([8, 8, 8, 8], 53),
            ),
            i,
            i,
        )
    };
    let p = allow_policy();
    l.ingest(&p, 1000, &[a(0), b(0)], &no_details);
    l.ingest(&p, 2000, &[a(100), b(900)], &no_details);
    let e = l.app("/usr/bin/curl").unwrap();
    assert_eq!(e.remotes.len(), 2);
    for r in &e.remotes {
        let want = if r.key.port == 443 { 100 } else { 900 };
        assert_eq!(r.total_in, want, "remote {} total", r.host);
    }
    assert_eq!(e.total_in, 1000);
}

#[test]
fn test_r2_rates_ring_caps_at_14() {
    let mut l = ledger_warm();
    let c = |i| {
        counters(
            conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443)),
            i,
            i,
        )
    };
    let p = allow_policy();
    let mut t = 1000u64;
    for i in 0..16u64 {
        l.ingest(&p, t, &[c(i * 100)], &no_details);
        t += 1000;
    }
    assert_eq!(
        l.app("/usr/bin/curl").unwrap().rates.len(),
        14,
        "rate ring keeps the last 14 samples"
    );
}

// ---------- R3: alert dedup / revalidation / once ----------

#[test]
fn test_r3_one_alert_per_app_and_address() {
    let mut l = ledger_warm();
    let p = ask_policy();
    let c = conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443));
    l.ingest(&p, 1000, std::slice::from_ref(&c), &no_details);
    l.ingest(&p, 2500, std::slice::from_ref(&c), &no_details);
    assert_eq!(
        l.alerts.pending_count(),
        1,
        "same (app, address) asks only once"
    );
}

#[test]
fn test_r3_registrable_domain_collapses_subdomains() {
    let mut center = AlertCenter::new(AlertCenterConfig::default());
    let mk = |host: &str| Alert {
        app: "/usr/bin/curl".into(),
        app_name: "curl".into(),
        host: host.into(),
        remote: net_remote(443),
        proto: Protocol::Tcp,
        details: ConnectionDetails::default(),
        reported_ms: 0,
    };
    assert!(center.report(mk("a.example.com")));
    assert!(
        !center.report(mk("b.example.com")),
        "same registrable domain deduped"
    );
    assert!(
        center.report(mk("other.org")),
        "different domain -> new alert"
    );
    assert_eq!(center.pending_count(), 2);
}

#[test]
fn test_r3_revalidate_drops_answered_by_policy() {
    let mut center = AlertCenter::new(AlertCenterConfig::default());
    let a = Alert {
        app: "/usr/bin/curl".into(),
        app_name: "curl".into(),
        host: "example.com".into(),
        remote: net_remote(443),
        proto: Protocol::Tcp,
        details: ConnectionDetails::default(),
        reported_ms: 0,
    };
    center.report(a.clone());
    assert_eq!(center.pending_count(), 1);
    let allow = FakePolicy {
        rules: vec![("/usr/bin/curl".into(), "example.com".into(), Verdict::Allow)],
        default: Verdict::Ask,
    };
    center.revalidate(&allow);
    assert_eq!(
        center.pending_count(),
        0,
        "app gained an allow rule -> prompt withdrawn"
    );
    // and it may ask again later
    assert!(center.report(a));
}

#[test]
fn test_r3_answer_once_forgets_the_key() {
    let mut center = AlertCenter::new(AlertCenterConfig::default());
    let a = Alert {
        app: "/usr/bin/curl".into(),
        app_name: "curl".into(),
        host: "example.com".into(),
        remote: net_remote(443),
        proto: Protocol::Tcp,
        details: ConnectionDetails::default(),
        reported_ms: 0,
    };
    center.report(a.clone());
    center.tick(0);
    assert!(center.current().is_some());
    let answer = center
        .answer_current(Verdict::Deny, Lifetime::Once)
        .expect("answered");
    assert_eq!(answer.verdict, Verdict::Deny);
    assert!(center.current().is_none());
    assert!(
        center.report(a),
        "a once answer must not silence the next connection"
    );
}

#[test]
fn test_r3_warmup_suppresses_alerts() {
    let mut l = Ledger::new(
        LedgerConfig { warmup_ms: 12_000 },
        AlertCenterConfig::default(),
    );
    let p = ask_policy();
    let c = conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443));
    let s = l.ingest(&p, 1000, std::slice::from_ref(&c), &no_details);
    assert_eq!(
        l.alerts.pending_count(),
        0,
        "sockets that existed at launch never prompt"
    );
    assert_eq!(s.unconfirmed, 1, "still counted as unconfirmed");
    l.ingest(&p, 20_000, &[c], &no_details);
    assert_eq!(
        l.alerts.pending_count(),
        1,
        "after warmup the ask is reported"
    );
}

// ---------- R4: derived enforcement ----------

#[test]
fn test_r4_denied_connection_puts_local_port_in_plan() {
    let mut l = ledger_warm();
    let p = FakePolicy {
        rules: vec![("/usr/bin/curl".into(), "1.2.3.4".into(), Verdict::Deny)],
        default: Verdict::Allow,
    };
    let c = conn(10, "/usr/bin/curl", local_remote(54321), net_remote(443));
    let s = l.ingest(&p, 1000, &[c], &no_details);
    assert_eq!(s.denied, 1);
    let plan = l.enforcement();
    assert!(
        plan.denied_local_ports.contains(&54321),
        "local port of the denied socket"
    );
    assert!(
        plan.denied_apps.is_empty(),
        "one denied remote is not a whole-app deny"
    );
}

#[test]
fn test_r4_whole_app_deny_by_probe() {
    let mut l = ledger_warm();
    let p = FakePolicy {
        rules: vec![("/usr/bin/curl".into(), "".into(), Verdict::Deny)],
        default: Verdict::Allow,
    };
    let c = conn(10, "/usr/bin/curl", local_remote(51000), net_remote(443));
    l.ingest(&p, 1000, &[c], &no_details);
    assert!(l.enforcement().denied_apps.contains("/usr/bin/curl"));
}

#[test]
fn test_r4_rule_removed_shrinks_plan() {
    let mut l = ledger_warm();
    let deny = FakePolicy {
        rules: vec![("/usr/bin/curl".into(), "1.2.3.4".into(), Verdict::Deny)],
        default: Verdict::Allow,
    };
    let allow = FakePolicy {
        rules: vec![("/usr/bin/curl".into(), "1.2.3.4".into(), Verdict::Allow)],
        default: Verdict::Allow,
    };
    let c = conn(10, "/usr/bin/curl", local_remote(54321), net_remote(443));
    l.ingest(&deny, 1000, std::slice::from_ref(&c), &no_details);
    assert!(!l.enforcement().denied_local_ports.is_empty());
    l.ingest(&allow, 2500, &[c], &no_details);
    assert!(
        l.enforcement().denied_local_ports.is_empty(),
        "removing the rule shrinks the plan"
    );
}

#[test]
fn test_r4_port_zero_and_loopback_never_listed() {
    let mut l = ledger_warm();
    let p = FakePolicy {
        rules: vec![("/usr/bin/curl".into(), "".into(), Verdict::Deny)],
        default: Verdict::Allow,
    };
    let wan = conn(10, "/usr/bin/curl", addr([0, 0, 0, 0], 0), net_remote(443)); // local port 0
    let loop_ = conn(10, "/usr/bin/curl", local_remote(51515), local_remote(8080)); // loopback remote
    l.ingest(&p, 1000, &[wan, loop_], &no_details);
    assert!(
        l.enforcement().denied_local_ports.is_empty(),
        "port 0 and loopback remotes are never blocked"
    );
}

// ---------- R5: timeout ----------

#[test]
fn test_r5_timeout_resolves_to_configured_default() {
    let cfg = AlertCenterConfig {
        timeout_ms: 5000,
        timeout_verdict: Verdict::Deny,
    };
    let mut center = AlertCenter::new(cfg);
    let a = Alert {
        app: "/usr/bin/curl".into(),
        app_name: "curl".into(),
        host: "example.com".into(),
        remote: net_remote(443),
        proto: Protocol::Tcp,
        details: ConnectionDetails::default(),
        reported_ms: 0,
    };
    center.report(a.clone());
    assert!(center.tick(0).is_none(), "not yet expired");
    assert!(center.current().is_some());
    let fired = center.tick(6000).expect("timeout answer");
    assert_eq!(fired.verdict, Verdict::Deny, "configured default verdict");
    assert_eq!(
        fired.lifetime,
        Lifetime::Once,
        "timeout answers once (Swift .once)"
    );
    assert!(center.current().is_none());
    assert!(center.report(a), "once semantics: may ask again");
}

#[test]
fn test_r5_timeout_zero_never_fires() {
    let mut center = AlertCenter::new(AlertCenterConfig::default());
    let a = Alert {
        app: "/x".into(),
        app_name: "x".into(),
        host: "example.com".into(),
        remote: net_remote(443),
        proto: Protocol::Tcp,
        details: ConnectionDetails::default(),
        reported_ms: 0,
    };
    center.report(a);
    center.tick(0);
    for t in (1..10).map(|s| s * 100_000) {
        assert!(center.tick(t).is_none(), "timeout disabled");
    }
    assert!(center.current().is_some());
}

// ---------- R6: v1.2.0 details carried ----------

#[test]
fn test_r6_details_carried_on_remote_entries() {
    let mut l = ledger_warm();
    let c = conn(
        10,
        "/Applications/Firefox.app",
        local_remote(51000),
        net_remote(443),
    );
    let details = |_: &Connection| ConnectionDetails {
        process: Some("plugin-container".into()),
        service_name: Some("HTTPS".into()),
        network_owner: Some("AS13335 Cloudflare, Inc.".into()),
        vpn_mark: Some("WireGuard".into()),
        proxy_mark: None,
        shared_service: false,
    };
    let p = allow_policy();
    l.ingest(&p, 1000, &[c], &details);
    let e = l.app("/Applications/Firefox.app").unwrap();
    let r = e.remotes.first().expect("remote listed");
    assert_eq!(
        r.details.process.as_deref(),
        Some("plugin-container"),
        "helper process behind the socket"
    );
    assert_eq!(r.details.service_name.as_deref(), Some("HTTPS"));
    assert_eq!(
        r.details.network_owner.as_deref(),
        Some("AS13335 Cloudflare, Inc.")
    );
    assert_eq!(r.details.vpn_mark.as_deref(), Some("WireGuard"));
    assert_eq!(r.details.proxy_mark, None);
}

// ---------- registrable_domain (Swift Geo.swift:144-148) ----------

#[test]
fn test_registrable_domain() {
    let mut m: HashMap<&str, &str> = HashMap::new();
    m.insert("a.b.example.com", "example.com");
    m.insert("example.com", "example.com");
    m.insert("host", "host");
    m.insert("1.2.3.4", "1.2.3.4");
    for (input, want) in m {
        assert_eq!(registrable_domain(input), want);
    }
}
