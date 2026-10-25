//! Alert answers → rules (RulesModel.swift:163-178). Pure logic, explicit inputs.

use rat_core::{Lifetime, PortRange, Verdict};
use rat_ledger::{rule_from_answer, Alert, AnswerScope, ConnectionDetails};
use rat_types::Protocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn alert(app: &str, host: &str, remote: SocketAddr, proto: Protocol) -> Alert {
    Alert {
        app: app.to_string(),
        app_name: "curl".to_string(),
        host: host.to_string(),
        remote,
        proto,
        details: ConnectionDetails::default(),
        reported_ms: 0,
    }
}

fn remote() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 443)
}

#[test]
fn test_once_allow_needs_no_rule() {
    let a = alert("/usr/bin/curl", "a.b.example.com", remote(), Protocol::Tcp);
    assert!(
        rule_from_answer(
            &a,
            Verdict::Allow,
            AnswerScope::Any,
            Lifetime::Once,
            false,
            None
        )
        .is_none(),
        "once-allow leaves the connection alone (RulesModel.swift:165)"
    );
}

#[test]
fn test_scope_any_is_whole_app_rule() {
    let a = alert("/usr/bin/curl", "a.b.example.com", remote(), Protocol::Tcp);
    let r = rule_from_answer(
        &a,
        Verdict::Deny,
        AnswerScope::Any,
        Lifetime::Forever,
        false,
        None,
    )
    .unwrap();
    assert_eq!(r.process_path.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r.remote_domain.is_none() && r.remote_host.is_none() && r.remote_address.is_none());
    assert!(r.ports.is_none() && r.proto.is_none());
    assert!(r.approved, "markNewRulesAsUnapproved=false -> approved");
    assert_eq!(r.note.as_deref(), Some("From a connection alert"));
    assert_eq!(r.lifetime, Lifetime::Forever);
    assert!(r.enabled);
}

#[test]
fn test_unapproved_setting_carried() {
    let a = alert("/usr/bin/curl", "x.example.com", remote(), Protocol::Tcp);
    let r = rule_from_answer(
        &a,
        Verdict::Allow,
        AnswerScope::Any,
        Lifetime::UntilQuit,
        true,
        None,
    )
    .unwrap();
    assert!(!r.approved, "markNewRulesAsUnapproved=true -> unapproved");
    assert_eq!(r.lifetime, Lifetime::UntilQuit, "non-once lifetime kept");
}

#[test]
fn test_scope_domain_and_host() {
    let named = alert("/usr/bin/curl", "a.b.example.com", remote(), Protocol::Tcp);
    let d = rule_from_answer(
        &named,
        Verdict::Allow,
        AnswerScope::Domain,
        Lifetime::Forever,
        false,
        None,
    )
    .unwrap();
    assert_eq!(d.remote_domain.as_deref(), Some("example.com"));
    assert!(d.remote_host.is_none() && d.remote_address.is_none());

    let h = rule_from_answer(
        &named,
        Verdict::Allow,
        AnswerScope::Host,
        Lifetime::Forever,
        false,
        None,
    )
    .unwrap();
    assert_eq!(h.remote_host.as_deref(), Some("a.b.example.com"));
    assert!(h.remote_domain.is_none() && h.remote_address.is_none());
}

#[test]
fn test_ip_literal_host_scopes_to_address() {
    // The Rust Alert.host is "ip:port" until reverse DNS is wired; a bare
    // "1.2.3.4" (as Swift carries it) must behave the same.
    for host in ["9.9.9.9", "9.9.9.9:443"] {
        let a = alert("/usr/bin/curl", host, remote(), Protocol::Tcp);
        let d = rule_from_answer(
            &a,
            Verdict::Allow,
            AnswerScope::Domain,
            Lifetime::Forever,
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            d.remote_address.as_deref(),
            Some("9.9.9.9"),
            "a raw IP has no domain: scope to the address ({host})"
        );
        assert!(d.remote_domain.is_none());
        let h = rule_from_answer(
            &a,
            Verdict::Allow,
            AnswerScope::Host,
            Lifetime::Forever,
            false,
            None,
        )
        .unwrap();
        assert_eq!(h.remote_address.as_deref(), Some("9.9.9.9"));
        assert!(h.remote_host.is_none());
    }
}

#[test]
fn test_scope_port() {
    let a = alert("/usr/bin/curl", "a.b.example.com", remote(), Protocol::Udp);
    let r = rule_from_answer(
        &a,
        Verdict::Allow,
        AnswerScope::Port,
        Lifetime::Forever,
        false,
        None,
    )
    .unwrap();
    assert_eq!(
        r.ports,
        Some(PortRange {
            start: 443,
            end: 443
        })
    );
    assert_eq!(r.proto, Some(Protocol::Udp));
    assert!(r.remote_address.is_none() && r.remote_host.is_none() && r.remote_domain.is_none());
}

#[test]
fn test_once_deny_is_session_rule_pinned_to_destination() {
    let a = alert("/usr/bin/curl", "a.b.example.com", remote(), Protocol::Tcp);
    let r = rule_from_answer(
        &a,
        Verdict::Deny,
        AnswerScope::Domain,
        Lifetime::Once,
        false,
        None,
    )
    .unwrap();
    assert_eq!(r.lifetime, Lifetime::UntilQuit, "once -> untilQuit");
    assert_eq!(
        r.remote_address.as_deref(),
        Some("9.9.9.9"),
        "the exact destination is added on top of the scope"
    );
    // Swift keeps the scope field too (RulesModel.swift:176 only ADDS address
    // and port); Rule::matches ANDs every present field, so the rule narrows
    // to this one destination.
    assert_eq!(r.remote_domain.as_deref(), Some("example.com"));
    assert_eq!(
        r.ports,
        Some(PortRange {
            start: 443,
            end: 443
        })
    );
}
