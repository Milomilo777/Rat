//! Alert answers → rules: port of `RulesModel.addRule(from:verdict:scope:lifetime:)`
//! (App/Model/RulesModel.swift:163-178). Pure logic; the daemon appends the
//! returned rule to the rule set when it wires the IPC (#10).

use crate::alerts::Alert;
use crate::registrable_domain;
use chrono::Utc;
use rat_core::{Lifetime, PortRange, Rule, Verdict};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

/// Answer scope (RulesModel.swift:158-161). Serialized lowercase over the
/// daemon IPC ("any" | "domain" | "host" | "port") — rat-daemon carries it
/// in ClientMessage::AlertAnswer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnswerScope {
    /// "This App (Any Server)" — a whole-app rule.
    Any,
    /// The host's registrable domain (the address itself for an IP literal).
    Domain,
    /// The exact host.
    Host,
    /// The alert's remote port, with its protocol.
    Port,
}

/// The alert host when it is an IP literal ("1.2.3.4" or "1.2.3.4:443"),
/// `None` for a real name (Swift `isIPLiteral(alert.host)`).
fn host_ip(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    host.parse::<SocketAddr>().ok().map(|s| s.ip())
}

/// Build the rule an alert answer creates, or `None` when the answer needs no
/// rule ("Once" allow — the connection is simply left alone).
pub fn rule_from_answer(
    alert: &Alert,
    verdict: Verdict,
    scope: AnswerScope,
    lifetime: Lifetime,
    mark_new_rules_as_unapproved: bool,
    active_profile_id: Option<uuid::Uuid>,
) -> Option<Rule> {
    // "Once" allow needs no rule. "Once" deny is a session rule so the open
    // connection is really cut (RulesModel.swift:164-165).
    let once = lifetime == Lifetime::Once;
    if once && verdict == Verdict::Allow {
        return None;
    }
    let port_once = PortRange {
        start: alert.remote.port(),
        end: alert.remote.port(),
    };
    let mut r = Rule {
        id: Uuid::new_v4(),
        verdict,
        process_path: Some(alert.app.clone()),
        signing_id: None,
        team_id: None,
        remote_domain: None,
        remote_host: None,
        remote_address: None,
        ports: None,
        proto: None,
        enabled: true,
        approved: !mark_new_rules_as_unapproved,
        lifetime: if once { Lifetime::UntilQuit } else { lifetime },
        profile_id: active_profile_id,
        group_id: None,
        created_at: Utc::now(),
        note: Some("From a connection alert".to_string()),
    };
    let address = alert.remote.ip().to_string();
    match scope {
        AnswerScope::Any => {}
        AnswerScope::Domain => {
            // A raw IP has no domain: scope it to the address instead.
            if let Some(ip) = host_ip(&alert.host) {
                r.remote_address = Some(ip.to_string());
            } else {
                r.remote_domain = Some(registrable_domain(&alert.host));
            }
        }
        AnswerScope::Host => {
            if let Some(ip) = host_ip(&alert.host) {
                r.remote_address = Some(ip.to_string());
            } else {
                r.remote_host = Some(alert.host.clone());
            }
        }
        AnswerScope::Port => {
            r.ports = Some(port_once.clone());
            r.proto = Some(alert.proto);
        }
    }
    if once {
        // Pin the one-shot deny to the exact destination (RulesModel.swift:176).
        r.remote_address = Some(address);
        r.ports = Some(port_once);
    }
    Some(r)
}
