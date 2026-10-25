//! Rule list handling for the app.
//!
//! The daemon is the single source of rules. The app asks it for the current
//! set with `GetRules`, applies one change and sends the full list back with
//! `SetRules` (which replaces the set). Asking fresh before every change keeps
//! rules the daemon created from alert answers, session rules (once / until
//! quit) included. The app never reads the rules file itself: the daemon may
//! have refused that file, and an elevated app must not push its content back.

use rat_core::{Rule, Verdict};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RuleView {
    pub id: String,
    pub app: String,
    pub action: String,
    pub remote: String,
}

/// A rule the user typed into the Rules tab.
#[derive(Deserialize, Debug, Clone)]
pub struct NewRule {
    /// Full path of the program (the rule matches the path and anything
    /// inside it).
    pub app: String,
    /// "allow" or "deny"
    pub action: String,
    /// Empty or "*" = any remote; an IP address; otherwise a domain
    /// (matches the domain and its subdomains).
    pub remote: String,
}

const MAX_FIELD: usize = 1024;

pub fn view_of(rule: &Rule) -> RuleView {
    let mut remote = rule
        .remote_address
        .clone()
        .or_else(|| rule.remote_host.clone())
        .or_else(|| rule.remote_domain.clone())
        .unwrap_or_else(|| "*".to_string());
    if let Some(p) = &rule.ports {
        if p.start == p.end {
            remote.push_str(&format!(":{}", p.start));
        } else {
            remote.push_str(&format!(":{}-{}", p.start, p.end));
        }
    }
    RuleView {
        id: rule.id.to_string(),
        app: rule.process_path.clone().unwrap_or_else(|| "*".to_string()),
        action: match rule.verdict {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Ask => "ask",
        }
        .to_string(),
        remote,
    }
}

fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !s.starts_with('.')
        && !s.ends_with('.')
}

/// Validate a typed rule and build the daemon's `Rule` (v2 wire format).
/// Everything not given takes the daemon's serde defaults (new id, enabled,
/// approved, forever, created now).
pub fn build_rule(new: &NewRule) -> Result<Rule, String> {
    let app = new.app.trim();
    if app.is_empty() {
        return Err("the program path is empty".to_string());
    }
    if app.len() > MAX_FIELD || app.chars().any(|c| c.is_control()) {
        return Err("the program path is not valid".to_string());
    }
    let verdict = match new.action.as_str() {
        "allow" => "allow",
        "deny" => "deny",
        other => return Err(format!("unknown action: {other}")),
    };
    let remote = new.remote.trim();
    let mut obj = serde_json::json!({ "verdict": verdict, "processPath": app });
    if !remote.is_empty() && remote != "*" {
        if remote.parse::<IpAddr>().is_ok() {
            obj["remoteAddress"] = remote.into();
        } else if valid_domain(remote) {
            obj["remoteDomain"] = remote.to_ascii_lowercase().into();
        } else {
            return Err("the remote must be an IP address or a domain name".to_string());
        }
    }
    serde_json::from_value(obj).map_err(|e| e.to_string())
}

/// Remove the rule with `id`; error when it does not exist.
pub fn remove_rule(rules: &mut Vec<Rule>, id: &str) -> Result<(), String> {
    let before = rules.len();
    rules.retain(|r| r.id.to_string() != id);
    if rules.len() == before {
        Err("no such rule".to_string())
    } else {
        Ok(())
    }
}

/// Parse the alert answer fields the webview sends. The daemon's own serde
/// spelling is used so there is a single source of truth for the strings.
pub fn parse_enum<T: serde::de::DeserializeOwned>(what: &str, value: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| format!("unknown {what}: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rat_core::Lifetime;
    use rat_ledger::AnswerScope;

    fn new(app: &str, action: &str, remote: &str) -> NewRule {
        NewRule {
            app: app.to_string(),
            action: action.to_string(),
            remote: remote.to_string(),
        }
    }

    #[test]
    fn builds_whole_app_rule() {
        let r = build_rule(&new(r"C:\Program Files\App\app.exe", "deny", "")).unwrap();
        assert_eq!(r.verdict, Verdict::Deny);
        assert_eq!(
            r.process_path.as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
        assert!(r.remote_domain.is_none() && r.remote_address.is_none());
        assert!(r.enabled && r.approved);
        assert_eq!(r.lifetime, Lifetime::Forever);
        let v = view_of(&r);
        assert_eq!((v.action.as_str(), v.remote.as_str()), ("deny", "*"));
    }

    #[test]
    fn ip_becomes_address_and_name_becomes_domain() {
        let ip = build_rule(&new("/usr/bin/curl", "allow", "8.8.8.8")).unwrap();
        assert_eq!(ip.remote_address.as_deref(), Some("8.8.8.8"));
        let ip6 = build_rule(&new("/usr/bin/curl", "allow", "2001:db8::1")).unwrap();
        assert_eq!(ip6.remote_address.as_deref(), Some("2001:db8::1"));
        let d = build_rule(&new("/usr/bin/curl", "allow", "Example.COM")).unwrap();
        assert_eq!(d.remote_domain.as_deref(), Some("example.com"));
        assert_eq!(view_of(&d).remote, "example.com");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(build_rule(&new("", "allow", "")).is_err());
        assert!(build_rule(&new("  ", "allow", "")).is_err());
        assert!(build_rule(&new("/a", "maybe", "")).is_err());
        assert!(build_rule(&new("/a", "allow", "not a host!")).is_err());
        assert!(build_rule(&new("/a", "allow", "<img src=x>")).is_err());
        assert!(build_rule(&new("/a\nb", "allow", "")).is_err());
        assert!(build_rule(&new(&"x".repeat(2000), "allow", "")).is_err());
    }

    #[test]
    fn view_shows_ports() {
        let mut r = build_rule(&new("/a", "allow", "")).unwrap();
        r.ports = Some(rat_core::PortRange {
            start: 443,
            end: 443,
        });
        assert_eq!(view_of(&r).remote, "*:443");
        r.ports = Some(rat_core::PortRange { start: 80, end: 90 });
        assert_eq!(view_of(&r).remote, "*:80-90");
    }

    #[test]
    fn remove_by_id() {
        let a = build_rule(&new("/a", "allow", "")).unwrap();
        let b = build_rule(&new("/b", "deny", "")).unwrap();
        let id = a.id.to_string();
        let mut v = vec![a, b];
        remove_rule(&mut v, &id).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].process_path.as_deref(), Some("/b"));
        assert!(remove_rule(&mut v, &id).is_err());
    }

    #[test]
    fn answer_fields_use_the_daemon_spelling() {
        assert_eq!(
            parse_enum::<Verdict>("verdict", "deny").unwrap(),
            Verdict::Deny
        );
        assert_eq!(
            parse_enum::<Lifetime>("lifetime", "untilQuit").unwrap(),
            Lifetime::UntilQuit
        );
        assert_eq!(
            parse_enum::<AnswerScope>("scope", "host").unwrap(),
            AnswerScope::Host
        );
        assert!(parse_enum::<Verdict>("verdict", "DENY!").is_err());
        assert!(parse_enum::<AnswerScope>("scope", "ip").is_err());
    }
}
