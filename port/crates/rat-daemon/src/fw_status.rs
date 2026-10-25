//! Silent-disable detection: tells the user when Windows Defender Firewall is
//! turned off for a profile, because Rat's rules do not block anything then.
//!
//! Read-only on purpose: the state is queried with `Get-NetFirewallProfile`
//! (JSON, English property names, so it does not depend on the Windows
//! language) and never changed. The parser and the change tracker are pure so
//! they are tested on every platform; only the query itself is Windows-only.
//! The warning travels over the existing `ServerMessage::Error` path (the
//! desktop app shows it as the connection detail), so IPC v1 stays unchanged.

/// One firewall profile (Domain, Private or Public) and whether it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    /// `None` = "not configured" by policy: the effective value is unknown,
    /// so it is never reported as off.
    pub enabled: Option<bool>,
}

/// PowerShell run for the query (fixed text, no user input).
pub const QUERY: &str =
    "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress";

/// Parse the JSON `QUERY` prints: an array, or a single object when only one
/// profile exists. `Enabled` is a number (GpoBoolean: 0 off, 1 on, 2 not
/// configured), a bool, or the text True/False. Anything else is an error,
/// never a guess.
pub fn parse_profiles(json: &str) -> Result<Vec<Profile>, String> {
    let value: serde_json::Value = serde_json::from_str(json.trim().trim_start_matches('\u{feff}'))
        .map_err(|e| format!("firewall profile output is not JSON: {e}"))?;
    let items = match value {
        serde_json::Value::Array(items) => items,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Err("firewall profile output is neither an object nor a list".to_string()),
    };
    if items.is_empty() {
        return Err("firewall profile output lists no profiles".to_string());
    }
    items.iter().map(parse_one).collect()
}

fn parse_one(item: &serde_json::Value) -> Result<Profile, String> {
    use serde_json::Value;
    let name = item
        .get("Name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .ok_or("firewall profile has no Name")?
        .to_string();
    let enabled = match item.get("Enabled") {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            Some(2) => None,
            _ => {
                return Err(format!(
                    "firewall profile {name}: unknown Enabled value {n}"
                ))
            }
        },
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            "notconfigured" => None,
            _ => {
                return Err(format!(
                    "firewall profile {name}: unknown Enabled value {s}"
                ))
            }
        },
        _ => return Err(format!("firewall profile {name} has no Enabled value")),
    };
    Ok(Profile { name, enabled })
}

/// Names of the profiles that are definitely off.
pub fn profiles_off(profiles: &[Profile]) -> Vec<String> {
    profiles
        .iter()
        .filter(|p| p.enabled == Some(false))
        .map(|p| p.name.clone())
        .collect()
}

/// What the watcher should do after one query.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Observation {
    /// Log line, set only when the state changed since the last query.
    pub log: Option<String>,
    /// Message for connected clients: sent on a change and repeated on every
    /// query while a profile stays off, so an app that connects later sees it.
    pub notify: Option<String>,
}

/// Remembers the last result so a change is logged once.
#[derive(Debug, Default)]
pub struct Tracker {
    last: Option<Result<Vec<String>, String>>,
}

impl Tracker {
    pub fn observe(&mut self, result: Result<Vec<Profile>, String>) -> Observation {
        let state = result.map(|p| profiles_off(&p));
        let changed = self.last.as_ref() != Some(&state);
        let first = self.last.is_none();
        self.last = Some(state.clone());
        let mut obs = Observation::default();
        match state {
            Ok(off) if !off.is_empty() => {
                let msg = format!(
                    "Windows Firewall is turned off for: {}. Rat's rules do not block anything for those profiles while it is off.",
                    off.join(", ")
                );
                if changed {
                    obs.log = Some(format!("rat-daemon: WARNING {msg}"));
                }
                obs.notify = Some(msg);
            }
            Ok(_) => {
                if changed {
                    obs.log = Some("rat-daemon: Windows Firewall is on for all profiles".into());
                    // Clear an earlier warning; nothing to say on the very first look.
                    if !first {
                        obs.notify = Some("Windows Firewall is on for all profiles.".into());
                    }
                }
            }
            Err(e) => {
                if changed {
                    obs.log = Some(format!("rat-daemon: cannot read the firewall state: {e}"));
                }
            }
        }
        obs
    }
}

/// Windows-only: run the read-only query under the shared tool timeout.
#[cfg(windows)]
pub fn query_profiles() -> Result<Vec<Profile>, String> {
    let mut cmd = std::process::Command::new(
        rat_enforcer::windows::powershell_path().map_err(|e| e.to_string())?,
    );
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", QUERY]);
    let out = rat_enforcer::run_with_timeout(cmd, "powershell", rat_enforcer::TOOL_TIMEOUT, None)
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("powershell exited with {}", out.status));
    }
    parse_profiles(&String::from_utf8_lossy(&out.stdout))
}

static WATCH_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Production wiring switch: only `run_daemon` turns the watcher on, so tests
/// that call `run_components` with fakes never start PowerShell.
pub fn enable_watch() {
    WATCH_ENABLED.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn watch_enabled() -> bool {
    WATCH_ENABLED.load(std::sync::atomic::Ordering::SeqCst)
}

/// How often the watcher looks again.
#[cfg(windows)]
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Spawn the watcher: queries now and then every minute, logs each change
/// once and broadcasts the warning. Stops with `shutdown`.
#[cfg(windows)]
pub fn spawn_watch(
    tx: tokio::sync::broadcast::Sender<crate::msg::ServerMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tracker = Tracker::default();
        let mut ticker = tokio::time::interval(WATCH_INTERVAL);
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = ticker.tick() => {
                    let result = tokio::task::spawn_blocking(query_profiles)
                        .await
                        .unwrap_or_else(|e| Err(format!("query task failed: {e}")));
                    let obs = tracker.observe(result);
                    if let Some(line) = obs.log {
                        eprintln!("{line}");
                    }
                    if let Some(message) = obs.notify {
                        let _ = tx.send(crate::msg::ServerMessage::Error { message });
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, enabled: Option<bool>) -> Profile {
        Profile {
            name: name.into(),
            enabled,
        }
    }

    const ALL_ON: &str = r#"[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":1}]"#;
    const ONE_OFF: &str = r#"[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":0}]"#;

    /// Live, read-only: the real cmdlet's output must parse.
    #[cfg(windows)]
    #[test]
    fn live_query_parses() {
        let profiles = query_profiles().expect("Get-NetFirewallProfile output parses");
        assert!(!profiles.is_empty());
    }

    #[test]
    fn parses_all_on() {
        let v = parse_profiles(ALL_ON).unwrap();
        assert_eq!(v.len(), 3);
        assert!(profiles_off(&v).is_empty());
    }

    #[test]
    fn parses_one_off() {
        let v = parse_profiles(ONE_OFF).unwrap();
        assert_eq!(profiles_off(&v), vec!["Public".to_string()]);
    }

    #[test]
    fn parses_single_object_and_other_encodings() {
        assert_eq!(
            parse_profiles(r#"{"Name":"Public","Enabled":0}"#).unwrap(),
            vec![p("Public", Some(false))]
        );
        assert_eq!(
            parse_profiles("\u{feff}[{\"Name\":\"A\",\"Enabled\":true},{\"Name\":\"B\",\"Enabled\":\"False\"},{\"Name\":\"C\",\"Enabled\":2}]\r\n")
                .unwrap(),
            vec![p("A", Some(true)), p("B", Some(false)), p("C", None)]
        );
    }

    #[test]
    fn not_configured_is_not_reported_as_off() {
        assert!(profiles_off(&[p("Domain", None)]).is_empty());
    }

    #[test]
    fn garbage_is_an_error_never_a_guess() {
        for bad in [
            "",
            "   ",
            "not json",
            "[]",
            "42",
            r#"[{"Name":"Public"}]"#,
            r#"[{"Enabled":0}]"#,
            r#"[{"Name":"Public","Enabled":7}]"#,
            r#"[{"Name":"Public","Enabled":"maybe"}]"#,
            r#"[{"Name":"Public","Enabled":null}]"#,
        ] {
            assert!(parse_profiles(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn tracker_logs_each_change_once_and_repeats_the_warning() {
        let mut t = Tracker::default();
        let on = || parse_profiles(ALL_ON);
        let off = || parse_profiles(ONE_OFF);

        // first look, all on: logged, nothing sent
        let o = t.observe(on());
        assert!(o.log.is_some() && o.notify.is_none());
        // unchanged: silent
        assert_eq!(t.observe(on()), Observation::default());
        // turned off: logged + sent
        let o = t.observe(off());
        assert!(o.log.as_deref().unwrap().contains("Public"));
        assert!(o.notify.as_deref().unwrap().contains("Public"));
        // still off: NOT logged again, but sent again for late clients
        let o = t.observe(off());
        assert!(o.log.is_none() && o.notify.is_some());
        // back on: logged once, clearing message sent
        let o = t.observe(on());
        assert!(o.log.is_some() && o.notify.is_some());
        assert_eq!(t.observe(on()), Observation::default());
    }

    #[test]
    fn tracker_first_look_off_warns_and_errors_are_logged_once() {
        let mut t = Tracker::default();
        let o = t.observe(parse_profiles(ONE_OFF));
        assert!(o.log.is_some() && o.notify.is_some());

        let mut t = Tracker::default();
        let o = t.observe(Err("boom".into()));
        assert!(o.log.as_deref().unwrap().contains("boom") && o.notify.is_none());
        assert_eq!(t.observe(Err("boom".into())), Observation::default());
    }
}
