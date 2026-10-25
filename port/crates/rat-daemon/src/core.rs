use crate::msg::ServerMessage;
use rat_core::{Lifetime, Verdict};
use rat_ledger::{Ledger, RuleEnginePolicy};
use rat_types::{Connection, ConnectionSource};
use std::io;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

/// How often the pipeline samples the monitor and re-evaluates enforcement.
pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(1500);

/// `<unknown>` (rat-ledger's app_key for a socket with no visible exe) is not
/// an executable path — it must never reach the enforcer.
const UNKNOWN_APP: &str = "<unknown>";

/// Commands the IPC layer forwards into the pipeline . The
/// pipeline is the single writer for the rule engine, the ledger and the
/// enforcement backend, so commands are data, not shared state.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    SetRules {
        rules: Vec<rat_core::Rule>,
    },
    AlertAnswer {
        id: u64,
        verdict: Verdict,
        scope: rat_ledger::AnswerScope,
        lifetime: Lifetime,
    },
    /// Broadcast the current rule set as `ServerMessage::Rules`.
    GetRules,
    /// Incremental edit: add one rule (or replace the rule with the same
    /// id), keeping every other rule — the whole-list replace stays
    /// `SetRules`. Boxed like the wire type (serde shape is unchanged).
    AddRule {
        rule: Box<rat_core::Rule>,
    },
    /// Incremental edit: remove one rule by id. An unknown id is logged and
    /// changes nothing.
    RemoveRule {
        id: uuid::Uuid,
    },
}

/// What [`EnforcementBackend::enforce`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnforceOutcome {
    pub applied: bool,
    /// Paths the backend REFUSED to block (shared service hosts).
    pub refused: Vec<String>,
    /// Paths the backend could NOT enforce (failed path validation):
    /// reported, skipped, the rest of the plan still applies.
    pub rejected: Vec<String>,
}

/// The enforcement half of the pipeline: turn the ledger's
/// EnforcementPlan into effective firewall state. Object-safe on purpose so
/// tests inject a recorder instead of netsh/nft.
pub trait EnforcementBackend: Send {
    /// Remove every rule this daemon created. The UNINSTALL path only
    /// (`rat-daemon --cleanup`): startup reconciles instead and a clean
    /// stop keeps the rules (macOS
    /// persistent-anchor parity).
    fn cleanup(&mut self) -> io::Result<()>;
    /// Read back the rules this backend currently holds, so a restart can
    /// RECONCILE against them instead of wiping (read existing, diff
    /// with the saved plan, remove extras, add missing — a wanted rule is
    /// never deleted). Must return only this daemon's own prefixed rules;
    /// foreign rules are never this backend's business.
    fn existing(&self) -> io::Result<rat_enforcer::Blocklist>;
    /// Adopt a read-back as the backend's notion of current state, seeding
    /// the diff so the next `enforce` computes exactly remove-extras +
    /// add-missing.
    fn adopt(&mut self, existing: rat_enforcer::Blocklist);
    /// Make `wanted` effective. Implementations must be no-ops when the
    /// wanted state is already effective, and on failure must leave their
    /// notion of the current state behind so the next call retries the diff.
    fn enforce(&mut self, wanted: &rat_enforcer::Blocklist) -> io::Result<EnforceOutcome>;
}

/// Windows backend: `netsh advfirewall` per-program rules (ADR 0001 as
/// amended 2026-10-25) plus per-port rules for the denied sockets' local
/// ports (the Windows mirror of the Linux backend's nft port set).
#[cfg(windows)]
pub struct WindowsBackend {
    pub enforcer: rat_enforcer::windows::WindowsEnforcer,
}

#[cfg(windows)]
impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl WindowsBackend {
    pub fn new() -> Self {
        Self {
            enforcer: rat_enforcer::windows::WindowsEnforcer {
                current: rat_enforcer::Blocklist::default(),
                runner: None,
            },
        }
    }
}

#[cfg(windows)]
impl EnforcementBackend for WindowsBackend {
    fn cleanup(&mut self) -> io::Result<()> {
        use rat_enforcer::Enforcer;
        self.enforcer.cleanup()
    }

    fn existing(&self) -> io::Result<rat_enforcer::Blocklist> {
        use std::process::Command;
        // Read-only query; blocking is fine here because this runs once at
        // startup, before the IPC server exists — and it goes through the
        // shared run_with_timeout, so a hung PowerShell is killed at
        // TOOL_TIMEOUT instead of stalling the startup read-back forever.
        let mut cmd = Command::new(rat_enforcer::windows::powershell_path()?);
        cmd.args(["-NoProfile", "-Command", existing_rules_query()]);
        let out =
            rat_enforcer::run_with_timeout(cmd, "powershell", rat_enforcer::TOOL_TIMEOUT, None)?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "firewall read-back failed: {}",
                out.status
            )));
        }
        // One program path / local port per line; anything non-empty counts.
        // An empty answer (no Rat rules at all) is success, not an error.
        Ok(parse_existing_output(&String::from_utf8_lossy(&out.stdout)))
    }

    fn adopt(&mut self, existing: rat_enforcer::Blocklist) {
        self.enforcer.current = existing;
    }

    fn enforce(&mut self, wanted: &rat_enforcer::Blocklist) -> io::Result<EnforceOutcome> {
        use rat_enforcer::Enforcer;

        // The port axis reaches the plan (dropping it here made
        // every refused shared host a silent no-op and ignored the ledger's
        // denied_local_ports).
        let plan = self.enforcer.plan(wanted);
        let refused = plan.refused.clone();
        let rejected = plan.rejected.clone();
        if plan.add.is_empty()
            && plan.remove.is_empty()
            && plan.add_ports.is_empty()
            && plan.remove_ports.is_empty()
        {
            return Ok(EnforceOutcome {
                applied: false,
                refused,
                rejected,
            });
        }
        // apply() honours RAT_DRY_RUN. apply() itself
        // advances the enforcer's `current` to the applied state on success
        // and leaves it behind on failure, so the next tick retries the same
        // diff (the daemon no longer patches `current` by hand).
        self.enforcer.apply(&plan)?;
        Ok(EnforceOutcome {
            applied: true,
            refused,
            rejected,
        })
    }
}

/// Linux backend: the `inet rat` nft table rebuilt whole per change (the
/// plan flushes the table, so a closed socket's local port simply drops out
/// of the wanted set — no stale per-port rule survives).
#[cfg(not(windows))]
pub struct LinuxBackend {
    enforcer: rat_enforcer::linux::LinuxEnforcer,
    last_ruleset: Option<String>,
}

#[cfg(not(windows))]
impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(windows))]
impl LinuxBackend {
    pub fn new() -> Self {
        Self {
            enforcer: rat_enforcer::linux::LinuxEnforcer,
            last_ruleset: None,
        }
    }
}

#[cfg(not(windows))]
impl EnforcementBackend for LinuxBackend {
    fn cleanup(&mut self) -> io::Result<()> {
        use rat_enforcer::Enforcer;
        self.enforcer.cleanup()
    }

    fn existing(&self) -> io::Result<rat_enforcer::Blocklist> {
        // The nft backend rebuilds the whole `inet rat` table per change
        // (plan() emits the full ruleset, apply() replaces it), so there is
        // no partial state to adopt: the first enforce after a restart
        // wholesale replaces whatever a predecessor left — stale rules
        // cannot survive it. Reconcile here is the rebuild itself.
        Ok(rat_enforcer::Blocklist::default())
    }

    fn adopt(&mut self, _existing: rat_enforcer::Blocklist) {
        // Nothing to seed: see existing() — the whole-table rebuild does not
        // keep per-rule state.
    }

    fn enforce(&mut self, wanted: &rat_enforcer::Blocklist) -> io::Result<EnforceOutcome> {
        use rat_enforcer::Enforcer;

        let ruleset = self.enforcer.plan(wanted);
        if self.last_ruleset.as_ref() == Some(&ruleset) {
            return Ok(EnforceOutcome::default());
        }
        self.enforcer.apply(&ruleset)?;
        self.last_ruleset = Some(ruleset);
        Ok(EnforceOutcome {
            applied: true,
            refused: Vec::new(),
            rejected: Vec::new(),
        })
    }
}

fn to_blocklist(plan: &rat_ledger::EnforcementPlan) -> rat_enforcer::Blocklist {
    rat_enforcer::Blocklist {
        paths: plan
            .denied_apps
            .iter()
            .filter(|p| p.as_str() != UNKNOWN_APP)
            .cloned()
            .collect(),
        local_ports: plan.denied_local_ports.iter().copied().collect(),
    }
}

/// The anchor the SAVED rules demand, independent of any live connection:
/// one whole-program block per app whose rules deny it outright, so an idle
/// app's block exists BEFORE its next connection attempt. This is the "saved
/// plan" the startup reconcile diffs against and the stable half of every
/// enforce round.
///
/// Follows Swift `Ledger.deniedAppPaths` (App/Model/Ledger.swift:398-418),
/// in particular lines 411-414: the whole app is blocked only when the
/// deciding rule is a deny with NO remote domain, host, address, port or
/// protocol scope. A scoped deny (one domain, one port, ...) must never
/// become a whole-program block; it is enforced per connection instead (the
/// ledger puts the LOCAL ports of rule-denied sockets into the plan, see
/// `to_blocklist` and rat-ledger ingest.rs). As in Swift line 410, an active
/// allow rule for the same program means the app is not blocked wholesale.
/// "Active" is what the engine's `matching_rule` uses: the rule is enabled,
/// belongs to no profile or to the active one, and is not in a disabled
/// group. `approved` is a review marker only and does not gate anything.
pub fn static_blocklist(set: &rat_core::RuleSet) -> rat_enforcer::Blocklist {
    let disabled_groups: std::collections::HashSet<_> = set
        .groups
        .iter()
        .filter(|g| !g.enabled)
        .map(|g| g.id)
        .collect();
    let active: Vec<&rat_core::Rule> = set
        .rules
        .iter()
        .filter(|r| {
            r.enabled
                && (r.profile_id.is_none() || r.profile_id == Some(set.active_profile_id))
                && !r.group_id.is_some_and(|g| disabled_groups.contains(&g))
        })
        .collect();
    let allowed: std::collections::HashSet<&str> = active
        .iter()
        .filter(|r| r.verdict == rat_core::Verdict::Allow)
        .filter_map(|r| r.process_path.as_deref())
        .collect();
    let mut paths: Vec<String> = active
        .iter()
        .filter(|r| r.verdict == rat_core::Verdict::Deny)
        .filter(|r| {
            r.remote_domain.is_none()
                && r.remote_host.is_none()
                && r.remote_address.is_none()
                && r.ports.is_none()
                && r.proto.is_none()
        })
        .filter_map(|r| r.process_path.as_deref())
        .filter(|p| !p.is_empty() && *p != UNKNOWN_APP && !allowed.contains(p))
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();
    rat_enforcer::Blocklist {
        paths,
        local_ports: Vec::new(),
    }
}

/// The wanted state of an enforce round: the static anchor from the saved
/// rules UNION the ledger's dynamic plan, deduplicated and sorted so an
/// unchanged state stays a no-op diff.
fn merge_blocklists(
    anchor: rat_enforcer::Blocklist,
    live: rat_enforcer::Blocklist,
) -> rat_enforcer::Blocklist {
    let mut paths = anchor.paths;
    paths.extend(live.paths);
    paths.sort();
    paths.dedup();
    let mut local_ports = anchor.local_ports;
    local_ports.extend(live.local_ports);
    local_ports.sort();
    local_ports.dedup();
    rat_enforcer::Blocklist { paths, local_ports }
}

/// The read-back query for [`EnforcementBackend::existing`] on Windows: the
/// program paths behind every `Rat:path:*` rule and the local ports behind
/// every `Rat:port:*` rule this daemon owns (the port axis is reconciled too).
/// Scoped to the daemon's own prefixes, so foreign rules can never enter the
/// reconcile diff. Read-only. The marker
/// separates the two sections for [`parse_existing_output`].
#[cfg(windows)]
fn existing_rules_query() -> &'static str {
    "Get-NetFirewallRule -DisplayName 'Rat:path:*' -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter | Select-Object -ExpandProperty Program; Write-Output '---RATPORTS---'; Get-NetFirewallRule -DisplayName 'Rat:port:*' -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter | Select-Object -ExpandProperty LocalPort"
}

#[cfg(windows)]
const PORTS_MARKER: &str = "---RATPORTS---";

/// Splits the read-back output into paths (before the marker) and local
/// ports (after it), both sorted and deduplicated. A `Rat:port:*` port exists
/// as FOUR netsh rules (out/in x TCP/UDP) and a program as two (out/in), so
/// the same value arrives once per rule — dedup here keeps the reconcile diff
/// from removing one entry several times. Non-numeric port
/// lines (Get-NetFirewallPortFilter can report "Any") are not ours to
/// reconcile and are skipped.
#[cfg(windows)]
fn parse_existing_output(stdout: &str) -> rat_enforcer::Blocklist {
    let mut paths = Vec::new();
    let mut local_ports = Vec::new();
    let mut in_ports = false;
    for line in stdout.lines() {
        let line = line.trim();
        if line == PORTS_MARKER {
            in_ports = true;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if in_ports {
            if let Ok(p) = line.parse::<u16>() {
                local_ports.push(p);
            }
        } else {
            paths.push(line.to_string());
        }
    }
    paths.sort();
    paths.dedup();
    local_ports.sort();
    local_ports.dedup();
    rat_enforcer::Blocklist { paths, local_ports }
}

/// Best-effort persistence: the rule set survives a restart (Swift
/// RulesModel parity). `save_set` keeps only Forever rules — UntilQuit
/// session rules are supposed to die with the daemon.
fn persist_rules(store: &Option<std::sync::Arc<rat_core::RuleStore>>, policy: &RuleEnginePolicy) {
    // None = the rules directory is untrusted: never write into it.
    let Some(store) = store else { return };
    if let Err(e) = store.save_set(&policy.0.rule_set()) {
        eprintln!("rat-daemon: saving rules failed: {e}");
    }
}

/// Per-connection details the ledger needs that the monitor does not carry.
/// Reverse-DNS (`host_name`) stays None for now: it needs an async resolver
/// with a cache, not a blocking lookup inside this closure.
fn connection_details(c: &Connection) -> rat_ledger::ConnectionDetails {
    rat_ledger::ConnectionDetails {
        process: None,
        service_name: rat_names::service_name(c.local.port(), c.protocol).map(str::to_string),
        network_owner: None,
        vpn_mark: None,
        proxy_mark: None,
        shared_service: c
            .process
            .exe
            .as_ref()
            .is_some_and(|p| rat_ledger::is_shared_service(&p.to_string_lossy())),
        host_name: None,
        country: None,
    }
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Apply an alert answer: take the current alert out of the queue and, when
/// the answer needs a rule, add it to the engine (port of
/// RulesModel.addRule(from:verdict:scope:lifetime:)). Returns whether a rule
/// was created (the caller persists on change).
fn answer_current_alert(
    ledger: &mut Ledger,
    policy: &RuleEnginePolicy,
    verdict: Verdict,
    scope: rat_ledger::AnswerScope,
    lifetime: Lifetime,
) -> bool {
    let Some(answer) = ledger.alerts.answer_current(verdict, lifetime) else {
        return false;
    };
    // An alert answer is a direct user decision: the rule it creates is
    // approved (unlike rule-file imports, which arrive unapproved — #11).
    match rat_ledger::rule_from_answer(&answer.alert, verdict, scope, lifetime, false, None) {
        Some(rule) => {
            policy.0.add(rule);
            true
        }
        None => false,
    }
}

/// Runs the whole data path: monitor -> ledger -> policy ->
/// enforcer, plus the alert fan-out to IPC clients. Re-judges the last
/// sample after every command so SetRules/AlertAnswer take effect without
/// waiting for the next tick. Commands arrive on a BOUNDED queue (back
/// pressure): each poll drains everything already queued into ONE round,
/// coalescing runs of `SetRules` to the newest list — a burst costs one
/// enforce, and a flooding client is rejected at the IPC layer, not here.
/// Exits when `shutdown` fires (rules are KEPT — persistent anchor, the
/// uninstall path removes them) or when every command sender is gone.
// The five components + three channels are the pipeline's real shape; a
// bundling struct would move, not remove, the coupling.
#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline(
    mut source: impl ConnectionSource + Send + 'static,
    policy: RuleEnginePolicy,
    mut ledger: Ledger,
    mut backend: impl EnforcementBackend,
    store: impl Into<Option<std::sync::Arc<rat_core::RuleStore>>>,
    mut commands: mpsc::Receiver<Command>,
    snapshot_tx: broadcast::Sender<ServerMessage>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let store: Option<std::sync::Arc<rat_core::RuleStore>> = store.into();
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    let mut last_conns: Vec<Connection> = Vec::new();
    let mut last_refused: Vec<String> = Vec::new();
    let mut last_rejected: Vec<String> = Vec::new();
    let mut next_alert_id: u64 = 0;
    let mut current_alert_id: Option<u64> = None;
    let mut sent_alert_key: Option<String> = None;
    // False until the first enforce round ran. A failed sample may skip a
    // round only AFTER that: before it, the static anchor (rules that need
    // no connection) must still be enforced on an empty sample.
    let mut enforced_once = false;

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                // Stop decision (macOS parity): the rules SURVIVE a
                // stop — the persistent anchor keeps blocking while the
                // daemon is down (rat-enforcerd KeepAlive, Enforcer.swift:144;
                // only Remove Helper clears them, :179). A wipe here would
                // re-open the fail-open window the startup reconcile closes. Full
                // removal is the uninstall path (`rat-daemon --cleanup`).
                break;
            }
            cmd = commands.recv() => {
                match cmd {
                    Some(command) => {
                        // Drain everything already queued in this one arm so
                        // a whole burst costs ONE enforce round below. Runs
                        // of SetRules coalesce to the NEWEST list (the
                        // intermediate lists are stale before they could
                        // ever run); a non-SetRules command keeps its order —
                        // it is handled after the SetRules in front of it
                        // was applied, and it stops the drain, so SetRules
                        // behind it batch with the next round.
                        let mut pending = Some(command);
                        while let Some(cmd) = pending.take() {
                            match cmd {
                                Command::SetRules { rules } => {
                                    let mut newest = rules;
                                    loop {
                                        match commands.try_recv() {
                                            // A newer list supersedes every
                                            // queued older one.
                                            Ok(Command::SetRules { rules }) => newest = rules,
                                            Ok(other) => {
                                                pending = Some(other);
                                                break;
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    policy.0.set_rules(newest);
                                    persist_rules(&store, &policy);
                                }
                                Command::AlertAnswer { id, verdict, scope, lifetime } => {
                                    if current_alert_id == Some(id) {
                                        if answer_current_alert(&mut ledger, &policy, verdict, scope, lifetime) {
                                            persist_rules(&store, &policy);
                                        }
                                        // The answered alert is gone. The same (app, host)
                                        // may be queued again at once (Allow once makes no
                                        // rule): that is a NEW alert, so forget the sent key
                                        // and tell clients the old one is cleared.
                                        sent_alert_key = None;
                                        current_alert_id = None;
                                        let _ = snapshot_tx.send(ServerMessage::AlertCleared { id });
                                    } else {
                                        eprintln!("rat-daemon: ignoring stale AlertAnswer id {id}");
                                    }
                                }
                                Command::GetRules => {
                                    // Answered from the live engine, never from the
                                    // rules file (which may be untrusted and unread).
                                    // A broadcast with no receiver is not an error.
                                    let _ = snapshot_tx.send(ServerMessage::Rules {
                                        rules: policy.0.rule_set().rules,
                                    });
                                }
                                Command::AddRule { rule } => {
                                    // Incremental edit: upsert by id, every
                                    // other rule keeps its place. Saved like
                                    // SetRules; an identical re-delivery
                                    // (client retry) changes nothing and
                                    // skips the write.
                                    if policy.0.upsert(*rule) {
                                        persist_rules(&store, &policy);
                                    }
                                }
                                Command::RemoveRule { id } => {
                                    // A stale id (rule already gone) is
                                    // reported, not silently swallowed.
                                    if policy.0.remove(id) {
                                        persist_rules(&store, &policy);
                                    } else {
                                        eprintln!(
                                            "rat-daemon: ignoring RemoveRule for unknown rule id {id}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Every IPC command sender is gone (server ended): wind down.
                    None => break,
                }
            }
            _ = ticker.tick() => {
                match source.sample() {
                    Ok(conns) => last_conns = conns,
                    Err(e) => {
                        // One failed sample skips the round; the monitor may
                        // recover (e.g. a transient table read) and the next
                        // tick retries. Killing the daemon for it would turn
                        // a read hiccup into an enforcement outage. The
                        // very first round is the exception: static rules
                        // are enforced at start-up even without a sample.
                        eprintln!("rat-daemon: monitor sample failed: {e}");
                        if enforced_once {
                            continue;
                        }
                    }
                }
            }
        }

        // Re-judge the last sample with the current rules. A second ingest
        // of the same sample is a no-op for the byte counters (the ledger's
        // baselines only advance) and rebuilds the enforcement plan.
        let now_ms = unix_now_ms();
        let _summary = ledger.ingest(&policy, now_ms, &last_conns, &|c: &Connection| {
            connection_details(c)
        });

        // AlertCenter.tick presents the next queued alert when idle
        // (AlertCenter.swift:79) — this is what turns a queued Ask into
        // ledger.alerts.current() so it can be broadcast below. A configured
        // timeout (disabled in the default config) would return an automatic
        // answer, which becomes a rule like a user answer does.
        if let Some(answer) = ledger.alerts.tick(now_ms) {
            if let Some(rule) = rat_ledger::rule_from_answer(
                &answer.alert,
                answer.verdict,
                rat_ledger::AnswerScope::Any,
                answer.lifetime,
                false,
                None,
            ) {
                policy.0.add(rule);
                persist_rules(&store, &policy);
            }
        }

        // One AlertRequest per NEW current alert (AlertCenter queues one
        // prompt per app|domain key until it is answered).
        match ledger.alerts.current() {
            Some(alert) if sent_alert_key.as_deref() != Some(alert.key().as_str()) => {
                next_alert_id += 1;
                current_alert_id = Some(next_alert_id);
                sent_alert_key = Some(alert.key());
                let _ = snapshot_tx.send(ServerMessage::AlertRequest {
                    id: next_alert_id,
                    alert: Box::new(alert.clone()),
                });
            }
            Some(_) => {}
            None => {
                if let Some(id) = current_alert_id.take() {
                    let _ = snapshot_tx.send(ServerMessage::AlertCleared { id });
                }
                sent_alert_key = None;
            }
        }

        // Enforcement = the static anchor the saved rules demand (a deny
        // rule blocks its program whether or not a connection is live,
        // macOS pf-anchor parity) UNION the ledger's plan: denied apps plus
        // the LOCAL ports of denied sockets — never server addresses.
        enforced_once = true;
        let wanted = merge_blocklists(
            static_blocklist(&policy.0.rule_set()),
            to_blocklist(ledger.enforcement()),
        );
        match backend.enforce(&wanted) {
            Ok(outcome) => {
                if outcome.refused != last_refused {
                    for path in &outcome.refused {
                        eprintln!(
                            "rat-daemon: refusing whole-program block of shared service host {path}"
                        );
                    }
                    last_refused = outcome.refused;
                }
                // Paths that failed validation are reported
                // (once per change, like refusals) instead of aborting the
                // whole plan — the rest of the plan still applies.
                if outcome.rejected != last_rejected {
                    for path in &outcome.rejected {
                        eprintln!(
                            "rat-daemon: cannot enforce {path} (invalid path, reported and skipped)"
                        );
                    }
                    last_rejected = outcome.rejected;
                }
            }
            Err(e) => eprintln!("rat-daemon: enforcement failed: {e}"),
        }

        let _ = snapshot_tx.send(ServerMessage::Snapshot {
            connections: last_conns.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: Option<&str>, verdict: Verdict, enabled: bool, approved: bool) -> rat_core::Rule {
        rat_core::Rule {
            id: uuid::Uuid::new_v4(),
            verdict,
            process_path: path.map(str::to_string),
            signing_id: None,
            team_id: None,
            remote_domain: None,
            remote_host: None,
            remote_address: None,
            ports: None,
            proto: None,
            enabled,
            approved,
            lifetime: Lifetime::Forever,
            profile_id: None,
            group_id: None,
            created_at: chrono::Utc::now(),
            note: None,
        }
    }

    fn set_of(rules: Vec<rat_core::Rule>) -> rat_core::RuleSet {
        let mut set = rat_core::RuleSet::standard(None);
        set.rules = rules;
        set
    }

    #[test]
    fn unscoped_deny_makes_a_whole_program_block() {
        let set = set_of(vec![
            rule(Some("/bin/deny"), Verdict::Deny, true, true),
            rule(Some("/bin/allow"), Verdict::Allow, true, true),
            rule(Some("/bin/disabled"), Verdict::Deny, false, true),
            rule(None, Verdict::Deny, true, true),
            rule(Some("/bin/deny"), Verdict::Deny, true, true), // dedup
        ]);
        assert_eq!(static_blocklist(&set).paths, vec!["/bin/deny".to_string()]);
    }

    #[test]
    fn enabled_unapproved_unscoped_deny_still_blocks() {
        let set = set_of(vec![rule(Some("/bin/u"), Verdict::Deny, true, false)]);
        assert_eq!(static_blocklist(&set).paths, vec!["/bin/u".to_string()]);
    }

    #[test]
    fn scoped_deny_never_makes_a_whole_program_block() {
        let mut domain = rule(Some("/bin/a"), Verdict::Deny, true, true);
        domain.remote_domain = Some("example.com".into());
        let mut host = rule(Some("/bin/b"), Verdict::Deny, true, true);
        host.remote_host = Some("host.example".into());
        let mut addr = rule(Some("/bin/c"), Verdict::Deny, true, true);
        addr.remote_address = Some("203.0.113.5".into());
        let mut port = rule(Some("/bin/d"), Verdict::Deny, true, true);
        port.ports = Some(rat_core::PortRange {
            start: 443,
            end: 443,
        });
        let mut proto = rule(Some("/bin/e"), Verdict::Deny, true, true);
        proto.proto = Some(rat_types::Protocol::Udp);
        let set = set_of(vec![domain, host, addr, port, proto]);
        assert!(static_blocklist(&set).paths.is_empty());
    }

    #[test]
    fn deny_in_inactive_profile_or_disabled_group_does_not_block() {
        let mut set = set_of(Vec::new());
        let mut other_profile = rule(Some("/bin/p"), Verdict::Deny, true, true);
        other_profile.profile_id = Some(uuid::Uuid::new_v4());
        let mut in_active = rule(Some("/bin/q"), Verdict::Deny, true, true);
        in_active.profile_id = Some(set.active_profile_id);
        let group = rat_core::RuleGroup::new(uuid::Uuid::new_v4(), "g".into(), Some(false));
        let mut in_off_group = rule(Some("/bin/g"), Verdict::Deny, true, true);
        in_off_group.group_id = Some(group.id);
        set.groups.push(group);
        set.rules = vec![other_profile, in_active, in_off_group];
        assert_eq!(static_blocklist(&set).paths, vec!["/bin/q".to_string()]);
    }

    #[test]
    fn active_allow_rule_for_the_same_program_wins_over_unscoped_deny() {
        let set = set_of(vec![
            rule(Some("/bin/x"), Verdict::Deny, true, true),
            rule(Some("/bin/x"), Verdict::Allow, true, true),
        ]);
        assert!(static_blocklist(&set).paths.is_empty());
    }

    #[test]
    fn merge_unions_and_dedups() {
        let merged = merge_blocklists(
            rat_enforcer::Blocklist {
                paths: vec!["/a".into(), "/b".into()],
                local_ports: vec![1, 2],
            },
            rat_enforcer::Blocklist {
                paths: vec!["/b".into(), "/c".into()],
                local_ports: vec![2, 3],
            },
        );
        assert_eq!(
            merged.paths,
            vec!["/a".to_string(), "/b".to_string(), "/c".to_string()]
        );
        assert_eq!(merged.local_ports, vec![1, 2, 3]);
    }

    // The read-back must target ONLY this daemon's own prefixed rules, and
    // it is read-only. It covers both rule families (paths and ports).
    #[cfg(windows)]
    #[test]
    fn existing_rules_query_scopes_to_rat_prefix_and_reads_only() {
        let q = existing_rules_query();
        assert!(q.contains("-DisplayName 'Rat:path:*'"));
        assert!(q.contains("-DisplayName 'Rat:port:*'"));
        assert!(!q.to_lowercase().contains("remove"));
        assert!(!q.to_lowercase().contains("add"));
    }

    // A long path's rule has a hashed display name (`Rat:path:#<hash>`), so
    // the read-back must take the path from the program field, never parse
    // it out of the name, and its wildcard must still match the hashed form.
    #[cfg(windows)]
    #[test]
    fn existing_rules_query_reads_the_program_field_not_the_name() {
        let q = existing_rules_query();
        assert!(q.contains("Get-NetFirewallApplicationFilter"));
        assert!(q.contains("Select-Object -ExpandProperty Program"));
        assert!(
            rat_enforcer::windows::format_rule_name(&format!(r"C:\{}\a.exe", "d".repeat(300)))
                .starts_with("Rat:path:")
        );
    }

    // The read-back parse separates the path and port sections,
    // dedups the per-variant port lines (4 rules per port), and skips
    // non-numeric lines.
    #[cfg(windows)]
    #[test]
    fn parse_existing_output_splits_paths_and_ports() {
        let out = "C:\\a\\app.exe\n\nC:\\b\\tool.exe\n---RATPORTS---\n5300\n5300\n5300\n5300\nAny\n4443\n";
        let b = parse_existing_output(out);
        assert_eq!(
            b.paths,
            vec![r"C:\a\app.exe".to_string(), r"C:\b\tool.exe".to_string()]
        );
        assert_eq!(b.local_ports, vec![4443, 5300]);
    }

    // Read-back paths come out sorted and without duplicates (a program
    // with several rules, e.g. one per direction, arrives once per rule).
    #[cfg(windows)]
    #[test]
    fn parse_existing_output_sorts_and_dedups_paths() {
        let out =
            "C:\\z\\last.exe\nC:\\a\\app.exe\nC:\\z\\last.exe\nC:\\a\\app.exe\n---RATPORTS---\n";
        let b = parse_existing_output(out);
        assert_eq!(
            b.paths,
            vec![r"C:\a\app.exe".to_string(), r"C:\z\last.exe".to_string()]
        );
    }
}
