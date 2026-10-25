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

/// Commands the IPC layer forwards into the pipeline (PROPOSALS #10). The
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
}

/// What [`EnforcementBackend::enforce`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnforceOutcome {
    pub applied: bool,
    /// Paths the backend REFUSED to block (shared service hosts, W2).
    pub refused: Vec<String>,
    /// Paths the backend could NOT enforce (failed path validation,
    /// review-01 R8): reported, skipped, the rest of the plan still applies.
    pub rejected: Vec<String>,
}

/// The enforcement half of the pipeline (PROPOSALS #10): turn the ledger's
/// EnforcementPlan into effective firewall state. Object-safe on purpose so
/// tests inject a recorder instead of netsh/nft.
pub trait EnforcementBackend: Send {
    /// #8 obligation (S8): remove every rule this daemon created. The
    /// UNINSTALL path only (`rat-daemon --cleanup`): startup reconciles
    /// instead (R2/e2e-01) and a clean stop keeps the rules (macOS
    /// persistent-anchor parity).
    fn cleanup(&self) -> io::Result<()>;
    /// Read back the rules this backend currently holds, so a restart can
    /// RECONCILE against them instead of wiping (R2: read existing, diff
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
/// amended 2026-10-25, PROPOSALS #8) plus per-port rules for the denied
/// sockets' local ports (review-01 R5 — the Windows mirror of the Linux
/// backend's nft port set).
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
    fn cleanup(&self) -> io::Result<()> {
        use rat_enforcer::Enforcer;
        self.enforcer.cleanup()
    }

    fn existing(&self) -> io::Result<rat_enforcer::Blocklist> {
        use std::process::Command;
        // Read-only query; blocking is fine here because this runs once at
        // startup, before the IPC server exists. Child timeouts are R16.
        let out = Command::new(rat_enforcer::windows::powershell_path()?)
            .args(["-NoProfile", "-Command", existing_rules_query()])
            .output()?;
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

        // review-01 R5: the port axis reaches the plan (dropping it here made
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
        // S7: apply() honours RAT_DRY_RUN. review-01 R6: apply() itself
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
/// of the wanted set — no stale per-port rule survives, PROPOSALS #3).
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
    fn cleanup(&self) -> io::Result<()> {
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

/// The anchor the SAVED rules demand, independent of any live connection —
/// macOS parity: the pf anchor holds one block per deny rule's program, so an
/// idle app's block exists BEFORE its next connection attempt (RulesModel +
/// Enforcer.swift). This is the "saved plan" the startup reconcile diffs
/// against and the stable half of every enforce round. Only whole-program
/// deny rules contribute: enabled (a disabled rule blocks nothing), approved
/// (an unapproved import must not block, #11) and with a process path.
pub fn static_blocklist(rules: &[rat_core::Rule]) -> rat_enforcer::Blocklist {
    let mut paths: Vec<String> = rules
        .iter()
        .filter(|r| r.enabled && r.approved && r.verdict == rat_core::Verdict::Deny)
        .filter_map(|r| r.process_path.clone())
        .filter(|p| !p.is_empty() && p != UNKNOWN_APP)
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
/// every `Rat:port:*` rule this daemon owns (review-01 R5: the port axis is
/// reconciled too). Scoped to the daemon's own prefixes, so foreign rules can
/// never enter the reconcile diff (e2e-01 item 3). Read-only. The marker
/// separates the two sections for [`parse_existing_output`].
#[cfg(windows)]
fn existing_rules_query() -> &'static str {
    "Get-NetFirewallRule -DisplayName 'Rat:path:*' -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter | Select-Object -ExpandProperty Program; Write-Output '---RATPORTS---'; Get-NetFirewallRule -DisplayName 'Rat:port:*' -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter | Select-Object -ExpandProperty LocalPort"
}

#[cfg(windows)]
const PORTS_MARKER: &str = "---RATPORTS---";

/// Splits the read-back output into paths (before the marker) and local
/// ports (after it). A `Rat:port:*` port exists as FOUR netsh rules (out/in x
/// TCP/UDP), so the same LocalPort arrives once per rule — dedup here keeps
/// the reconcile diff from removing one port three times. Non-numeric port
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
    local_ports.sort();
    local_ports.dedup();
    rat_enforcer::Blocklist { paths, local_ports }
}

/// Best-effort persistence: the rule set survives a restart (Swift
/// RulesModel parity). `save_set` keeps only Forever rules — UntilQuit
/// session rules are supposed to die with the daemon.
fn persist_rules(store: &rat_core::RuleStore, policy: &RuleEnginePolicy) {
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
/// the answer needs a rule, add it to the engine (PROPOSALS #10; port of
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

/// Runs the whole data path (PROPOSALS #10): monitor -> ledger -> policy ->
/// enforcer, plus the alert fan-out to IPC clients. Re-judges the last
/// sample after every command so SetRules/AlertAnswer take effect without
/// waiting for the next tick. Exits when `shutdown` fires (rules are KEPT —
/// persistent anchor, the uninstall path removes them) or when every command
/// sender is gone.
// The five components + three channels are the pipeline's real shape; a
// bundling struct would move, not remove, the coupling.
#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline(
    mut source: impl ConnectionSource + Send + 'static,
    policy: RuleEnginePolicy,
    mut ledger: Ledger,
    mut backend: impl EnforcementBackend,
    store: std::sync::Arc<rat_core::RuleStore>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    snapshot_tx: broadcast::Sender<ServerMessage>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    let mut last_conns: Vec<Connection> = Vec::new();
    let mut last_refused: Vec<String> = Vec::new();
    let mut last_rejected: Vec<String> = Vec::new();
    let mut next_alert_id: u64 = 0;
    let mut current_alert_id: Option<u64> = None;
    let mut sent_alert_key: Option<String> = None;

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                // e2e-01 stop decision (macOS parity): the rules SURVIVE a
                // stop — the persistent anchor keeps blocking while the
                // daemon is down (rat-enforcerd KeepAlive, Enforcer.swift:144;
                // only Remove Helper clears them, :179). A wipe here would
                // re-open the fail-open window R2 closes at startup. Full
                // removal is the uninstall path (`rat-daemon --cleanup`).
                break;
            }
            cmd = commands.recv() => {
                match cmd {
                    Some(Command::SetRules { rules }) => {
                        policy.0.set_rules(rules);
                        persist_rules(&store, &policy);
                    }
                    Some(Command::AlertAnswer { id, verdict, scope, lifetime }) => {
                        if current_alert_id == Some(id) {
                            if answer_current_alert(&mut ledger, &policy, verdict, scope, lifetime) {
                                persist_rules(&store, &policy);
                            }
                        } else {
                            eprintln!("rat-daemon: ignoring stale AlertAnswer id {id}");
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
                        // a read hiccup into an enforcement outage.
                        eprintln!("rat-daemon: monitor sample failed: {e}");
                        continue;
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
                current_alert_id = None;
                sent_alert_key = None;
            }
        }

        // Enforcement = the static anchor the saved rules demand (a deny
        // rule blocks its program whether or not a connection is live,
        // macOS pf-anchor parity) UNION the ledger's plan: denied apps plus
        // the LOCAL ports of denied sockets — never server addresses (R4).
        let wanted = merge_blocklists(
            static_blocklist(&policy.0.all_rules()),
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
                // review-01 R8: paths that failed validation are reported
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

    #[test]
    fn static_blocklist_takes_only_enabled_approved_deny_program_rules() {
        let rules = vec![
            rule(Some("/bin/deny"), Verdict::Deny, true, true),
            rule(Some("/bin/allow"), Verdict::Allow, true, true),
            rule(Some("/bin/disabled"), Verdict::Deny, false, true),
            rule(Some("/bin/unapproved"), Verdict::Deny, true, false),
            rule(None, Verdict::Deny, true, true),
            rule(Some("/bin/deny"), Verdict::Deny, true, true), // dedup
        ];
        assert_eq!(
            static_blocklist(&rules).paths,
            vec!["/bin/deny".to_string()]
        );
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

    // e2e-01 item 3: the read-back must target ONLY this daemon's own
    // prefixed rules, and it is read-only. review-01 R5: it covers both rule
    // families (paths and ports).
    #[cfg(windows)]
    #[test]
    fn existing_rules_query_scopes_to_rat_prefix_and_reads_only() {
        let q = existing_rules_query();
        assert!(q.contains("-DisplayName 'Rat:path:*'"));
        assert!(q.contains("-DisplayName 'Rat:port:*'"));
        assert!(!q.to_lowercase().contains("remove"));
        assert!(!q.to_lowercase().contains("add"));
    }

    // review-01 R5: the read-back parse separates the path and port sections,
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
}
