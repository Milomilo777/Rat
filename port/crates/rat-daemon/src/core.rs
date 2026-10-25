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
}

/// The enforcement half of the pipeline (PROPOSALS #10): turn the ledger's
/// EnforcementPlan into effective firewall state. Object-safe on purpose so
/// tests inject a recorder instead of netsh/nft.
pub trait EnforcementBackend: Send {
    /// #8 obligation (S8): remove every rule this daemon created. Called once
    /// at startup before the first apply, once on clean shutdown, and by the
    /// uninstall path (`rat-daemon --cleanup`).
    fn cleanup(&self) -> io::Result<()>;
    /// Make `wanted` effective. Implementations must be no-ops when the
    /// wanted state is already effective, and on failure must leave their
    /// notion of the current state behind so the next call retries the diff.
    fn enforce(&mut self, wanted: &rat_enforcer::Blocklist) -> io::Result<EnforceOutcome>;
}

/// Windows backend: `netsh advfirewall` per-program rules (ADR 0001 as
/// amended 2026-10-25, PROPOSALS #8). Local ports are the nft backend's axis.
#[cfg(windows)]
pub struct WindowsBackend {
    enforcer: rat_enforcer::windows::WindowsEnforcer,
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

    fn enforce(&mut self, wanted: &rat_enforcer::Blocklist) -> io::Result<EnforceOutcome> {
        use rat_enforcer::Enforcer;

        let wanted = rat_enforcer::Blocklist {
            paths: wanted.paths.clone(),
            local_ports: Vec::new(),
        };
        let plan = self.enforcer.plan(&wanted);
        let refused = plan.refused.clone();
        if plan.add.is_empty() && plan.remove.is_empty() {
            return Ok(EnforceOutcome {
                applied: false,
                refused,
            });
        }
        // S7: apply() honours RAT_DRY_RUN; on failure `current` stays behind
        // so the next tick retries the same diff instead of losing it.
        self.enforcer.apply(&plan)?;
        self.enforcer.current = wanted;
        Ok(EnforceOutcome {
            applied: true,
            refused,
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
/// RulesModel.addRule(from:verdict:scope:lifetime:)).
fn answer_current_alert(
    ledger: &mut Ledger,
    policy: &RuleEnginePolicy,
    verdict: Verdict,
    scope: rat_ledger::AnswerScope,
    lifetime: Lifetime,
) {
    let Some(answer) = ledger.alerts.answer_current(verdict, lifetime) else {
        return;
    };
    // An alert answer is a direct user decision: the rule it creates is
    // approved (unlike rule-file imports, which arrive unapproved — #11).
    if let Some(rule) =
        rat_ledger::rule_from_answer(&answer.alert, verdict, scope, lifetime, false, None)
    {
        policy.0.add(rule);
    }
}

/// Runs the whole data path (PROPOSALS #10): monitor -> ledger -> policy ->
/// enforcer, plus the alert fan-out to IPC clients. Re-judges the last
/// sample after every command so SetRules/AlertAnswer take effect without
/// waiting for the next tick. Exits when `shutdown` fires (best-effort
/// `cleanup()` first) or when every command sender is gone.
pub async fn run_pipeline(
    mut source: impl ConnectionSource + Send + 'static,
    policy: RuleEnginePolicy,
    mut ledger: Ledger,
    mut backend: impl EnforcementBackend,
    mut commands: mpsc::UnboundedReceiver<Command>,
    snapshot_tx: broadcast::Sender<ServerMessage>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    let mut last_conns: Vec<Connection> = Vec::new();
    let mut last_refused: Vec<String> = Vec::new();
    let mut next_alert_id: u64 = 0;
    let mut current_alert_id: Option<u64> = None;
    let mut sent_alert_key: Option<String> = None;

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                // #8 obligation: best-effort cleanup on clean shutdown so no
                // netsh rule / nft table outlives the daemon by accident.
                if let Err(e) = backend.cleanup() {
                    eprintln!("rat-daemon: shutdown cleanup failed: {e}");
                }
                break;
            }
            cmd = commands.recv() => {
                match cmd {
                    Some(Command::SetRules { rules }) => {
                        policy.0.set_rules(rules);
                    }
                    Some(Command::AlertAnswer { id, verdict, scope, lifetime }) => {
                        if current_alert_id == Some(id) {
                            answer_current_alert(&mut ledger, &policy, verdict, scope, lifetime);
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

        // Enforcement follows the ledger's plan: denied apps plus the LOCAL
        // ports of denied sockets — never server addresses (R4).
        let wanted = to_blocklist(ledger.enforcement());
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
            }
            Err(e) => eprintln!("rat-daemon: enforcement failed: {e}"),
        }

        let _ = snapshot_tx.send(ServerMessage::Snapshot {
            connections: last_conns.clone(),
        });
    }
}
