//! PROPOSALS #10 wiring tests: monitor -> ledger -> policy -> enforcer via
//! run_pipeline, and the #8 cleanup obligations via run_components. The
//! enforcer is a recorder so these run without netsh/nft/admin.

use rat_core::{Lifetime, Rule, Verdict};
use rat_daemon::core::{Command, EnforceOutcome, EnforcementBackend};
use rat_daemon::msg::ServerMessage;
use rat_ledger::{AlertCenterConfig, Ledger, LedgerConfig, RuleEnginePolicy};
use rat_types::{Connection, ConnectionSource, ProcessInfo, Protocol};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The recorder keeps ONE interleaved timeline so ordering claims
/// (cleanup before the first apply) are actually testable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Cleanup,
    Enforce(rat_enforcer::Blocklist),
}

#[derive(Default, Clone)]
struct RecorderBackend {
    events: Arc<Mutex<Vec<Event>>>,
    fail_enforce: Arc<AtomicBool>,
}

impl EnforcementBackend for RecorderBackend {
    fn cleanup(&self) -> io::Result<()> {
        self.events.lock().unwrap().push(Event::Cleanup);
        Ok(())
    }

    fn enforce(&mut self, wanted: &rat_enforcer::Blocklist) -> io::Result<EnforceOutcome> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Enforce(wanted.clone()));
        if self.fail_enforce.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected enforcement failure"));
        }
        Ok(EnforceOutcome {
            applied: true,
            refused: vec![],
        })
    }
}

impl RecorderBackend {
    fn enforced_paths(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Event::Enforce(b) => Some(b.paths.clone()),
                Event::Cleanup => None,
            })
            .flatten()
            .collect()
    }

    fn any_enforced_path(&self) -> bool {
        !self.enforced_paths().is_empty()
    }

    fn last_enforced(&self) -> Option<rat_enforcer::Blocklist> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|e| match e {
                Event::Enforce(b) => Some(b.clone()),
                Event::Cleanup => None,
            })
    }

    fn first_event(&self) -> Option<Event> {
        self.events.lock().unwrap().first().cloned()
    }

    fn cleanup_count(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Event::Cleanup))
            .count()
    }
}

#[derive(Clone)]
struct ScriptedSource {
    conns: Vec<Connection>,
}

impl ConnectionSource for ScriptedSource {
    fn sample(&mut self) -> io::Result<Vec<Connection>> {
        Ok(self.conns.clone())
    }
}

fn conn(exe: &str, name: &str, remote_port: u16, local_port: u16) -> Connection {
    Connection {
        process: ProcessInfo {
            pid: 42,
            exe: Some(PathBuf::from(exe)),
            name: name.to_string(),
            user: None,
        },
        protocol: Protocol::Tcp,
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), local_port),
        remote: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            remote_port,
        )),
        listening: false,
        bytes_in: Some(1000),
        bytes_out: Some(2000),
        via_vpn: false,
    }
}

fn deny_rule(path: &str) -> Rule {
    Rule {
        id: Uuid::new_v4(),
        verdict: Verdict::Deny,
        process_path: Some(path.to_string()),
        signing_id: None,
        team_id: None,
        remote_domain: None,
        remote_host: None,
        remote_address: None,
        ports: None,
        proto: None,
        enabled: true,
        approved: true,
        lifetime: Lifetime::Forever,
        profile_id: None,
        group_id: None,
        created_at: chrono::Utc::now(),
        note: None,
    }
}

fn test_app() -> &'static str {
    if cfg!(windows) {
        r"C:\evil\app.exe"
    } else {
        "/usr/bin/evil"
    }
}

async fn wait_for_snapshot(
    snapshot_rx: &mut tokio::sync::broadcast::Receiver<ServerMessage>,
    timeout: Duration,
) -> ServerMessage {
    let deadline = Instant::now() + timeout;
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a snapshot"
        );
        let msg = tokio::time::timeout(timeout, snapshot_rx.recv())
            .await
            .expect("no broadcast at all")
            .expect("snapshot channel closed");
        if matches!(msg, ServerMessage::Snapshot { .. }) {
            return msg;
        }
    }
}

/// Poll until `pred` holds against the recorder, with a deadline.
async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !pred() {
        assert!(Instant::now() < deadline, "condition never became true");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// PROPOSALS #10: SetRules must reach the rule engine and produce an
// enforcement diff on the backend WITHOUT waiting for the next sample tick;
// the ledger's plan (denied app + the denied socket's LOCAL port) is what
// gets enforced (R4 / L2 wiring).
#[tokio::test]
async fn test_set_rules_enforces_denied_app_and_local_port() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let recorder = RecorderBackend::default();

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let source = ScriptedSource {
        conns: vec![conn(app, "evil", 443, 54321)],
    };

    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        source,
        policy,
        ledger,
        recorder.clone(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    // First pass: no rules yet, nothing to enforce.
    wait_for_snapshot(&mut snapshot_rx, Duration::from_secs(5)).await;
    assert!(
        !recorder.any_enforced_path(),
        "no path must be enforced before any rule exists"
    );

    cmd_tx
        .send(Command::SetRules {
            rules: vec![deny_rule(app)],
        })
        .expect("command channel open");

    wait_until(Duration::from_secs(5), || {
        recorder
            .last_enforced()
            .is_some_and(|b| b.paths.contains(&app.to_string()))
    })
    .await;

    let applied = recorder.last_enforced().expect("enforcement recorded");
    assert_eq!(applied.paths, vec![app.to_string()]);
    // The denied socket's local port flows to the enforcer (port axis).
    assert_eq!(applied.local_ports, vec![54321]);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

// PROPOSALS #10: an unknown connection (default verdict Ask) queues an alert
// after warmup; the AlertRequest goes out with an id, and the matching
// AlertAnswer takes the alert out of the queue, creates the rule and
// enforces it (port of RulesModel.addRule(from:verdict:scope:lifetime:)).
#[tokio::test]
async fn test_alert_answer_creates_rule_and_enforces() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let recorder = RecorderBackend::default();

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let source = ScriptedSource {
        conns: vec![conn(app, "evil", 443, 54321)],
    };

    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        source,
        policy,
        ledger,
        recorder.clone(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    // Wait for the AlertRequest the pipeline broadcasts for the Ask verdict.
    let deadline = Instant::now() + Duration::from_secs(5);
    let alert_request = loop {
        assert!(Instant::now() < deadline, "no AlertRequest ever arrived");
        let msg = tokio::time::timeout(Duration::from_secs(5), snapshot_rx.recv())
            .await
            .expect("no broadcast at all")
            .expect("snapshot channel closed");
        if let ServerMessage::AlertRequest { id, alert } = msg {
            break (id, alert);
        }
    };
    let (id, alert) = alert_request;
    assert_eq!(alert.app, app, "the alert names the asking app");

    cmd_tx
        .send(Command::AlertAnswer {
            id,
            verdict: Verdict::Deny,
            scope: rat_ledger::AnswerScope::Any,
            lifetime: Lifetime::Forever,
        })
        .expect("command channel open");

    wait_until(Duration::from_secs(5), || {
        recorder
            .last_enforced()
            .is_some_and(|b| b.paths.contains(&app.to_string()))
    })
    .await;
    let applied = recorder.last_enforced().expect("enforcement recorded");
    assert_eq!(applied.paths, vec![app.to_string()]);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

// PROPOSALS #10: an AlertAnswer with a stale id (no matching current alert)
// must be ignored — no rule, no enforcement.
#[tokio::test]
async fn test_stale_alert_answer_is_ignored() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let recorder = RecorderBackend::default();

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let source = ScriptedSource {
        conns: vec![conn(app, "evil", 443, 54321)],
    };

    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        source,
        policy,
        ledger,
        recorder.clone(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    wait_for_snapshot(&mut snapshot_rx, Duration::from_secs(5)).await;

    cmd_tx
        .send(Command::AlertAnswer {
            id: 999_999,
            verdict: Verdict::Deny,
            scope: rat_ledger::AnswerScope::Any,
            lifetime: Lifetime::Forever,
        })
        .expect("command channel open");

    // Give the pipeline a moment to process the (ignored) answer, then assert
    // nothing was ever enforced.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !recorder.any_enforced_path(),
        "a stale answer must not create rules or enforcement"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

// #8 obligations: cleanup() runs once at startup (before the first apply)
// and once on clean shutdown. Runs through run_components with the real
// IPC endpoint so the shell is covered too.
#[tokio::test]
async fn test_cleanup_runs_on_start_and_shutdown() {
    let endpoint = format!("rat_test_cleanup_{}_{}", std::process::id(), line!());
    let endpoint = if cfg!(windows) {
        format!(r"\\.\pipe\{endpoint}")
    } else {
        format!("/tmp/{endpoint}.sock")
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let recorder = RecorderBackend::default();
    let source = ScriptedSource { conns: vec![] };

    let ep = endpoint.clone();
    let task = tokio::spawn(rat_daemon::run_components(
        ep,
        source,
        recorder.clone(),
        shutdown_rx,
    ));

    wait_until(Duration::from_secs(5), || recorder.cleanup_count() >= 1).await;
    assert_eq!(
        recorder.first_event(),
        Some(Event::Cleanup),
        "the startup cleanup must be the very first backend event"
    );
    assert!(
        !recorder.any_enforced_path(),
        "startup cleanup must run BEFORE the first apply"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run_components must end on shutdown")
        .expect("pipeline task did not panic")
        .expect("clean shutdown is not an error");
    assert_eq!(recorder.cleanup_count(), 2, "exactly one shutdown cleanup");
}

// PROPOSALS #10: a failing enforcement backend must not kill the pipeline —
// the monitor keeps running and the next tick retries the diff.
#[tokio::test]
async fn test_enforcement_failure_does_not_stop_the_pipeline() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let recorder = RecorderBackend::default();
    recorder.fail_enforce.store(true, Ordering::SeqCst);

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let source = ScriptedSource { conns: vec![] };

    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        source,
        policy,
        ledger,
        recorder.clone(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    // Two snapshots after the failure started: the pipeline survived.
    wait_for_snapshot(&mut snapshot_rx, Duration::from_secs(5)).await;
    wait_for_snapshot(&mut snapshot_rx, Duration::from_secs(5)).await;
    assert!(
        recorder
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Enforce(_))),
        "the backend was really called (and failed)"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

#[cfg(windows)]
#[test]
fn test_windows_backend_refuses_shared_host_and_enforces_paths() {
    use rat_enforcer::Blocklist;

    // S7: RAT_DRY_RUN makes apply() a no-op printer, so the backend diff and
    // refusal logic run for real without touching the firewall.
    std::env::set_var("RAT_DRY_RUN", "1");

    let mut backend = rat_daemon::core::WindowsBackend::new();

    let svchost = r"C:\Windows\System32\svchost.exe";
    let outcome = backend
        .enforce(&Blocklist {
            paths: vec![svchost.to_string()],
            local_ports: vec![],
        })
        .expect("dry-run enforce must not fail");
    assert!(
        outcome.refused.contains(&svchost.to_string()),
        "shared service hosts are refused: {outcome:?}"
    );
    assert!(!outcome.applied, "a refused plan applies nothing");

    let app = r"C:\evil\app.exe";
    let wanted = Blocklist {
        paths: vec![app.to_string()],
        local_ports: vec![],
    };
    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(outcome.applied, "a plain app gets per-program rules");
    assert!(outcome.refused.is_empty());

    // Already-effective state is a no-op (no netsh churn per tick).
    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(!outcome.applied, "unchanged state must not re-apply");
}

#[cfg(not(windows))]
#[test]
fn test_linux_backend_enforces_and_skips_unchanged() {
    use rat_enforcer::Blocklist;

    std::env::set_var("RAT_DRY_RUN", "1");

    let mut backend = rat_daemon::core::LinuxBackend::new();

    let wanted = Blocklist {
        paths: vec![],
        local_ports: vec![4444],
    };
    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(outcome.applied, "first wanted state is applied");

    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(!outcome.applied, "unchanged state must not re-apply");

    // A port that dropped out (socket closed, PROPOSALS #3) is part of the
    // next diff.
    let outcome = backend
        .enforce(&Blocklist {
            paths: vec![],
            local_ports: vec![],
        })
        .expect("dry-run enforce");
    assert!(outcome.applied, "port removal re-applies the ruleset");
}
