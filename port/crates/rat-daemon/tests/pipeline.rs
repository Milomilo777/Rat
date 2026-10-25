//! wiring tests: monitor -> ledger -> policy -> enforcer via
//! run_pipeline, and the #8/e2e-01 restart obligations via run_components:
//! startup RECONCILES (read existing rules, diff against the saved plan,
//! never wipe-then-apply) before the IPC endpoint serves, a clean stop KEEPS
//! the rules (macOS persistent-anchor parity), and rules persist to disk so a
//! restart reloads the anchor. The enforcer is a recorder so these run
//! without netsh/nft/admin.

use rat_core::{Lifetime, Rule, RuleStore, Verdict};
use rat_daemon::core::{Command, EnforceOutcome, EnforcementBackend};
use rat_daemon::msg::ServerMessage;
use rat_ledger::{AlertCenterConfig, Ledger, LedgerConfig, RuleEnginePolicy};
use rat_types::{Connection, ConnectionSource, ProcessInfo, Protocol};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The recorder keeps ONE interleaved timeline so ordering claims
/// (reconcile before the first apply, nothing on stop) are testable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Cleanup,
    Adopt(rat_enforcer::Blocklist),
    Enforce(rat_enforcer::Blocklist),
}

#[derive(Default, Clone)]
struct RecorderBackend {
    events: Arc<Mutex<Vec<Event>>>,
    fail_enforce: Arc<AtomicBool>,
    /// What `existing()` reports (the read-back of live firewall state);
    /// None makes the read fail, exercising the tolerant path.
    existing_state: Arc<Mutex<Option<rat_enforcer::Blocklist>>>,
    /// When set, `existing()` blocks on this receiver first, so a test can
    /// hold the startup reconcile and observe the endpoint is NOT serving.
    existing_gate: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
}

impl EnforcementBackend for RecorderBackend {
    fn cleanup(&self) -> io::Result<()> {
        self.events.lock().unwrap().push(Event::Cleanup);
        Ok(())
    }

    fn existing(&self) -> io::Result<rat_enforcer::Blocklist> {
        if let Some(rx) = self.existing_gate.lock().unwrap().take() {
            // Blocks the reconcile (and with it the whole startup) until the
            // test drops the sender. Err on a dropped sender = gate released.
            let _ = rx.recv();
        }
        self.existing_state
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| io::Error::other("no existing state configured"))
    }

    fn adopt(&mut self, existing: rat_enforcer::Blocklist) {
        self.events.lock().unwrap().push(Event::Adopt(existing));
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
            rejected: vec![],
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
                Event::Adopt(_) | Event::Cleanup => None,
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
                Event::Adopt(_) | Event::Cleanup => None,
            })
    }

    fn cleanup_count(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Event::Cleanup))
            .count()
    }

    fn events_snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
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

/// Two paths a previous daemon left rules for but the saved plan no longer
/// wants — the stale half of the reconcile scenario.
fn stale_apps() -> [&'static str; 2] {
    if cfg!(windows) {
        [r"C:\stale\one.exe", r"C:\stale\two.exe"]
    } else {
        ["/usr/bin/stale1", "/usr/bin/stale2"]
    }
}

static SEQ: AtomicU32 = AtomicU32::new(0);

fn temp_rules_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rat_daemon_test_{tag}_{}_{}.json",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ))
}

fn dummy_store() -> Arc<RuleStore> {
    Arc::new(RuleStore::new(temp_rules_path("pipeline")))
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

/// Whether the IPC endpoint is accepting clients right now (sync: the
/// underlying probe is a named-pipe CreateFile / socket-path existence check).
fn endpoint_serving(endpoint: &str) -> bool {
    #[cfg(windows)]
    {
        tokio::net::windows::named_pipe::ClientOptions::new()
            .open(endpoint)
            .is_ok()
    }
    #[cfg(unix)]
    {
        std::path::Path::new(endpoint).exists()
    }
}

fn test_endpoint(tag: &str) -> String {
    let name = format!("rat_test_{tag}_{}_{}", std::process::id(), line!());
    if cfg!(windows) {
        format!(r"\\.\pipe\{name}")
    } else {
        format!("/tmp/{name}.sock")
    }
}

// SetRules must reach the rule engine and produce an
// enforcement diff on the backend WITHOUT waiting for the next sample tick;
// the ledger's plan (denied app + the denied socket's LOCAL port) unions with
// the static anchor the saved rules demand (L2 wiring).
#[tokio::test]
async fn test_set_rules_enforces_denied_app_and_local_port() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
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
        dummy_store(),
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
        .await
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

// an unknown connection (default verdict Ask) queues an alert
// after warmup; the AlertRequest goes out with an id, and the matching
// AlertAnswer takes the alert out of the queue, creates the rule and
// enforces it (port of RulesModel.addRule(from:verdict:scope:lifetime:)).
#[tokio::test]
async fn test_alert_answer_creates_rule_and_enforces() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
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
        dummy_store(),
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
        .await
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

// an AlertAnswer with a stale id (no matching current alert)
// must be ignored — no rule, no enforcement.
#[tokio::test]
async fn test_stale_alert_answer_is_ignored() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
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
        dummy_store(),
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
        .await
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

// The restart scenario (W4): the rules file holds ONE wanted deny
// (W); the live firewall holds W + two stale rules from a predecessor. The
// daemon must (1) read the existing rules back, (2) reconcile BEFORE the IPC
// endpoint serves, (3) ask for exactly the wanted set — the diff keeps W and
// removes only the stale ones, and (4) never wipe via cleanup(). Runs through
// run_components with the real IPC endpoint so the shell is covered too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_startup_reconciles_before_serving_and_keeps_wanted() {
    let wanted_app = test_app();
    let [stale1, stale2] = stale_apps();

    // A previous daemon saved one deny rule for `wanted_app`.
    let rules_path = temp_rules_path("reconcile");
    RuleStore::new(rules_path.clone())
        .save(vec![deny_rule(wanted_app)])
        .expect("seed rules file");

    // ...and left W + two stale rules in the firewall.
    let recorder = RecorderBackend::default();
    *recorder.existing_state.lock().unwrap() = Some(rat_enforcer::Blocklist {
        paths: vec![
            wanted_app.to_string(),
            stale1.to_string(),
            stale2.to_string(),
        ],
        local_ports: vec![],
    });
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    *recorder.existing_gate.lock().unwrap() = Some(gate_rx);

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let endpoint = test_endpoint("reconcile");
    let source = ScriptedSource { conns: vec![] };

    let ep = endpoint.clone();
    let task = tokio::spawn(rat_daemon::run_components(
        ep,
        source,
        recorder.clone(),
        rules_path.clone(),
        shutdown_rx,
    ));

    // Phase 1 — the reconcile gate is held: no backend events yet and the
    // endpoint must NOT be serving. multi_thread flavor: the blocked
    // existing() sits on one worker while we probe from this one.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut observed_not_serving = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert!(
            !endpoint_serving(&endpoint),
            "IPC served before the startup reconcile completed (gate still held)"
        );
        observed_not_serving = true;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        observed_not_serving,
        "probe never ran while the gate was held"
    );
    assert!(
        recorder.events_snapshot().is_empty(),
        "no backend event may precede the reconcile (found {:?})",
        recorder.events_snapshot()
    );

    // Phase 2 — release the gate: reconcile runs (read-back, adopt, enforce
    // of the static anchor from the saved rules), THEN the endpoint serves.
    drop(gate_tx);
    wait_until(Duration::from_secs(10), || endpoint_serving(&endpoint)).await;

    let events = recorder.events_snapshot();
    assert_eq!(
        events.first(),
        Some(&Event::Adopt(rat_enforcer::Blocklist {
            paths: vec![
                wanted_app.to_string(),
                stale1.to_string(),
                stale2.to_string(),
            ],
            local_ports: vec![],
        })),
        "the reconcile must ADOPT the read-back state before anything else: {events:?}"
    );
    let first_enforce = events
        .iter()
        .find_map(|e| match e {
            Event::Enforce(b) => Some(b.clone()),
            Event::Adopt(_) | Event::Cleanup => None,
        })
        .expect("the reconcile enforce ran");
    assert_eq!(
        first_enforce.paths,
        vec![wanted_app.to_string()],
        "the wanted set is exactly the saved plan's anchor (stale rules are the DIFF's job, never re-added): {events:?}"
    );
    assert!(first_enforce.local_ports.is_empty());
    assert!(
        !events.iter().any(|e| matches!(e, Event::Cleanup)),
        "startup must RECONCILE, never wipe via cleanup(): {events:?}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run_components must end on shutdown")
        .expect("pipeline task did not panic")
        .expect("clean shutdown is not an error");
    assert_eq!(
        recorder.cleanup_count(),
        0,
        "a clean stop must keep the rules (persistent anchor, macOS parity)"
    );
}

// e2e-01 item 2 decision (macOS parity, Enforcer.swift:144/:179): a clean
// stop KEEPS the rules — the persistent anchor keeps blocking while the
// daemon is down. Full removal is the uninstall path's job (`--cleanup`).
#[tokio::test]
async fn test_stop_keeps_rules_no_cleanup_on_shutdown() {
    let rules_path = temp_rules_path("keep_on_stop");
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let recorder = RecorderBackend::default();
    let source = ScriptedSource { conns: vec![] };

    let endpoint = test_endpoint("keep_on_stop");
    let task = tokio::spawn(rat_daemon::run_components(
        endpoint,
        source,
        recorder.clone(),
        rules_path,
        shutdown_rx,
    ));

    // Daemon ran (an enforce round happened), then a clean stop.
    wait_until(Duration::from_secs(5), || {
        recorder
            .events_snapshot()
            .iter()
            .any(|e| matches!(e, Event::Enforce(_)))
    })
    .await;

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run_components must end on shutdown")
        .expect("pipeline task did not panic")
        .expect("clean shutdown is not an error");
    assert_eq!(
        recorder.cleanup_count(),
        0,
        "a clean stop must NOT remove rules (persistent anchor, macOS parity)"
    );
}

// Fake-enforcer rule: never real firewall changes in unit
// tests. A garbage rules file is an
// ERROR, and the daemon keeps the current firewall state (no startup
// reconcile, nothing adopted — seeding `current` is what lets the diff
// remove rules) while it still SERVES. Every enforcement round that runs
// carries an empty anchor: the unknown plan invents none until a client
// sends rules.
#[tokio::test]
async fn test_corrupt_rules_file_daemon_still_serves() {
    let rules_path = temp_rules_path("corrupt");
    std::fs::write(&rules_path, b"{not json at all").expect("seed corrupt file");

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let recorder = RecorderBackend::default();
    let source = ScriptedSource { conns: vec![] };

    let endpoint = test_endpoint("corrupt");
    let task = tokio::spawn(rat_daemon::run_components(
        endpoint.clone(),
        source,
        recorder.clone(),
        rules_path,
        shutdown_rx,
    ));

    wait_until(Duration::from_secs(10), || endpoint_serving(&endpoint)).await;
    // Wait for at least one full pipeline round so the assertion below covers
    // the tick path, not only startup.
    wait_until(Duration::from_secs(5), || {
        recorder
            .events_snapshot()
            .iter()
            .any(|e| matches!(e, Event::Enforce(_)))
    })
    .await;

    let events = recorder.events_snapshot();
    assert!(
        !events.iter().any(|e| matches!(e, Event::Adopt(_))),
        "nothing may be adopted while the plan is unknown: {events:?}"
    );
    for event in &events {
        if let Event::Enforce(b) = event {
            assert!(
                b.paths.is_empty() && b.local_ports.is_empty(),
                "an unknown plan must never invent an enforcement anchor: {event:?}"
            );
        }
    }

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run_components must end on shutdown")
        .expect("pipeline task did not panic")
        .expect("clean shutdown is not an error");
}

// the prescribed fail-open scenario: rules.json truncated
// MID-JSON (a crash during a non-atomic save) with a firewall preloaded with
// a predecessor's rules. The truncated file must not become a zero-rule plan:
// the daemon serves, the preloaded state is never adopted, and no enforcement
// round proposes the predecessor's paths. The old behaviour parsed the
// truncated file into zero rules with Ok and removed every real Rat:* rule.
#[tokio::test]
async fn test_truncated_rules_file_keeps_current_firewall_state() {
    let rules_path = temp_rules_path("truncated");
    // Valid JSON up to the cut: parses as neither RuleSet nor legacy Vec<Rule>.
    std::fs::write(
        &rules_path,
        br#"{"version":2,"profiles":[],"rules":[{"id":" "#,
    )
    .expect("seed truncated rules file");

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let recorder = RecorderBackend::default();
    // The firewall still holds rules a previous daemon created.
    let [stale1, _] = stale_apps();
    let preloaded = vec![test_app().to_string(), stale1.to_string()];
    *recorder.existing_state.lock().unwrap() = Some(rat_enforcer::Blocklist {
        paths: preloaded.clone(),
        local_ports: vec![],
    });

    let source = ScriptedSource { conns: vec![] };
    let endpoint = test_endpoint("truncated");
    let task = tokio::spawn(rat_daemon::run_components(
        endpoint.clone(),
        source,
        recorder.clone(),
        rules_path,
        shutdown_rx,
    ));

    wait_until(Duration::from_secs(10), || endpoint_serving(&endpoint)).await;
    wait_until(Duration::from_secs(5), || {
        recorder
            .events_snapshot()
            .iter()
            .any(|e| matches!(e, Event::Enforce(_)))
    })
    .await;

    let events = recorder.events_snapshot();
    assert!(
        !events.iter().any(|e| matches!(e, Event::Adopt(_))),
        "the preloaded firewall state must never be adopted while the plan is unknown (adopting is what makes the diff remove): {events:?}"
    );
    for event in &events {
        if let Event::Enforce(b) = event {
            assert!(
                b.paths.iter().all(|p| !preloaded.contains(p)),
                "an unknown plan must never propose the predecessor's rules: {event:?}"
            );
        }
    }

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run_components must end on shutdown")
        .expect("pipeline task did not panic")
        .expect("clean shutdown is not an error");
}

// The reconcile diff itself on the REAL windows backend: after adopting what the
// firewall read-back reported, the plan must remove exactly the stale rules
// and never the wanted one — reconcile, not wipe-then-apply.
// The port axis diffs the same way (stale port rule goes, wanted port is
// added).
#[cfg(windows)]
#[test]
fn test_windows_adopt_then_plan_reconciles() {
    use rat_enforcer::Enforcer;

    let wanted = test_app();
    let [stale1, stale2] = stale_apps();
    let foreign = r"C:\foreign\tool.exe";

    let mut backend = rat_daemon::core::WindowsBackend::new();
    backend.adopt(rat_enforcer::Blocklist {
        paths: vec![wanted.to_string(), stale1.to_string(), stale2.to_string()],
        local_ports: vec![7777],
    });

    let plan = backend.enforcer.plan(&rat_enforcer::Blocklist {
        paths: vec![wanted.to_string()],
        local_ports: vec![8888],
    });
    assert!(plan.add.is_empty(), "nothing to add: W is already there");
    assert_eq!(plan.remove, vec![stale1.to_string(), stale2.to_string()]);
    assert!(
        !plan.remove.contains(&wanted.to_string()),
        "a wanted rule must NEVER be deleted by the reconcile diff"
    );
    assert!(
        !plan.remove.contains(&foreign.to_string()),
        "a foreign rule was never adopted, so it is never removed"
    );
    assert_eq!(
        plan.add_ports,
        vec![8888],
        "the wanted port is added by the diff"
    );
    assert_eq!(
        plan.remove_ports,
        vec![7777],
        "a stale port rule is removed by the diff"
    );
}

// SetRules must persist the rule set to the store (Swift RulesModel parity:
// rules survive a restart) — save happens with the change, not on quit.
#[tokio::test]
async fn test_set_rules_persists_to_store() {
    let app = test_app();
    let store = dummy_store();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
    let recorder = RecorderBackend::default();

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let source = ScriptedSource { conns: vec![] };

    let store_path = store.url.clone();
    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        source,
        policy,
        ledger,
        recorder.clone(),
        store,
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    wait_for_snapshot(&mut snapshot_rx, Duration::from_secs(5)).await;
    cmd_tx
        .send(Command::SetRules {
            rules: vec![deny_rule(app)],
        })
        .await
        .expect("command channel open");
    wait_until(Duration::from_secs(5), || recorder.any_enforced_path()).await;

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();

    let loaded = RuleStore::new(store_path).load().expect("rules were saved");
    assert_eq!(loaded.len(), 1, "exactly the deny rule persists");
    assert_eq!(loaded[0].process_path.as_deref(), Some(app));
    assert_eq!(loaded[0].verdict, Verdict::Deny);
    assert!(loaded[0].enabled && loaded[0].approved);
}

// a failing enforcement backend must not kill the pipeline —
// the monitor keeps running and the next tick retries the diff.
#[tokio::test]
async fn test_enforcement_failure_does_not_stop_the_pipeline() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
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
        dummy_store(),
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

    // RAT_DRY_RUN makes apply() a no-op printer, so the backend diff and
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

// the Windows backend must enforce the denied sockets' LOCAL
// ports (the port axis, macOS Ledger.swift:330 parity) instead of silently
// dropping them — and a refused shared host's denied socket port must still
// land as a per-port rule ("block by port instead" must not be a no-op).
#[cfg(windows)]
#[test]
fn test_windows_backend_enforces_denied_local_ports() {
    use rat_enforcer::Blocklist;

    std::env::set_var("RAT_DRY_RUN", "1");
    let mut backend = rat_daemon::core::WindowsBackend::new();

    let wanted = Blocklist {
        paths: vec![],
        local_ports: vec![5300],
    };
    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(
        outcome.applied,
        "a denied local port must be enforced, not dropped: {outcome:?}"
    );

    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(!outcome.applied, "unchanged port set must not re-apply");

    // A port that dropped out (socket closed) is part of the
    // next diff, like on the Linux backend.
    let outcome = backend
        .enforce(&Blocklist {
            paths: vec![],
            local_ports: vec![],
        })
        .expect("dry-run enforce");
    assert!(outcome.applied, "port removal re-applies the ruleset");
}

// ONE invalid path (a `"` cannot occur in a real Windows
// filename) must not fail the whole enforce — the backend reports it in
// `outcome.rejected`, skips it, and applies the rest. The skipped entry
// must also not churn the diff: the next tick with the same wanted state is
// a no-op (applied == false) that still reports the rejection.
#[cfg(windows)]
#[test]
fn test_windows_backend_reports_rejected_path_and_enforces_rest() {
    use rat_enforcer::Blocklist;

    std::env::set_var("RAT_DRY_RUN", "1");
    let mut backend = rat_daemon::core::WindowsBackend::new();

    let good = r"C:\evil\app.exe";
    let bad = r#"C:\Users\bad"; app.exe"#;
    let wanted = Blocklist {
        paths: vec![good.to_string(), bad.to_string()],
        local_ports: vec![],
    };
    let outcome = backend
        .enforce(&wanted)
        .expect("one invalid path must not fail the whole enforce");
    assert!(
        outcome.applied,
        "the valid path is still enforced: {outcome:?}"
    );
    assert!(
        outcome.rejected.contains(&bad.to_string()),
        "the invalid path is reported: {outcome:?}"
    );
    assert!(outcome.refused.is_empty());

    // Already-effective state is a no-op (the rejected entry stays in the
    // report but never causes perpetual re-apply churn).
    let outcome = backend.enforce(&wanted).expect("dry-run enforce");
    assert!(!outcome.applied, "unchanged state must not re-apply");
    assert!(
        outcome.rejected.contains(&bad.to_string()),
        "the rejection stays reported on later ticks: {outcome:?}"
    );
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

    // A port that dropped out (socket closed) is part of the
    // next diff.
    let outcome = backend
        .enforce(&Blocklist {
            paths: vec![],
            local_ports: vec![],
        })
        .expect("dry-run enforce");
    assert!(outcome.applied, "port removal re-applies the ruleset");
}

/// Wait for the next broadcast that `pick` accepts.
async fn wait_for_msg<T>(
    rx: &mut tokio::sync::broadcast::Receiver<ServerMessage>,
    mut pick: impl FnMut(ServerMessage) -> Option<T>,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "expected message never arrived");
        let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no broadcast at all")
            .expect("broadcast channel closed");
        if let Some(v) = pick(msg) {
            return v;
        }
    }
}

// GetRules is answered from the pipeline's in-memory rule set: empty at
// start, and the exact set after SetRules (ids included), never from a file.
#[tokio::test]
async fn test_get_rules_answers_the_current_in_memory_set() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut rx) = tokio::sync::broadcast::channel(64);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        ScriptedSource { conns: vec![] },
        policy,
        ledger,
        RecorderBackend::default(),
        None::<Arc<RuleStore>>,
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    cmd_tx.send(Command::GetRules).await.unwrap();
    let first = wait_for_msg(&mut rx, |m| match m {
        ServerMessage::Rules { rules } => Some(rules),
        _ => None,
    })
    .await;
    assert!(first.is_empty());

    let rule = deny_rule(app);
    cmd_tx
        .send(Command::SetRules {
            rules: vec![rule.clone()],
        })
        .await
        .unwrap();
    cmd_tx.send(Command::GetRules).await.unwrap();
    let second = wait_for_msg(&mut rx, |m| match m {
        ServerMessage::Rules { rules } => Some(rules),
        _ => None,
    })
    .await;
    assert_eq!(second, vec![rule]);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

// A3: AddRule/RemoveRule edit the set INCREMENTALLY — the rules around an
// edit keep their place (the pre-fix client move was a whole-list SetRules
// per edit) — and the edited set persists like SetRules. A stale RemoveRule
// id is ignored without touching the set.
#[tokio::test]
async fn test_add_and_remove_rule_edit_the_set_incrementally_and_persist() {
    let app = test_app();
    let added_path = if cfg!(windows) {
        r"C:\added\tool.exe"
    } else {
        "/usr/bin/added"
    };
    let store = dummy_store();
    let store_path = store.url.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut rx) = tokio::sync::broadcast::channel(64);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);

    let keep = deny_rule(app);
    let added = deny_rule(added_path);

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let recorder = RecorderBackend::default();
    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        ScriptedSource { conns: vec![] },
        policy,
        ledger,
        recorder.clone(),
        store,
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    async fn rules_now(rx: &mut tokio::sync::broadcast::Receiver<ServerMessage>) -> Vec<Rule> {
        wait_for_msg(rx, |m| match m {
            ServerMessage::Rules { rules } => Some(rules),
            _ => None,
        })
        .await
    }

    cmd_tx
        .send(Command::SetRules {
            rules: vec![keep.clone()],
        })
        .await
        .unwrap();
    cmd_tx.send(Command::GetRules).await.unwrap();
    let first = rules_now(&mut rx).await;
    assert_eq!(first, vec![keep.clone()], "seed via SetRules");

    // The incremental add keeps the seeded rule and lands its own.
    cmd_tx
        .send(Command::AddRule {
            rule: Box::new(added.clone()),
        })
        .await
        .unwrap();
    cmd_tx.send(Command::GetRules).await.unwrap();
    let second = rules_now(&mut rx).await;
    assert_eq!(
        second,
        vec![keep.clone(), added.clone()],
        "AddRule must edit the list, not replace it"
    );
    // The added unscoped deny is enforced as part of the static anchor
    // without waiting for a connection sample.
    wait_until(Duration::from_secs(5), || {
        recorder
            .last_enforced()
            .is_some_and(|b| b.paths.iter().any(|p| p == added_path))
    })
    .await;

    // Remove one rule: only that rule goes.
    cmd_tx
        .send(Command::RemoveRule { id: keep.id })
        .await
        .unwrap();
    cmd_tx.send(Command::GetRules).await.unwrap();
    let third = rules_now(&mut rx).await;
    assert_eq!(
        third,
        vec![added.clone()],
        "RemoveRule takes exactly one rule"
    );

    // A stale id changes nothing (and must not wedge the pipeline).
    cmd_tx
        .send(Command::RemoveRule { id: Uuid::new_v4() })
        .await
        .unwrap();
    cmd_tx.send(Command::GetRules).await.unwrap();
    let fourth = rules_now(&mut rx).await;
    assert_eq!(
        fourth,
        vec![added.clone()],
        "stale RemoveRule id is a no-op"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();

    // Persisted like SetRules: exactly the surviving rule is on disk.
    let loaded = RuleStore::new(store_path).load().expect("rules were saved");
    assert_eq!(loaded, vec![added], "exactly the surviving rule persists");
}

// The daemon tells clients when the alert it asked about is gone, so the app
// can keep a local alert until the daemon confirms it was handled.
#[tokio::test]
async fn test_alert_cleared_is_sent_after_the_answer() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, mut rx) = tokio::sync::broadcast::channel(64);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        ScriptedSource {
            conns: vec![conn(app, "evil", 443, 54321)],
        },
        policy,
        ledger,
        RecorderBackend::default(),
        dummy_store(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    let id = wait_for_msg(&mut rx, |m| match m {
        ServerMessage::AlertRequest { id, .. } => Some(id),
        _ => None,
    })
    .await;
    cmd_tx
        .send(Command::AlertAnswer {
            id,
            verdict: Verdict::Deny,
            scope: rat_ledger::AnswerScope::Any,
            lifetime: Lifetime::Forever,
        })
        .await
        .unwrap();
    let cleared = wait_for_msg(&mut rx, |m| match m {
        ServerMessage::AlertCleared { id } => Some(id),
        _ => None,
    })
    .await;
    assert_eq!(cleared, id);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

// A burst of SetRules already queued when the pipeline first polls the
// command channel must coalesce to the NEWEST list: the intermediate lists
// are stale before they could ever run, so only the newest one may reach
// the backend (each SetRules would otherwise cost a full enforce round).
// The burst is queued BEFORE the pipeline task exists, so its first poll
// provably sees all three commands at once - deterministic, no blocking.
#[tokio::test]
async fn test_set_rules_burst_coalesces_to_newest_list() {
    let (a, b, c) = ("/burst/a", "/burst/b", "/burst/c");
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, _snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
    let recorder = RecorderBackend::default();

    cmd_tx
        .send(Command::SetRules {
            rules: vec![deny_rule(a)],
        })
        .await
        .expect("command channel open");
    cmd_tx
        .send(Command::SetRules {
            rules: vec![deny_rule(b)],
        })
        .await
        .expect("command channel open");
    cmd_tx
        .send(Command::SetRules {
            rules: vec![deny_rule(c)],
        })
        .await
        .expect("command channel open");

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        ScriptedSource { conns: vec![] },
        policy,
        ledger,
        recorder.clone(),
        dummy_store(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    // On BOTH the old and the fixed pipeline the newest list ends up
    // enforced; the assertion below is what tells them apart.
    wait_until(Duration::from_secs(5), || {
        recorder
            .last_enforced()
            .is_some_and(|e| e.paths == vec![c.to_string()])
    })
    .await;

    let enforced: Vec<Vec<String>> = recorder
        .events_snapshot()
        .iter()
        .filter_map(|e| match e {
            Event::Enforce(b) => Some(b.paths.clone()),
            Event::Adopt(_) | Event::Cleanup => None,
        })
        .collect();
    assert!(
        enforced
            .iter()
            .all(|p| p.is_empty() || p == &vec![c.to_string()]),
        "intermediate rule lists must never be enforced, saw {enforced:?}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

/// A source whose every sample fails (a monitor that cannot read the table).
struct FailingSource;

impl ConnectionSource for FailingSource {
    fn sample(&mut self) -> io::Result<Vec<Connection>> {
        Err(io::Error::other("injected sample failure"))
    }
}

// B7: static rules need no connection sample, so they are enforced at
// start-up even when the very first sample fails (pre-fix the failed sample
// skipped the whole round and nothing was enforced until a sample worked).
#[tokio::test]
async fn test_static_rules_enforced_even_if_first_sample_fails() {
    let app = test_app();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, _snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);
    let recorder = RecorderBackend::default();

    let engine = rat_core::RuleEngine::new();
    engine.set_rules(vec![deny_rule(app)]);
    let ledger = Ledger::new(LedgerConfig { warmup_ms: 0 }, AlertCenterConfig::default());
    let task = tokio::spawn(rat_daemon::core::run_pipeline(
        FailingSource,
        RuleEnginePolicy(engine),
        ledger,
        recorder.clone(),
        dummy_store(),
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));

    wait_until(Duration::from_secs(5), || {
        recorder
            .last_enforced()
            .is_some_and(|b| b.paths.iter().any(|p| p == app))
    })
    .await;

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("pipeline must end on shutdown")
        .unwrap();
}

// B8: a save that crashed between write and rename leaves its own temp file
// (`<rules file>.<32 hex>.tmp`) next to the rules. Start-up removes exactly
// that, and nothing else in the directory.
#[tokio::test]
async fn test_startup_removes_only_the_daemons_own_leftover_temp_files() {
    let dir = std::env::temp_dir().join(format!(
        "rat_daemon_test_stray_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let rules_path = dir.join("rules.json");
    let stray = dir.join(format!("rules.json.{}.tmp", "ab12".repeat(8)));
    let foreign = [
        dir.join("rules.json.tmp"),
        dir.join("unrelated.tmp"),
        dir.join("notes.txt"),
    ];
    std::fs::write(&stray, b"half-written").unwrap();
    for f in &foreign {
        std::fs::write(f, b"not ours").unwrap();
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let endpoint = test_endpoint("stray_tmp");
    let task = tokio::spawn(rat_daemon::run_components(
        endpoint.clone(),
        ScriptedSource { conns: vec![] },
        RecorderBackend::default(),
        rules_path,
        shutdown_rx,
    ));
    wait_until(Duration::from_secs(10), || endpoint_serving(&endpoint)).await;

    assert!(!stray.exists(), "the daemon's own leftover temp is removed");
    for f in &foreign {
        assert!(
            f.exists(),
            "{} is not the daemon's and must stay",
            f.display()
        );
    }

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run_components must end on shutdown")
        .expect("pipeline task did not panic")
        .expect("clean shutdown is not an error");
    let _ = std::fs::remove_dir_all(&dir);
}
