pub mod core;
pub mod fw_status;
pub mod ipc;
pub mod msg;
pub mod rules_dir;
pub mod service;

pub use crate::core::{run_pipeline, Command, EnforceOutcome, EnforcementBackend};
pub use crate::ipc::start_ipc_server;

use rat_ledger::{AlertCenterConfig, Ledger, LedgerConfig, RuleEnginePolicy};
use rat_types::ConnectionSource;

/// The daemon shell: startup cleanup (#8), then the pipeline
/// (monitor -> ledger -> policy -> enforcer) and the IPC server until
/// `shutdown_rx` fires. Returns an error when the IPC endpoint cannot be
/// claimed — e.g. a second daemon finds the socket/pipe already owned by a
/// live one — so the caller can exit instead of running
/// headless. `endpoint`/`source`/`backend` are parameters so tests inject a
/// fake source and a recorder backend; [`run_daemon`] holds the production
/// wiring.
pub async fn run_components(
    endpoint: String,
    source: impl ConnectionSource + Send + 'static,
    backend: impl EnforcementBackend + 'static,
    rules_path: std::path::PathBuf,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> std::io::Result<()> {
    run_components_trusted(endpoint, source, backend, rules_path, true, shutdown_rx).await
}

/// [`run_components`] with the rules-directory trust verdict. `rules_trusted
/// == false` (Windows: the directory is a junction or not owned by
/// SYSTEM/Administrators) means: never read, never write the directory, start
/// with an empty in-memory set and skip the startup reconcile, so no firewall
/// rule is removed on the strength of an untrusted file.
pub async fn run_components_trusted(
    endpoint: String,
    source: impl ConnectionSource + Send + 'static,
    mut backend: impl EnforcementBackend + 'static,
    rules_path: std::path::PathBuf,
    rules_trusted: bool,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> std::io::Result<()> {
    let store = rules_trusted.then(|| std::sync::Arc::new(rat_core::RuleStore::new(rules_path)));
    // The saved plan (Swift RulesModel parity): rules survive restarts and
    // are the anchor the reconcile below diffs against. an
    // unparsable rules file is an ERROR (load_set never yields a zero-rule
    // set) — starting from an empty plan would reconcile every real Rat:*
    // rule away (fail-open). Without a recovered plan the startup reconcile
    // is SKIPPED: the firewall keeps exactly what the predecessor left until
    // a client sends rules. The backend is deliberately never seeded with
    // the live state in this mode, so its diff can only add, never remove;
    // the cost is that stray rules the later plan no longer names stay until
    // the uninstall cleanup.
    // A crash between the atomic save's write and rename leaves its own
    // temp file next to the rules; drop those (only that exact naming).
    if let Some(s) = &store {
        match s.remove_stale_temp_files() {
            Ok(gone) => {
                for p in gone {
                    eprintln!("rat-daemon: removed leftover temp file {}", p.display());
                }
            }
            Err(e) => eprintln!("rat-daemon: cleaning leftover temp files failed: {e}"),
        }
    }
    let loaded_set = match &store {
        Some(s) => s.load_set(),
        None => Err(std::io::Error::other("rules directory is not trusted")),
    };
    let (engine, loaded, plan_loaded) = match loaded_set {
        Ok(set) => {
            let count = set.rules.len();
            (rat_core::RuleEngine::with_rule_set(set), count, true)
        }
        Err(e) => {
            eprintln!(
                "rat-daemon: rules file unreadable ({e}); keeping the current firewall state until a client sends rules"
            );
            (rat_core::RuleEngine::new(), 0, false)
        }
    };
    let policy = RuleEnginePolicy(engine);

    // RECONCILE, never wipe-then-apply. A cleanup() here would drop wanted
    // rules and leave a fail-open window until the first re-add. Instead:
    // read back what is really in the firewall, adopt it as the backend's
    // view of current state, then make the saved plan's anchor effective —
    // the backend's diff removes only the stale extras and adds what is
    // missing; a wanted rule is never deleted. Foreign rules are never
    // touched: existing() lists only this daemon's own prefixed rules. All
    // of this happens BEFORE the IPC endpoint is created below, so no
    // client is ever served against unrepaired state. Failures are
    // best-effort: a daemon that cannot read the firewall still serves, and
    // the pipeline's first tick re-attempts the diff.
    if plan_loaded {
        match backend.existing() {
            Ok(found) => backend.adopt(found),
            Err(e) => {
                eprintln!(
                    "rat-daemon: firewall read-back failed ({e}); reconciling from an empty view"
                )
            }
        }
        let anchor = core::static_blocklist(&policy.0.rule_set());
        if let Err(e) = backend.enforce(&anchor) {
            eprintln!("rat-daemon: startup reconcile enforce failed: {e} (first tick retries)");
        }
        eprintln!("rat-daemon: {loaded} rules loaded, startup reconcile done");
    } else {
        eprintln!(
            "rat-daemon: no saved plan recovered; startup reconcile skipped (firewall state kept)"
        );
    }

    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);
    // BOUNDED on purpose (back pressure): a flooding client is told the
    // queue is full instead of building an unbounded backlog, and the
    // pipeline coalesces queued SetRules to the newest list.
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(crate::ipc::COMMAND_QUEUE_CAPACITY);

    let ledger = Ledger::new(LedgerConfig::default(), AlertCenterConfig::default());

    let shutdown_core = shutdown_rx.resubscribe();
    let shutdown_ipc = shutdown_rx.resubscribe();
    let mut shutdown_wait = shutdown_rx.resubscribe();

    // Silent-disable warning (Windows, production only): read-only watcher.
    #[cfg(windows)]
    let fw_task = fw_status::watch_enabled()
        .then(|| fw_status::spawn_watch(snapshot_tx.clone(), shutdown_rx.resubscribe()));

    let mut core_task = tokio::spawn(run_pipeline(
        source,
        policy,
        ledger,
        backend,
        store,
        command_rx,
        snapshot_tx.clone(),
        shutdown_core,
    ));

    let mut ipc_task = tokio::spawn(async move {
        start_ipc_server(&endpoint, shutdown_ipc, snapshot_rx, command_tx).await
    });

    // recv() also resolves (with Err) when every sender is dropped; treat
    // that as shutdown like an explicit signal.
    //
    // if EITHER task ends on its own the daemon shuts down
    // and exits non-zero, so systemd/SCM Restart=on-failure brings it back
    // instead of serving a half-dead process. run_pipeline only returns on
    // shutdown, so a core exit without a pending signal is the failure.
    let failure = tokio::select! {
        _ = shutdown_wait.recv() => None,
        res = &mut ipc_task => match res {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(e) => Some(std::io::Error::other(e)),
        },
        _ = &mut core_task => match shutdown_wait.try_recv() {
            Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => None,
            Err(_) => Some(std::io::Error::other("core pipeline exited unexpectedly")),
        },
    };

    #[cfg(windows)]
    if let Some(task) = &fw_task {
        task.abort();
    }

    match failure {
        Some(e) => {
            core_task.abort();
            ipc_task.abort();
            Err(e)
        }
        None => {
            // The select above may have exited through one of the task arms,
            // in which case that JoinHandle's output is already consumed and
            // re-polling it panics ("JoinHandle polled after completion",
            // reproduced 2026-10-25 with the multi-thread reconcile test).
            // Reap only a task that has not finished; a finished one whose
            // output the select took is left to the runtime reaper, and a
            // finished one the select never got to has no one waiting on it.
            if !ipc_task.is_finished() {
                let _ = ipc_task.await;
            }
            if !core_task.is_finished() {
                let _ = core_task.await;
            }
            Ok(())
        }
    }
}

/// Production wiring: the platform monitor, the platform enforcement backend
/// and the production IPC endpoint.
pub async fn run_daemon(shutdown_rx: tokio::sync::broadcast::Receiver<()>) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let source = rat_monitor_windows::WindowsMonitor::new();
        let backend = core::WindowsBackend::new();
        let rules_path = default_rules_path();
        fw_status::enable_watch();
        // RAT_RULES_FILE is an explicit admin/test override; only the
        // built-in ProgramData location needs the trust gate.
        let trusted = std::env::var_os("RAT_RULES_FILE").is_some()
            || rules_dir::ensure_rules_dir(&rules_path);
        run_components_trusted(
            ipc::PIPE_NAME.to_string(),
            source,
            backend,
            rules_path,
            trusted,
            shutdown_rx,
        )
        .await
    }
    #[cfg(not(windows))]
    {
        let source = rat_monitor_linux::LinuxMonitor::new(std::path::PathBuf::from("/proc"));
        let backend = core::LinuxBackend::new();
        run_components(
            ipc::SOCKET_PATH.to_string(),
            source,
            backend,
            default_rules_path(),
            shutdown_rx,
        )
        .await
    }
}

/// Where the daemon persists its rule set (Swift RulesModel parity: the rules
/// survive a restart and are the saved plan the startup reconcile diffs
/// against). `RAT_RULES_FILE` overrides for tests and non-service installs;
/// the service runs as SYSTEM, so the machine-wide ProgramData / etc location
/// is the right home — per-user state would be invisible to it.
pub fn default_rules_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os("RAT_RULES_FILE") {
        return std::path::PathBuf::from(p);
    }
    if cfg!(windows) {
        let program_data = std::env::var_os("ProgramData")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
        program_data.join("rat").join("rules.json")
    } else {
        std::path::PathBuf::from("/etc/rat/rules.json")
    }
}

/// #8 obligation, uninstall path: remove every rule this daemon created and
/// exit. Wired to `rat-daemon --cleanup` in main.rs.
pub fn run_cleanup() -> std::io::Result<()> {
    #[cfg(windows)]
    let mut backend = core::WindowsBackend::new();
    #[cfg(not(windows))]
    let mut backend = core::LinuxBackend::new();
    backend.cleanup()
}
