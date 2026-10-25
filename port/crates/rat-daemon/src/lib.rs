pub mod core;
pub mod ipc;
pub mod msg;
pub mod service;

pub use crate::core::{run_pipeline, Command, EnforceOutcome, EnforcementBackend};
pub use crate::ipc::start_ipc_server;

use rat_ledger::{AlertCenterConfig, Ledger, LedgerConfig, RuleEnginePolicy};
use rat_types::ConnectionSource;

/// The daemon shell (PROPOSALS #10): startup cleanup (#8), then the pipeline
/// (monitor -> ledger -> policy -> enforcer) and the IPC server until
/// `shutdown_rx` fires. Returns an error when the IPC endpoint cannot be
/// claimed — e.g. a second daemon finds the socket/pipe already owned by a
/// live one (PROPOSALS #9) — so the caller can exit instead of running
/// headless. `endpoint`/`source`/`backend` are parameters so tests inject a
/// fake source and a recorder backend; [`run_daemon`] holds the production
/// wiring.
pub async fn run_components(
    endpoint: String,
    source: impl ConnectionSource + Send + 'static,
    backend: impl EnforcementBackend + 'static,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> std::io::Result<()> {
    // #8 obligation: remove the rules a crashed predecessor left behind
    // BEFORE the first apply, so startup never duplicates or trusts stale
    // state. Best-effort: a failure here (no admin yet, nft absent) must not
    // keep the monitor from running — systemd/SCM Restart=on-failure covers
    // repeated failures, and the first apply retries the same diff.
    if let Err(e) = backend.cleanup() {
        eprintln!("rat-daemon: startup cleanup failed: {e}");
    }

    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();

    let policy = RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = Ledger::new(LedgerConfig::default(), AlertCenterConfig::default());

    let shutdown_core = shutdown_rx.resubscribe();
    let shutdown_ipc = shutdown_rx.resubscribe();
    let mut shutdown_wait = shutdown_rx.resubscribe();

    let mut core_task = tokio::spawn(run_pipeline(
        source,
        policy,
        ledger,
        backend,
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
    // S9 (update-08): if EITHER task ends on its own the daemon shuts down
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

    match failure {
        Some(e) => {
            core_task.abort();
            ipc_task.abort();
            Err(e)
        }
        None => {
            let _ = ipc_task.await;
            let _ = core_task.await;
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
        run_components(ipc::PIPE_NAME.to_string(), source, backend, shutdown_rx).await
    }
    #[cfg(not(windows))]
    {
        let source = rat_monitor_linux::LinuxMonitor::new(std::path::PathBuf::from("/proc"));
        let backend = core::LinuxBackend::new();
        run_components(ipc::SOCKET_PATH.to_string(), source, backend, shutdown_rx).await
    }
}

/// #8 obligation, uninstall path: remove every rule this daemon created and
/// exit. Wired to `rat-daemon --cleanup` in main.rs.
pub fn run_cleanup() -> std::io::Result<()> {
    #[cfg(windows)]
    let backend = core::WindowsBackend::new();
    #[cfg(not(windows))]
    let backend = core::LinuxBackend::new();
    backend.cleanup()
}
