pub mod core;
pub mod ipc;
pub mod msg;
pub mod service;

pub use crate::core::run_core_loop;
pub use crate::ipc::start_ipc_server;

use rat_types::{Connection, ConnectionSource};

/// Placeholder source until the monitor crates are wired in; samples nothing.
struct FakeSource;
impl ConnectionSource for FakeSource {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
        Ok(vec![])
    }
}

/// Runs the core sampling loop and the platform IPC server until `shutdown_rx`
/// fires. Returns an error when the IPC endpoint cannot be claimed — e.g. a
/// second daemon finds the socket/pipe already owned by a live one
/// (PROPOSALS #9) — so the caller can exit instead of running headless.
pub async fn run_daemon(shutdown_rx: tokio::sync::broadcast::Receiver<()>) -> std::io::Result<()> {
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);

    let source = FakeSource;

    let shutdown_core = shutdown_rx.resubscribe();
    let shutdown_ipc = shutdown_rx.resubscribe();
    let mut shutdown_wait = shutdown_rx.resubscribe();

    let mut core_task = tokio::spawn(async move {
        run_core_loop(source, snapshot_tx, shutdown_core).await;
    });

    #[cfg(unix)]
    let ipc_endpoint = ipc::SOCKET_PATH;
    #[cfg(windows)]
    let ipc_endpoint = ipc::PIPE_NAME;
    let mut ipc_task =
        tokio::spawn(
            async move { start_ipc_server(ipc_endpoint, shutdown_ipc, snapshot_rx).await },
        );

    // recv() also resolves (with Err) when every sender is dropped; treat
    // that as shutdown like an explicit signal.
    //
    // S9 (update-08): if EITHER task ends on its own the daemon shuts down
    // and exits non-zero, so systemd/SCM Restart=on-failure brings it back
    // instead of serving a half-dead process. run_core_loop only returns on
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
            Err(_) => Some(std::io::Error::other("core sampling loop exited unexpectedly")),
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
