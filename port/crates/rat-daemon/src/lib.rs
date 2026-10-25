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

/// Runs the core sampling loop and the platform IPC server until `shutdown_rx` fires.
pub async fn run_daemon(shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);

    let source = FakeSource;

    let shutdown_core = shutdown_rx.resubscribe();
    let shutdown_ipc = shutdown_rx.resubscribe();

    let core_task = tokio::spawn(async move {
        run_core_loop(source, snapshot_tx, shutdown_core).await;
    });

    let ipc_task = tokio::spawn(async move {
        #[cfg(unix)]
        let _ = start_ipc_server(ipc::SOCKET_PATH, shutdown_ipc, snapshot_rx).await;
        #[cfg(windows)]
        let _ = start_ipc_server(ipc::PIPE_NAME, shutdown_ipc, snapshot_rx).await;
    });

    let _ = tokio::join!(core_task, ipc_task);
}
