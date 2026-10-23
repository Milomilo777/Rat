use rat_daemon::msg::Message;
use rat_types::{Connection, ConnectionSource, ProcessInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

struct MockSource {
    invocations: usize,
}

impl ConnectionSource for MockSource {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
        self.invocations += 1;
        Ok(vec![Connection {
            process: ProcessInfo {
                pid: 1234,
                exe: None,
                name: "test".to_string(),
                user: None,
            },
            protocol: Protocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            remote: None,
            listening: true,
            bytes_in: Some(100),
            bytes_out: Some(200),
        }])
    }
}

#[cfg(unix)]
#[tokio::test]
async fn test_ipc_snapshot() {
    use futures::StreamExt;
    use tokio::net::UnixStream;
    use tokio_util::codec::{FramedRead, LinesCodec};

    // We will use a unique socket path for tests so we don't need root to write to /run
    let socket_path = format!("/tmp/rat_test_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path); // Cleanup

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);

    let shutdown_rx_core = shutdown_tx.subscribe();
    let shutdown_rx_ipc = shutdown_tx.subscribe();

    let source = MockSource { invocations: 0 };
    let snapshot_tx_clone = snapshot_tx.clone();

    let _core_task = tokio::spawn(async move {
        rat_daemon::core::run_core_loop(source, snapshot_tx_clone, shutdown_rx_core).await;
    });

    let sp_clone = socket_path.clone();
    let _ipc_task = tokio::spawn(async move {
        let _ = rat_daemon::ipc::start_ipc_server(&sp_clone, shutdown_rx_ipc, snapshot_rx).await;
    });

    // Wait for socket to be created
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect");
    let mut framed = FramedRead::new(stream, LinesCodec::new());

    // We should receive snapshots every 1.5 seconds.
    // Wait for the first one.
    if let Some(Ok(line)) = framed.next().await {
        let msg: Message = serde_json::from_str(&line).expect("Invalid message");
        if let Message::Snapshot { connections } = msg {
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].process.pid, 1234);
        } else {
            panic!("Expected Snapshot");
        }
    } else {
        panic!("Did not receive a message");
    }

    let _ = shutdown_tx.send(());
}

#[cfg(windows)]
#[tokio::test]
async fn test_ipc_snapshot() {
    use futures::StreamExt;
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio_util::codec::{FramedRead, LinesCodec};

    // Use a unique pipe name for the test
    let pipe_name = format!(r"\\.\pipe\rat_test_{}", std::process::id());

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);

    let shutdown_rx_core = shutdown_tx.subscribe();
    let shutdown_rx_ipc = shutdown_tx.subscribe();

    let source = MockSource { invocations: 0 };
    let snapshot_tx_clone = snapshot_tx.clone();

    let _core_task = tokio::spawn(async move {
        rat_daemon::core::run_core_loop(source, snapshot_tx_clone, shutdown_rx_core).await;
    });

    let pn_clone = pipe_name.clone();
    let _ipc_task = tokio::spawn(async move {
        let _ = rat_daemon::ipc::start_ipc_server(&pn_clone, shutdown_rx_ipc, snapshot_rx).await;
    });

    // Wait for server to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let client = ClientOptions::new()
        .open(&pipe_name)
        .expect("Failed to connect to pipe");
    let mut framed = FramedRead::new(client, LinesCodec::new());

    if let Some(Ok(line)) = framed.next().await {
        let msg: Message = serde_json::from_str(&line).expect("Invalid message");
        if let Message::Snapshot { connections } = msg {
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].process.pid, 1234);
        } else {
            panic!("Expected Snapshot");
        }
    } else {
        panic!("Did not receive a message");
    }

    let _ = shutdown_tx.send(());
}
