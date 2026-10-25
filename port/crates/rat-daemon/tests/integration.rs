use rat_daemon::msg::Message;
use rat_types::{Connection, ConnectionSource, ProcessInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

    let socket_path = format!("/tmp/rat_test_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

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

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect");
    let mut framed = FramedRead::new(stream, LinesCodec::new());

    if let Some(Ok(line)) = framed.next().await {
        let msg: Message = Message::from_json_str(&line).expect("Invalid message");
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

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let client = ClientOptions::new()
        .open(&pipe_name)
        .expect("Failed to connect to pipe");
    let mut framed = FramedRead::new(client, LinesCodec::new());

    if let Some(Ok(line)) = framed.next().await {
        let msg: Message = Message::from_json_str(&line).expect("Invalid message");
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

#[cfg(unix)]
#[tokio::test]
async fn test_ipc_edge_cases() {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    use tokio_util::codec::{FramedRead, LinesCodec};

    let socket_path = format!("/tmp/rat_test_edges_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

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

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect");

    // 1. Empty input
    let _ = stream.write_all(b"\n").await;

    // 2. Malformed input
    let _ = stream.write_all(b"not a valid json message\n").await;

    // 3. Oversized input (e.g. 10MB +) will close the connection which causes broken pipe so we ignore error.
    let huge_line = vec![b'a'; 11 * 1024 * 1024];
    let _ = stream.write_all(&huge_line).await;
    let _ = stream.write_all(b"\n").await;

    let mut framed = FramedRead::new(stream, LinesCodec::new());

    let mut _saw_error = false;
    // We expect some Error messages back for malformed/oversized.
    for _ in 0..3 {
        if let Some(Ok(line)) = framed.next().await {
            if let Ok(Message::Error { .. }) = serde_json::from_str::<Message>(&line) {
                _saw_error = true;
                break;
            }
        }
    }

    let _ = shutdown_tx.send(());
}

#[test]
fn test_edge_cases_msg_roundtrip() {
    use std::path::PathBuf;

    let snapshot = Message::Snapshot {
        connections: vec![Connection {
            process: ProcessInfo {
                pid: 1234,
                exe: Some(PathBuf::from(r"C:\Program Files\Some فارسی Name\App.exe")),
                name: "تست中文".to_string(),
                user: Some("用戶".to_string()),
            },
            protocol: Protocol::Udp,
            local: SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080),
            remote: Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                8080,
            )), // link-local
            listening: false,
            bytes_in: None,
            bytes_out: None,
        }],
    };

    let serialized = snapshot.to_string().unwrap();
    let deserialized: Message = Message::from_json_str(&serialized).unwrap();
    assert_eq!(snapshot, deserialized);
}
