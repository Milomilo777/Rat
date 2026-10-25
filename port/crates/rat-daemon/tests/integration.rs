use rat_daemon::msg::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use rat_types::{Connection, ProcessInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

fn sample_connection() -> Connection {
    Connection {
        process: ProcessInfo {
            pid: 1234,
            exe: Some(PathBuf::from(r"C:\Program Files\Some فارسی Name\App.exe")),
            name: "تست中文".to_string(),
            user: None,
        },
        protocol: Protocol::Tcp,
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        remote: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            443,
        )),
        listening: false,
        bytes_in: Some(100),
        bytes_out: Some(200),
        via_vpn: false,
    }
}

// ---------------------------------------------------------------- helpers

async fn spawn_server(
    test: &str,
) -> (
    String,
    tokio::sync::broadcast::Sender<ServerMessage>,
    tokio::sync::broadcast::Sender<()>,
) {
    // Commands are dropped here: most IPC scenarios never set rules.
    let (endpoint, snapshot_tx, shutdown_tx, _cmd_rx) = spawn_server_with_commands(test).await;
    (endpoint, snapshot_tx, shutdown_tx)
}

async fn spawn_server_with_commands(
    test: &str,
) -> (
    String,
    tokio::sync::broadcast::Sender<ServerMessage>,
    tokio::sync::broadcast::Sender<()>,
    tokio::sync::mpsc::Receiver<rat_daemon::core::Command>,
) {
    spawn_server_with_write_timeout(test, rat_daemon::ipc::CLIENT_WRITE_TIMEOUT).await
}

async fn spawn_server_with_write_timeout(
    test: &str,
    write_timeout: Duration,
) -> (
    String,
    tokio::sync::broadcast::Sender<ServerMessage>,
    tokio::sync::broadcast::Sender<()>,
    tokio::sync::mpsc::Receiver<rat_daemon::core::Command>,
) {
    #[cfg(unix)]
    let endpoint = format!("/tmp/rat_it_{test}_{}.sock", std::process::id());
    #[cfg(windows)]
    let endpoint = format!(r"\\.\pipe\rat_it_{test}_{}", std::process::id());

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);

    let ep = endpoint.clone();
    tokio::spawn(async move {
        let _ = rat_daemon::ipc::start_ipc_server_with_write_timeout(
            &ep,
            shutdown_rx,
            snapshot_rx,
            cmd_tx,
            write_timeout,
        )
        .await;
    });

    #[cfg(unix)]
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !std::path::Path::new(&endpoint).exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            std::path::Path::new(&endpoint).exists(),
            "server never bound {endpoint}"
        );
    }
    #[cfg(windows)]
    {
        // Probe with a throwaway client: its handler occupies one of the four
        // handshake slots for its (unused) 10s window.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(&endpoint) {
                Ok(probe) => {
                    drop(probe);
                    break;
                }
                Err(_) => {
                    assert!(Instant::now() < deadline, "server never created {endpoint}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    (endpoint, snapshot_tx, shutdown_tx, cmd_rx)
}

#[cfg(unix)]
async fn connect_ep(path: &str) -> tokio::net::UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(s) => return s,
            Err(_) => {
                assert!(Instant::now() < deadline, "server at {path} never came up");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

#[cfg(windows)]
async fn connect_ep(pipe: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe) {
            Ok(c) => return c,
            Err(_) => {
                assert!(Instant::now() < deadline, "pipe {pipe} never came up");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn send_client<S>(writer: &mut FramedWrite<S, LinesCodec>, msg: &ClientMessage)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use futures::SinkExt;
    writer
        .send(msg.to_string().expect("test message serializes"))
        .await
        .expect("write to server");
}

async fn read_server<S>(
    reader: &mut FramedRead<S, LinesCodec>,
    timeout: Duration,
) -> Option<ServerMessage>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use futures::StreamExt;
    match tokio::time::timeout(timeout, reader.next()).await {
        Ok(Some(Ok(line))) => {
            Some(ServerMessage::from_json_str(&line).expect("server sent a non-ServerMessage line"))
        }
        Ok(Some(Err(e))) => panic!("codec error reading server: {e}"),
        Ok(None) => None,
        Err(_) => panic!("timed out reading a server message"),
    }
}

const READ_TIMEOUT: Duration = Duration::from_secs(5);

// ------------------------------------------------------------ scenarios

// Hello{PROTOCOL_VERSION} is answered with HelloAck; a repeat
// Hello gets an error but keeps the connection.
async fn scenario_hello_ack<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());

    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    let ack = read_server(&mut reader, READ_TIMEOUT)
        .await
        .expect("HelloAck");
    assert_eq!(
        ack,
        ServerMessage::HelloAck {
            protocol_version: PROTOCOL_VERSION
        }
    );

    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    let again = read_server(&mut reader, READ_TIMEOUT).await.expect("reply");
    assert!(
        matches!(again, ServerMessage::Error { .. }),
        "a repeat Hello must be answered with an error: {again:?}"
    );
}

// a mismatched version is answered with Error and closed.
async fn scenario_version_mismatch<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());

    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION + 1,
        },
    )
    .await;
    let reply = read_server(&mut reader, READ_TIMEOUT)
        .await
        .expect("Error reply");
    match reply {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("unsupported protocol version"),
                "the error must name the version problem: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(
        read_server(&mut reader, READ_TIMEOUT).await.is_none(),
        "the connection must close after a version mismatch"
    );
}

// any other opener is rejected — the first message must be
// Hello, and SetRules before it is dropped on the floor.
async fn scenario_first_message_must_be_hello<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());

    send_client(&mut writer, &ClientMessage::SetRules { rules: vec![] }).await;
    let reply = read_server(&mut reader, READ_TIMEOUT)
        .await
        .expect("Error reply");
    match reply {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("first message must be Hello"),
                "the error must name the handshake requirement: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(
        read_server(&mut reader, READ_TIMEOUT).await.is_none(),
        "the connection must close when the handshake is skipped"
    );
}

// A client that never sends Hello receives nothing (no
// ServerMessage flows before the handshake completes).
async fn scenario_unhandshaked_gets_nothing<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures::StreamExt;
    let (r, _w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let got = tokio::time::timeout(Duration::from_millis(700), reader.next()).await;
    assert!(
        got.is_err(),
        "an unhandshaked client must not receive anything"
    );
}

// Malformed and oversized input before the handshake: answered with Error,
// then closed.
async fn scenario_bad_input<S>(stream: S, payload: &[u8], needle: &str)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let _ = w.write_all(payload).await;
    let _ = w.write_all(b"\n").await;

    let deadline = Instant::now() + READ_TIMEOUT;
    let mut saw_error = false;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), reader.next()).await {
            Ok(Some(Ok(line))) => {
                if line.contains(needle) {
                    saw_error = true;
                    break;
                }
            }
            Ok(Some(Err(e))) => {
                if format!("{e}").contains(needle) {
                    saw_error = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    assert!(saw_error, "expected a reply containing {needle:?}");
}

// ------------------------------------------------------------ tests

// GetRules crosses the IPC layer as a pipeline command, and the Rules reply
// the pipeline broadcasts reaches the handshaked client.
#[tokio::test]
async fn test_get_rules_is_forwarded_and_the_reply_delivered() {
    let (endpoint, snapshot_tx, shutdown_tx, mut cmd_rx) =
        spawn_server_with_commands("get_rules").await;
    let (r, w) = tokio::io::split(connect_ep(&endpoint).await);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());
    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    assert!(matches!(
        read_server(&mut reader, READ_TIMEOUT).await,
        Some(ServerMessage::HelloAck { .. })
    ));

    send_client(&mut writer, &ClientMessage::GetRules).await;
    let cmd = tokio::time::timeout(READ_TIMEOUT, cmd_rx.recv())
        .await
        .expect("no command forwarded")
        .expect("command channel closed");
    assert_eq!(cmd, rat_daemon::core::Command::GetRules);

    let _ = snapshot_tx.send(ServerMessage::Rules { rules: vec![] });
    assert_eq!(
        read_server(&mut reader, READ_TIMEOUT).await,
        Some(ServerMessage::Rules { rules: vec![] })
    );
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_hello_ack() {
    let (endpoint, _snapshot_tx, shutdown_tx) = spawn_server("hello_ack").await;
    scenario_hello_ack(connect_ep(&endpoint).await).await;
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_version_mismatch_is_refused_and_closed() {
    let (endpoint, _snapshot_tx, shutdown_tx) = spawn_server("version_mismatch").await;
    scenario_version_mismatch(connect_ep(&endpoint).await).await;
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_first_message_must_be_hello() {
    let (endpoint, _snapshot_tx, shutdown_tx) = spawn_server("hello_first").await;
    scenario_first_message_must_be_hello(connect_ep(&endpoint).await).await;
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_unhandshaked_client_gets_nothing() {
    let (endpoint, snapshot_tx, shutdown_tx) = spawn_server("no_hello_no_data").await;
    let stream = connect_ep(&endpoint).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = snapshot_tx.send(ServerMessage::Snapshot {
        connections: vec![sample_connection()],
    });
    scenario_unhandshaked_gets_nothing(stream).await;
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_empty_line_before_handshake_rejected() {
    let (endpoint, _snapshot_tx, shutdown_tx) = spawn_server("empty_line").await;
    scenario_bad_input(connect_ep(&endpoint).await, b"", "Invalid JSON").await;
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_garbage_before_handshake_rejected() {
    let (endpoint, _snapshot_tx, shutdown_tx) = spawn_server("garbage").await;
    scenario_bad_input(
        connect_ep(&endpoint).await,
        b"not a valid json message",
        "Invalid JSON",
    )
    .await;
    let _ = shutdown_tx.send(());
}

// The snapshot must reach a handshaked client over a REAL socket/pipe,
// produced by the same core loop the daemon runs (run_pipeline).
#[cfg(unix)]
#[tokio::test]
async fn test_ipc_snapshot() {
    let socket_path = format!("/tmp/rat_it_snapshot_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);
    run_snapshot_pipeline(&socket_path).await;
}

#[cfg(windows)]
#[tokio::test]
async fn test_ipc_snapshot() {
    let pipe_name = format!(r"\\.\pipe\rat_it_snapshot_{}", std::process::id());
    run_snapshot_pipeline(&pipe_name).await;
}

async fn run_snapshot_pipeline(endpoint: &str) {
    use tokio_util::codec::LinesCodec;

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY);

    let source = MockSource;
    let policy = rat_ledger::RuleEnginePolicy(rat_core::RuleEngine::new());
    let ledger = rat_ledger::Ledger::new(Default::default(), Default::default());
    let backend = NoopBackend;
    let store = std::sync::Arc::new(rat_core::RuleStore::new(std::env::temp_dir().join(
        format!("rat_it_snapshot_{}_{}.json", std::process::id(), line!()),
    )));

    let _core_task = tokio::spawn(rat_daemon::core::run_pipeline(
        source,
        policy,
        ledger,
        backend,
        store,
        cmd_rx,
        snapshot_tx,
        shutdown_rx,
    ));
    let shutdown_for_ipc = shutdown_tx.clone();
    let ep = endpoint.to_string();
    let _ipc_task = tokio::spawn(async move {
        let _ = rat_daemon::ipc::start_ipc_server(
            &ep,
            shutdown_for_ipc.subscribe(),
            snapshot_rx,
            cmd_tx,
        )
        .await;
    });

    // Wait for the server endpoint, then handshake.
    #[cfg(unix)]
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !std::path::Path::new(endpoint).exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let stream = connect_ep(endpoint).await;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());

    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    let ack = read_server(&mut reader, READ_TIMEOUT)
        .await
        .expect("HelloAck");
    assert!(matches!(ack, ServerMessage::HelloAck { .. }));

    // The pipeline's Snapshot (from MockSource, pid 1234) arrives on its own.
    use futures::StreamExt;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got = None;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), reader.next()).await {
            Ok(Some(Ok(line))) => {
                if let Ok(ServerMessage::Snapshot { connections }) =
                    ServerMessage::from_json_str(&line)
                {
                    got = Some(connections);
                    break;
                }
            }
            Ok(Some(Err(e))) => panic!("codec error: {e}"),
            Ok(None) => panic!("connection closed before a snapshot arrived"),
            Err(_) => {}
        }
    }
    let connections = got.expect("no snapshot arrived");
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].process.pid, 1234);

    let _ = shutdown_tx.send(());
}

struct MockSource;

impl rat_types::ConnectionSource for MockSource {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
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
            via_vpn: false,
        }])
    }
}

struct NoopBackend;

impl rat_daemon::core::EnforcementBackend for NoopBackend {
    fn cleanup(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn existing(&self) -> std::io::Result<rat_enforcer::Blocklist> {
        Ok(rat_enforcer::Blocklist::default())
    }

    fn adopt(&mut self, _existing: rat_enforcer::Blocklist) {}

    fn enforce(
        &mut self,
        _wanted: &rat_enforcer::Blocklist,
    ) -> std::io::Result<rat_daemon::core::EnforceOutcome> {
        Ok(rat_daemon::core::EnforceOutcome::default())
    }
}

#[test]
fn test_edge_cases_msg_roundtrip() {
    let snapshot = ServerMessage::Snapshot {
        connections: vec![Connection {
            process: ProcessInfo {
                pid: 4321,
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
            via_vpn: false,
        }],
    };

    let serialized = snapshot.to_string().unwrap();
    let deserialized: ServerMessage = ServerMessage::from_json_str(&serialized).unwrap();
    assert_eq!(snapshot, deserialized);
}

#[cfg(unix)]
fn is_socket(p: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(p)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

// a second daemon must refuse to start while another daemon's
// socket is live, instead of removing it and binding its own.
#[cfg(unix)]
#[tokio::test]
async fn test_second_daemon_cannot_steal_live_socket() {
    let socket_path = format!("/tmp/rat_it_steal_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let cmd_tx = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0;

    let sp = socket_path.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(&sp, shutdown_rx_ipc, snapshot_rx, cmd_tx).await
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_socket(&socket_path) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        is_socket(&socket_path),
        "first daemon never bound its socket"
    );

    let second = tokio::time::timeout(
        Duration::from_secs(10),
        rat_daemon::ipc::start_ipc_server(
            &socket_path,
            shutdown_tx.subscribe(),
            snapshot_tx.subscribe(),
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        ),
    )
    .await
    .expect("second start_ipc_server did not return");
    let err = second.expect_err("second daemon must be refused on a live socket");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);

    // the refused instance must not have removed the live daemon's socket
    assert!(is_socket(&socket_path));

    shutdown_tx.send(()).expect("shutdown send");
    ipc_task
        .await
        .expect("ipc task join")
        .expect("first daemon clean shutdown");
    assert!(
        !std::path::Path::new(&socket_path).exists(),
        "socket must be cleaned up on shutdown"
    );
}

// a socket file left behind by a crashed daemon is not live,
// so a new daemon must still be able to reclaim it.
#[cfg(unix)]
#[tokio::test]
async fn test_stale_socket_from_crashed_daemon_is_reclaimed() {
    let socket_path = format!("/tmp/rat_it_stale_{}.sock", std::process::id());
    std::fs::write(&socket_path, b"leftover from a crashed daemon").unwrap();

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    // Hold a sender: with every sender dropped the handlers' snapshot_rx
    // reports Closed and they would exit immediately (the daemon always
    // keeps the core loop's sender alive).
    let (_snapshot_tx_keepalive, snapshot_rx) = tokio::sync::broadcast::channel(16);

    let sp = socket_path.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(
            &sp,
            shutdown_rx_ipc,
            snapshot_rx,
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        )
        .await
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_socket(&socket_path) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        is_socket(&socket_path),
        "stale file should have been replaced by a bound socket"
    );

    shutdown_tx.send(()).expect("shutdown send");
    ipc_task
        .await
        .expect("ipc task join")
        .expect("daemon must reclaim a stale socket");
    assert!(
        !std::path::Path::new(&socket_path).exists(),
        "socket must be cleaned up on shutdown"
    );
}

// named-pipe side: first_pipe_instance(true) must make a second
// daemon fail while the first one owns the pipe.
#[cfg(windows)]
#[tokio::test]
async fn test_second_daemon_cannot_steal_live_pipe() {
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_name = format!(r"\\.\pipe\rat_it_steal_{}", std::process::id());

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let cmd_tx = tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0;

    let pn = pipe_name.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(&pn, shutdown_rx_ipc, snapshot_rx, cmd_tx).await
    });

    // Wait until the first daemon has a live pipe instance, then let it
    // recreate its next instance; otherwise the "second" daemon would race
    // the first into creating the pipe at all.
    let mut ready = false;
    for _ in 0..100 {
        match ClientOptions::new().open(&pipe_name) {
            Ok(client) => {
                drop(client);
                ready = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert!(ready, "first daemon never created its pipe");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let second = tokio::time::timeout(
        Duration::from_secs(5),
        rat_daemon::ipc::start_ipc_server(
            &pipe_name,
            shutdown_tx.subscribe(),
            snapshot_tx.subscribe(),
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        ),
    )
    .await
    .expect("second start_ipc_server did not return");
    let err = second.expect_err("second daemon must be refused while the pipe is live");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // the live daemon must still accept a client afterwards
    let client = ClientOptions::new()
        .open(&pipe_name)
        .expect("first daemon still owns the pipe");
    drop(client);

    shutdown_tx.send(()).expect("shutdown send");
    ipc_task
        .await
        .expect("ipc task join")
        .expect("first daemon clean shutdown");
}

// an inbound line over the 64 KiB cap must be rejected with
// an error reply and the connection closed.
#[cfg(unix)]
#[tokio::test]
async fn test_oversized_client_line_is_rejected_and_closed() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let socket_path = format!("/tmp/rat_it_oversize_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    // Hold a sender: with every sender dropped the handlers' snapshot_rx
    // reports Closed and they would exit immediately (the daemon always
    // keeps the core loop's sender alive).
    let (_snapshot_tx_keepalive, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let sp = socket_path.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(
            &sp,
            shutdown_rx_ipc,
            snapshot_rx,
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        )
        .await
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_socket(&socket_path) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(is_socket(&socket_path), "daemon never bound its socket");

    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
    // The server may close the connection while the oversized line is still
    // being written - a failed write here is part of the expected rejection.
    let big = vec![b'a'; 200 * 1024];
    let _ = stream.write_all(&big).await;
    let _ = stream.write_all(b"\n").await;

    let mut framed = FramedRead::new(stream, LinesCodec::new());
    let saw_error = tokio::time::timeout(Duration::from_secs(5), async {
        use futures::StreamExt;
        while let Some(Ok(line)) = framed.next().await {
            assert!(
                line.contains("LinesCodec error") || line.contains("Invalid JSON"),
                "unexpected non-error reply: {line}"
            );
            if line.contains("LinesCodec error") {
                return true;
            }
        }
        false
    })
    .await
    .expect("connection must close promptly");
    assert!(saw_error, "expected a LinesCodec error reply");

    shutdown_tx.send(()).unwrap();
    ipc_task.await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn test_oversized_client_line_is_rejected_and_closed() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_name = format!(r"\\.\pipe\rat_it_oversize_{}", std::process::id());
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    // Hold a sender: with every sender dropped the handlers' snapshot_rx
    // reports Closed and they would exit immediately (the daemon always
    // keeps the core loop's sender alive).
    let (_snapshot_tx_keepalive, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let pn = pipe_name.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(
            &pn,
            shutdown_rx_ipc,
            snapshot_rx,
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        )
        .await
    });

    let mut client = None;
    for _ in 0..100 {
        match ClientOptions::new().open(&pipe_name) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let mut client = client.expect("pipe never came up");

    // The server may close the pipe while the oversized line is still being
    // written - a failed write here is part of the expected rejection.
    let big = vec![b'a'; 200 * 1024];
    let _ = client.write_all(&big).await;
    let _ = client.write_all(b"\n").await;

    let mut framed = FramedRead::new(client, LinesCodec::new());
    let mut received: Vec<String> = Vec::new();
    let saw_error = tokio::time::timeout(Duration::from_secs(5), async {
        use futures::StreamExt;
        while let Some(Ok(line)) = framed.next().await {
            received.push(line.clone());
            if line.contains("LinesCodec error") {
                return true;
            }
        }
        false
    })
    .await
    .expect("connection must close promptly");
    assert!(
        saw_error,
        "expected a LinesCodec error reply, got {received:?}"
    );

    shutdown_tx.send(()).unwrap();
    ipc_task.await.unwrap().unwrap();
}

// the 5th concurrent client must be refused (connection
// closed without service) while the first four stay connected.
#[cfg(unix)]
#[tokio::test]
async fn test_fifth_concurrent_client_is_refused() {
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;

    let socket_path = format!("/tmp/rat_it_cap_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    // Hold a sender: with every sender dropped the handlers' snapshot_rx
    // reports Closed and they would exit immediately (the daemon always
    // keeps the core loop's sender alive).
    let (_snapshot_tx_keepalive, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let sp = socket_path.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(
            &sp,
            shutdown_rx_ipc,
            snapshot_rx,
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        )
        .await
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_socket(&socket_path) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(is_socket(&socket_path), "daemon never bound its socket");

    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            UnixStream::connect(&socket_path)
                .await
                .expect("held client"),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut fifth = UnixStream::connect(&socket_path)
        .await
        .expect("5th connect");
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), fifth.read(&mut buf))
        .await
        .expect("5th client must not hang");
    match read {
        Ok(0) => {}
        Ok(n) => panic!("5th client received {n} bytes instead of refusal"),
        Err(_) => {}
    }
    drop(fifth);
    drop(held);

    shutdown_tx.send(()).unwrap();
    ipc_task.await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn test_fifth_concurrent_client_is_refused() {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_name = format!(r"\\.\pipe\rat_it_cap_{}", std::process::id());
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    // Hold a sender: with every sender dropped the handlers' snapshot_rx
    // reports Closed and they would exit immediately (the daemon always
    // keeps the core loop's sender alive).
    let (_snapshot_tx_keepalive, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let pn = pipe_name.clone();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(
            &pn,
            shutdown_rx_ipc,
            snapshot_rx,
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        )
        .await
    });

    let mut held = Vec::new();
    for _ in 0..4 {
        let mut client = None;
        for _ in 0..100 {
            match ClientOptions::new().open(&pipe_name) {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        held.push(client.expect("held client"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut fifth = None;
    for _ in 0..100 {
        match ClientOptions::new().open(&pipe_name) {
            Ok(c) => {
                fifth = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let mut fifth = fifth.expect("5th client connect");
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), fifth.read(&mut buf))
        .await
        .expect("5th client must not hang");
    match read {
        Ok(0) => {}
        Ok(n) => panic!("5th client received {n} bytes instead of refusal"),
        Err(_) => {}
    }
    drop(fifth);
    drop(held);

    shutdown_tx.send(()).unwrap();
    ipc_task.await.unwrap().unwrap();
}

// the socket is always 0o660 and a directory the daemon
// created is 0o750, so others cannot reach the socket during the
// bind->chmod window (runs on CI linux).
#[cfg(unix)]
#[tokio::test]
async fn test_socket_and_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!("rat_it_perms_{}", std::process::id()));
    let socket_path = base.join("sub").join("rat.sock");

    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    let (_snapshot_tx_keepalive, snapshot_rx) = tokio::sync::broadcast::channel(16);
    let sp = socket_path.to_string_lossy().into_owned();
    let shutdown_rx_ipc = shutdown_tx.subscribe();
    let ipc_task = tokio::spawn(async move {
        rat_daemon::ipc::start_ipc_server(
            &sp,
            shutdown_rx_ipc,
            snapshot_rx,
            tokio::sync::mpsc::channel(rat_daemon::ipc::COMMAND_QUEUE_CAPACITY).0,
        )
        .await
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_socket(&socket_path.to_string_lossy()) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        is_socket(&socket_path.to_string_lossy()),
        "daemon never bound its socket"
    );

    let sock_mode = std::fs::metadata(&socket_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o660, "socket must be 0o660, got {sock_mode:o}");
    let dir_mode = std::fs::metadata(socket_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode, 0o750,
        "created dir must be 0o750, got {dir_mode:o}"
    );

    shutdown_tx.send(()).unwrap();
    ipc_task.await.unwrap().unwrap();
}

// A client that floods SetRules must get a clear Error reply once the
// daemon's command queue is full — never a hang, never a silent unbounded
// backlog. The test holds the queue's receiver unconsumed, so the queue
// provably fills no matter how fast the daemon would drain it.
#[tokio::test]
async fn test_set_rules_flood_gets_error_reply_not_a_hang() {
    let (endpoint, _snapshot_tx, shutdown_tx, _cmd_rx) = spawn_server_with_commands("flood").await;
    let (r, w) = tokio::io::split(connect_ep(&endpoint).await);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());

    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    assert!(matches!(
        read_server(&mut reader, READ_TIMEOUT).await,
        Some(ServerMessage::HelloAck { .. })
    ));

    // Well past any sane queue bound.
    for _ in 0..64 {
        send_client(&mut writer, &ClientMessage::SetRules { rules: vec![] }).await;
    }

    let reply = read_server(&mut reader, READ_TIMEOUT)
        .await
        .expect("a full command queue must produce an error reply, not silence");
    match reply {
        ServerMessage::Error { message } => assert!(
            message.contains("command queue full"),
            "the error must name the full queue: {message}"
        ),
        other => panic!("expected Error, got {other:?}"),
    }
    let _ = shutdown_tx.send(());
}

// A client that stops reading its replies must not hold one of the four
// client slots for ever: the server gives each write a timeout, drops the
// client (with a log line) and the slot comes back. Four clients handshake and
// then never read; a flood of large broadcasts blocks every handler's write;
// after the (shortened) timeout a fifth client must get its handshake, and the
// stalled clients must see their connection end.
#[tokio::test]
async fn test_client_that_never_reads_is_dropped_and_frees_its_slot() {
    use futures::StreamExt;

    let (endpoint, snapshot_tx, shutdown_tx, _cmd_rx) =
        spawn_server_with_write_timeout("neverreads", Duration::from_millis(500)).await;

    let mut stalled = Vec::new();
    for _ in 0..4 {
        let stream = connect_ep(&endpoint).await;
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, LinesCodec::new());
        let mut writer = FramedWrite::new(w, LinesCodec::new());
        send_client(
            &mut writer,
            &ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .await;
        match read_server(&mut reader, READ_TIMEOUT).await {
            Some(ServerMessage::HelloAck { .. }) => {}
            other => panic!("expected HelloAck, got {other:?}"),
        }
        stalled.push((reader, writer));
    }

    // 3 MiB per message: far beyond any socket / pipe buffer, so the write of
    // the first one cannot finish while nobody reads.
    for _ in 0..4 {
        let _ = snapshot_tx.send(ServerMessage::Error {
            message: "x".repeat(3 * 1024 * 1024),
        });
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The slots are free again: a fifth client gets its handshake.
    let stream = connect_ep(&endpoint).await;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, LinesCodec::new());
    let mut writer = FramedWrite::new(w, LinesCodec::new());
    send_client(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    match read_server(&mut reader, READ_TIMEOUT).await {
        Some(ServerMessage::HelloAck { .. }) => {}
        other => panic!("a fifth client must get a slot once stalled ones are dropped: {other:?}"),
    }

    // And a stalled client's connection really ended (EOF or error after the
    // data that was already in flight).
    let (first_reader, _first_writer) = &mut stalled[0];
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match first_reader.next().await {
                Some(Ok(_)) => continue,
                _ => return,
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the stalled client was never disconnected");

    let _ = shutdown_tx.send(());
}
