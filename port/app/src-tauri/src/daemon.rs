//! Client for the privileged Rat daemon (IPC protocol v1).
//!
//! Wire format: newline-delimited JSON, the first client message must be
//! `Hello`, the daemon answers `HelloAck`, then streams `Snapshot` and
//! `AlertRequest` messages. The message types come from the `rat-daemon`
//! crate so this client cannot drift from the server.
//!
//! The session logic is generic over any async byte stream, so it is tested
//! against an in-memory fake daemon; only `connect()` touches the OS.

use rat_daemon::msg::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use rat_ledger::Alert;
use rat_types::Connection;
use serde::Serialize;
use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

use futures::{SinkExt, StreamExt};

/// Same ceilings as the daemon (ipc.rs): requests are small, snapshots may
/// be large.
const MAX_CLIENT_LINE: usize = 64 * 1024;
const MAX_SERVER_LINE: usize = 10 * 1024 * 1024;
/// The daemon gives up on a client that does not say Hello within 10 s.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the app is (not) connected. Serialized as `snake_case` code for the UI.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Connecting,
    Connected,
    /// Pipe / socket does not exist: the service is not running.
    NotRunning,
    /// The OS refused the connection, or the daemon closed it before the
    /// handshake (it does that for clients that are not an elevated admin /
    /// root / `rat` group member, and when 4 clients are already attached).
    AccessDenied,
    /// The daemon answered the Hello with an Error (other protocol version).
    ProtocolMismatch,
    Failed,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    pub code: ConnState,
    pub detail: Option<String>,
    /// True when the app runs on fake demo data (`RAT_DEMO=1`).
    pub demo: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct PendingAlert {
    pub id: u64,
    pub alert: Alert,
}

/// Events the session reports to the shell (opening the alert window).
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Alert(u64),
}

struct Inner {
    state: ConnState,
    detail: Option<String>,
    connections: Vec<Connection>,
    alert: Option<PendingAlert>,
}

/// Latest daemon state, shared between the background task and the commands.
pub struct Shared {
    inner: Mutex<Inner>,
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

impl Shared {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: ConnState::Connecting,
                detail: None,
                connections: Vec::new(),
                alert: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means another thread panicked mid-update of
        // plain data; the data is still usable.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn status(&self) -> DaemonStatus {
        let g = self.lock();
        DaemonStatus {
            code: g.state,
            detail: g.detail.clone(),
            demo: false,
        }
    }

    pub fn connections(&self) -> Vec<Connection> {
        self.lock().connections.clone()
    }

    pub fn alert(&self) -> Option<PendingAlert> {
        self.lock().alert.clone()
    }

    pub fn clear_alert(&self, id: u64) {
        let mut g = self.lock();
        if g.alert.as_ref().is_some_and(|a| a.id == id) {
            g.alert = None;
        }
    }

    fn set_state(&self, state: ConnState, detail: Option<String>) {
        let mut g = self.lock();
        g.state = state;
        g.detail = detail;
        if state != ConnState::Connected {
            // Stale data would look like live data: drop it.
            g.connections.clear();
            g.alert = None;
        }
    }

    fn set_connections(&self, connections: Vec<Connection>) {
        self.lock().connections = connections;
    }

    fn set_alert(&self, alert: PendingAlert) {
        self.lock().alert = Some(alert);
    }

    fn set_detail(&self, detail: String) {
        self.lock().detail = Some(detail);
    }

    #[cfg(test)]
    pub fn mark_connected_for_test(&self) {
        self.set_state(ConnState::Connected, None);
    }

    #[cfg(test)]
    pub fn set_alert_for_test(&self, id: u64) {
        use rat_ledger::ConnectionDetails;
        use rat_types::Protocol;
        self.set_alert(PendingAlert {
            id,
            alert: Alert {
                app: "/a".to_string(),
                app_name: "a".to_string(),
                host: "203.0.113.9".to_string(),
                remote: "203.0.113.9:443".parse().unwrap(),
                proto: Protocol::Tcp,
                details: ConnectionDetails::default(),
                reported_ms: 0,
            },
        });
    }
}

/// Map a failed connect to the state the UI explains.
pub fn classify_connect_error(err: &io::Error) -> (ConnState, String) {
    let detail = err.to_string();
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            (ConnState::NotRunning, detail)
        }
        io::ErrorKind::PermissionDenied => (ConnState::AccessDenied, detail),
        // ERROR_PIPE_BUSY (231): all pipe instances are in use right now.
        // The daemon is there; the retry loop will get a free instance.
        _ if err.raw_os_error() == Some(231) => (ConnState::Connecting, detail),
        _ => (ConnState::Failed, detail),
    }
}

/// Reconnect delay: doubles from 500 ms up to 5 s, resets after a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    current: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    const START: Duration = Duration::from_millis(500);
    const MAX: Duration = Duration::from_secs(5);

    pub fn new() -> Self {
        Self {
            current: Self::START,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let d = self.current;
        self.current = (self.current * 2).min(Self::MAX);
        d
    }

    pub fn reset(&mut self) {
        self.current = Self::START;
    }
}

/// How one session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// Handshake never completed (state already set by the session).
    Handshake,
    /// Was connected; the daemon went away or the stream failed.
    Dropped,
    /// The command channel is gone: the app is shutting down.
    Shutdown,
}

async fn send<W>(writer: &mut FramedWrite<W, LinesCodec>, msg: &ClientMessage) -> Result<(), String>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let line = msg.to_string().map_err(|e| e.to_string())?;
    writer.send(line).await.map_err(|e| e.to_string())
}

/// Run one connected session on `stream` until it ends.
pub async fn run_session<S>(
    stream: S,
    shared: &Shared,
    cmds: &mut UnboundedReceiver<ClientMessage>,
    events: &UnboundedSender<Event>,
) -> SessionEnd
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Commands queued while we were not connected are stale.
    while cmds.try_recv().is_ok() {}

    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(MAX_SERVER_LINE));
    let mut writer = FramedWrite::new(write_half, LinesCodec::new_with_max_length(MAX_CLIENT_LINE));

    let hello = ClientMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
    };
    if let Err(e) = send(&mut writer, &hello).await {
        // The pipe / socket opened but the daemon already hung up (its client
        // check refused us): the same situation as a close before HelloAck.
        shared.set_state(ConnState::AccessDenied, Some(e));
        return SessionEnd::Handshake;
    }

    // Handshake: only HelloAck is acceptable as the first answer.
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.next()).await {
        Ok(Some(Ok(line))) => match ServerMessage::from_json_str(&line) {
            Ok(ServerMessage::HelloAck { protocol_version })
                if protocol_version == PROTOCOL_VERSION =>
            {
                shared.set_state(ConnState::Connected, None);
            }
            Ok(ServerMessage::Error { message }) => {
                shared.set_state(ConnState::ProtocolMismatch, Some(message));
                return SessionEnd::Handshake;
            }
            _ => {
                shared.set_state(
                    ConnState::ProtocolMismatch,
                    Some("unexpected answer to Hello".to_string()),
                );
                return SessionEnd::Handshake;
            }
        },
        // Closed without an answer: the daemon's client check said no.
        Ok(None) | Ok(Some(Err(_))) => {
            shared.set_state(
                ConnState::AccessDenied,
                Some("the daemon closed the connection before the handshake".to_string()),
            );
            return SessionEnd::Handshake;
        }
        Err(_) => {
            shared.set_state(ConnState::Failed, Some("handshake timed out".to_string()));
            return SessionEnd::Handshake;
        }
    }

    loop {
        tokio::select! {
            line = reader.next() => {
                match line {
                    Some(Ok(line)) => handle_server_line(&line, shared, events),
                    // EOF or a broken / oversized line: drop the session.
                    Some(Err(_)) | None => return SessionEnd::Dropped,
                }
            }
            cmd = cmds.recv() => {
                match cmd {
                    Some(msg) => {
                        if send(&mut writer, &msg).await.is_err() {
                            return SessionEnd::Dropped;
                        }
                    }
                    None => return SessionEnd::Shutdown,
                }
            }
        }
    }
}

/// Apply one daemon line to the shared state. Unparsable lines are ignored:
/// one bad message must not end a working session.
pub fn handle_server_line(line: &str, shared: &Shared, events: &UnboundedSender<Event>) {
    match ServerMessage::from_json_str(line) {
        Ok(ServerMessage::Snapshot { connections }) => shared.set_connections(connections),
        Ok(ServerMessage::AlertRequest { id, alert }) => {
            shared.set_alert(PendingAlert { id, alert: *alert });
            let _ = events.send(Event::Alert(id));
        }
        Ok(ServerMessage::Error { message }) => shared.set_detail(message),
        Ok(ServerMessage::HelloAck { .. }) | Err(_) => {}
    }
}

/// Connect, run sessions and reconnect with backoff, forever (until the
/// command channel closes). `connect` is the OS-specific opener.
pub async fn run_client<C, Fut, S>(
    connect: C,
    shared: &Shared,
    cmds: &mut UnboundedReceiver<ClientMessage>,
    events: &UnboundedSender<Event>,
) where
    C: Fn() -> Fut,
    Fut: Future<Output = io::Result<S>>,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut backoff = Backoff::new();
    loop {
        match connect().await {
            Ok(stream) => {
                let end = run_session(stream, shared, cmds, events).await;
                match end {
                    SessionEnd::Shutdown => return,
                    SessionEnd::Dropped => {
                        backoff.reset();
                        shared.set_state(ConnState::Connecting, None);
                    }
                    SessionEnd::Handshake => {}
                }
            }
            Err(e) => {
                let (state, detail) = classify_connect_error(&e);
                shared.set_state(state, Some(detail));
            }
        }
        tokio::time::sleep(backoff.next_delay()).await;
    }
}

/// Where the daemon listens. `RAT_IPC_ENDPOINT` overrides it (tests and
/// non-standard installs).
pub fn endpoint() -> String {
    if let Some(p) = std::env::var_os("RAT_IPC_ENDPOINT") {
        return p.to_string_lossy().into_owned();
    }
    #[cfg(windows)]
    {
        rat_daemon::ipc::PIPE_NAME.to_string()
    }
    #[cfg(not(windows))]
    {
        rat_daemon::ipc::SOCKET_PATH.to_string()
    }
}

#[cfg(windows)]
pub async fn connect(
    endpoint: &str,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint)
}

#[cfg(not(windows))]
pub async fn connect(endpoint: &str) -> io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(endpoint).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rat_core::{Lifetime, Verdict};
    use rat_ledger::{AnswerScope, ConnectionDetails};
    use rat_types::{ProcessInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn conn(pid: u32) -> Connection {
        Connection {
            process: ProcessInfo {
                pid,
                exe: Some(PathBuf::from(r"C:\Program Files\App\app.exe")),
                name: "app".to_string(),
                user: None,
            },
            protocol: Protocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
            remote: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                443,
            )),
            listening: false,
            bytes_in: Some(1),
            bytes_out: Some(2),
            via_vpn: false,
        }
    }

    fn alert() -> Alert {
        Alert {
            app: r"C:\Program Files\App\app.exe".to_string(),
            app_name: "app".to_string(),
            host: "203.0.113.9".to_string(),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443),
            proto: Protocol::Tcp,
            details: ConnectionDetails::default(),
            reported_ms: 1,
        }
    }

    async fn write_server<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, m: &ServerMessage) {
        let mut line = m.to_string().unwrap();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();
    }

    /// Wait (bounded) until `f` is true.
    async fn wait_for(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn handshake_snapshot_alert_and_commands() {
        let (client_io, daemon_io) = tokio::io::duplex(1 << 16);
        let shared = std::sync::Arc::new(Shared::new());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel();

        let s2 = shared.clone();
        let session =
            tokio::spawn(async move { run_session(client_io, &s2, &mut cmd_rx, &ev_tx).await });

        let (dr, mut dw) = tokio::io::split(daemon_io);
        let mut dr = BufReader::new(dr).lines();

        // The first thing the client sends is exactly the documented Hello.
        let first = dr.next_line().await.unwrap().unwrap();
        assert_eq!(first, r#"{"Hello":{"protocol_version":1}}"#);
        write_server(
            &mut dw,
            &ServerMessage::HelloAck {
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .await;
        wait_for(|| shared.status().code == ConnState::Connected).await;

        write_server(
            &mut dw,
            &ServerMessage::Snapshot {
                connections: vec![conn(1), conn(2)],
            },
        )
        .await;
        wait_for(|| shared.connections().len() == 2).await;

        write_server(
            &mut dw,
            &ServerMessage::AlertRequest {
                id: 9,
                alert: Box::new(alert()),
            },
        )
        .await;
        assert_eq!(ev_rx.recv().await, Some(Event::Alert(9)));
        assert_eq!(shared.alert().unwrap().id, 9);

        // Commands are written as the daemon's own ClientMessage.
        cmd_tx
            .send(ClientMessage::AlertAnswer {
                id: 9,
                verdict: Verdict::Deny,
                scope: AnswerScope::Host,
                lifetime: Lifetime::Forever,
            })
            .unwrap();
        let line = dr.next_line().await.unwrap().unwrap();
        assert_eq!(
            ClientMessage::from_json_str(&line).unwrap(),
            ClientMessage::AlertAnswer {
                id: 9,
                verdict: Verdict::Deny,
                scope: AnswerScope::Host,
                lifetime: Lifetime::Forever,
            }
        );

        // Daemon goes away: session ends as Dropped.
        drop(dw);
        drop(dr);
        assert_eq!(session.await.unwrap(), SessionEnd::Dropped);
    }

    #[tokio::test]
    async fn closed_before_ack_is_access_denied() {
        let (client_io, daemon_io) = tokio::io::duplex(1 << 12);
        let shared = Shared::new();
        let (_cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ev_tx, _ev_rx) = tokio::sync::mpsc::unbounded_channel();
        drop(daemon_io); // the daemon's client check hung up
        let end = run_session(client_io, &shared, &mut cmd_rx, &ev_tx).await;
        assert_eq!(end, SessionEnd::Handshake);
        assert_eq!(shared.status().code, ConnState::AccessDenied);
    }

    #[tokio::test]
    async fn error_answer_is_protocol_mismatch() {
        let (client_io, daemon_io) = tokio::io::duplex(1 << 12);
        let shared = Shared::new();
        let (_cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ev_tx, _ev_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_dr, mut dw) = tokio::io::split(daemon_io);
        write_server(
            &mut dw,
            &ServerMessage::Error {
                message: "unsupported protocol version 1; this server speaks 2".to_string(),
            },
        )
        .await;
        let end = run_session(client_io, &shared, &mut cmd_rx, &ev_tx).await;
        assert_eq!(end, SessionEnd::Handshake);
        let st = shared.status();
        assert_eq!(st.code, ConnState::ProtocolMismatch);
        assert!(st.detail.unwrap().contains("speaks 2"));
    }

    #[tokio::test]
    async fn disconnect_clears_stale_connections() {
        let shared = Shared::new();
        shared.set_state(ConnState::Connected, None);
        shared.set_connections(vec![conn(1)]);
        shared.set_alert(PendingAlert {
            id: 1,
            alert: alert(),
        });
        shared.set_state(ConnState::Connecting, None);
        assert!(shared.connections().is_empty());
        assert!(shared.alert().is_none());
    }

    #[test]
    fn bad_server_line_is_ignored() {
        let shared = Shared::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        shared.set_state(ConnState::Connected, None);
        handle_server_line("not json", &shared, &tx);
        handle_server_line(r#"{"Hello":{"protocol_version":1}}"#, &shared, &tx);
        assert_eq!(shared.status().code, ConnState::Connected);
    }

    #[test]
    fn clear_alert_only_matches_its_id() {
        let shared = Shared::new();
        shared.set_alert(PendingAlert {
            id: 5,
            alert: alert(),
        });
        shared.clear_alert(4);
        assert!(shared.alert().is_some());
        shared.clear_alert(5);
        assert!(shared.alert().is_none());
    }

    #[test]
    fn connect_errors_are_classified() {
        let nf = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(classify_connect_error(&nf).0, ConnState::NotRunning);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_connect_error(&refused).0, ConnState::NotRunning);
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(classify_connect_error(&denied).0, ConnState::AccessDenied);
        let busy = io::Error::from_raw_os_error(231);
        assert_eq!(classify_connect_error(&busy).0, ConnState::Connecting);
        let other = io::Error::other("boom");
        assert_eq!(classify_connect_error(&other).0, ConnState::Failed);
    }

    #[test]
    fn backoff_doubles_caps_and_resets() {
        let mut b = Backoff::new();
        let seq: Vec<u64> = (0..6).map(|_| b.next_delay().as_millis() as u64).collect();
        assert_eq!(seq, vec![500, 1000, 2000, 4000, 5000, 5000]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn client_reconnects_after_failures_and_stops_on_shutdown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        tokio::time::pause();
        let attempts = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Shared::new());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<ClientMessage>();
        let (ev_tx, _ev_rx) = tokio::sync::mpsc::unbounded_channel();

        let a = attempts.clone();
        let s = shared.clone();
        let task = tokio::spawn(async move {
            run_client(
                || {
                    a.fetch_add(1, Ordering::SeqCst);
                    async {
                        Err::<tokio::io::DuplexStream, _>(io::Error::from(io::ErrorKind::NotFound))
                    }
                },
                &s,
                &mut cmd_rx,
                &ev_tx,
            )
            .await;
        });
        tokio::time::sleep(Duration::from_secs(20)).await;
        // 0, +0.5, +1, +2, +4, +5, +5 ... : several attempts, not a hot loop.
        let n = attempts.load(Ordering::SeqCst);
        assert!((4..=8).contains(&n), "attempts {n}");
        assert_eq!(shared.status().code, ConnState::NotRunning);
        drop(cmd_tx);
        task.abort();
    }
}
