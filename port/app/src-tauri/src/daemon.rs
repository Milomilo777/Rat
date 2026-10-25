//! Client for the privileged Rat daemon (IPC protocol v1).
//!
//! Wire format: newline-delimited JSON, the first client message must be
//! `Hello`, the daemon answers `HelloAck`, then streams `Snapshot`,
//! `AlertRequest` and `AlertCleared` messages; `GetRules` is answered with
//! `Rules`. The message types come from the `rat-daemon` crate so this client
//! cannot drift from the server.
//!
//! The session logic is generic over any async byte stream, so it is tested
//! against an in-memory fake daemon; only `connect()` touches the OS.

use rat_core::Rule;
use rat_daemon::msg::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use rat_ledger::Alert;
use rat_types::Connection;
use serde::Serialize;
use std::future::Future;
use std::io;
use std::sync::mpsc::Sender as AckSender;
use std::sync::{Condvar, Mutex};
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
/// How long a rules command waits for the session to write, or for the
/// daemon to answer `GetRules`.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Serialize a client message for the wire. A line over the daemon's limit
/// would make the daemon drop the whole session, so it is refused here and
/// never written.
pub fn encode(msg: &ClientMessage) -> Result<String, String> {
    let line = msg.to_string().map_err(|e| e.to_string())?;
    if line.len() > MAX_CLIENT_LINE {
        return Err(match msg {
            ClientMessage::SetRules { .. } => format!(
                "too many rules for one update: {} bytes, limit {}",
                line.len(),
                MAX_CLIENT_LINE
            ),
            _ => format!(
                "message too large: {} bytes, limit {}",
                line.len(),
                MAX_CLIENT_LINE
            ),
        });
    }
    Ok(line)
}

/// One serialized client message, plus an optional channel on which the
/// session reports whether the line was really written.
pub struct Outgoing {
    line: String,
    ack: Option<AckSender<Result<(), String>>>,
}

impl Outgoing {
    /// Fire-and-forget message.
    pub fn new(msg: &ClientMessage) -> Result<Self, String> {
        Ok(Self {
            line: encode(msg)?,
            ack: None,
        })
    }

    /// Message whose write result is reported on `ack`.
    pub fn with_ack(
        msg: &ClientMessage,
        ack: AckSender<Result<(), String>>,
    ) -> Result<Self, String> {
        Ok(Self {
            line: encode(msg)?,
            ack: Some(ack),
        })
    }

    #[cfg(test)]
    pub fn message(&self) -> ClientMessage {
        ClientMessage::from_json_str(&self.line).unwrap()
    }
}

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
    /// A new alert arrived: open the alert window, or focus it.
    Alert(u64),
    /// An alert is still waiting for an answer (sent with every snapshot):
    /// reopen the window if the user closed it, never steal focus.
    AlertPending(u64),
}

/// The alert the daemon asked about. `answered` is set once the answer was
/// written to the daemon; the alert stays on record until the daemon says it
/// is gone (`AlertCleared`) or sends another one.
struct TrackedAlert {
    alert: PendingAlert,
    answered: bool,
}

struct Inner {
    state: ConnState,
    detail: Option<String>,
    connections: Vec<Connection>,
    alert: Option<TrackedAlert>,
    /// The daemon's rule set as of the last `Rules` answer.
    rules: Option<Vec<Rule>>,
    /// Counts `Rules` answers, so a caller can wait for the next one.
    rules_gen: u64,
}

/// Latest daemon state, shared between the background task and the commands.
pub struct Shared {
    inner: Mutex<Inner>,
    rules_cv: Condvar,
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
                rules: None,
                rules_gen: 0,
            }),
            rules_cv: Condvar::new(),
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

    /// The alert still waiting for an answer (None once it was answered).
    pub fn alert(&self) -> Option<PendingAlert> {
        self.lock()
            .alert
            .as_ref()
            .filter(|t| !t.answered)
            .map(|t| t.alert.clone())
    }

    /// The answer for alert `id` reached the daemon. The alert is kept on
    /// record (not offered again) until the daemon confirms it is gone.
    pub fn mark_answered(&self, id: u64) {
        let mut g = self.lock();
        if let Some(t) = g.alert.as_mut().filter(|t| t.alert.id == id) {
            t.answered = true;
        }
    }

    /// The daemon says alert `id` is no longer pending.
    pub fn clear_alert(&self, id: u64) {
        let mut g = self.lock();
        if g.alert.as_ref().is_some_and(|t| t.alert.id == id) {
            g.alert = None;
        }
    }

    /// How many `Rules` answers have arrived so far.
    pub fn rules_generation(&self) -> u64 {
        self.lock().rules_gen
    }

    /// Wait for a `Rules` answer newer than `gen`. Fails when the connection
    /// is lost or `timeout` passes first.
    pub fn wait_rules_after(&self, gen: u64, timeout: Duration) -> Result<Vec<Rule>, String> {
        let g = self.lock();
        let (g, _) = self
            .rules_cv
            .wait_timeout_while(g, timeout, |i| {
                i.rules_gen == gen && i.state == ConnState::Connected
            })
            .unwrap_or_else(|p| p.into_inner());
        if g.rules_gen != gen {
            if let Some(rules) = &g.rules {
                return Ok(rules.clone());
            }
        }
        if g.state != ConnState::Connected {
            return Err("The Rat service is not connected".to_string());
        }
        Err("The Rat service did not answer the rules request in time".to_string())
    }

    fn set_state(&self, state: ConnState, detail: Option<String>) {
        let mut g = self.lock();
        g.state = state;
        g.detail = detail;
        if state != ConnState::Connected {
            // Stale data would look like live data: drop it.
            g.connections.clear();
            g.alert = None;
            g.rules = None;
            // Wake anybody waiting for rules: they fail now, not at timeout.
            self.rules_cv.notify_all();
        }
    }

    fn set_connections(&self, connections: Vec<Connection>) {
        self.lock().connections = connections;
    }

    fn set_alert(&self, alert: PendingAlert) {
        self.lock().alert = Some(TrackedAlert {
            alert,
            answered: false,
        });
    }

    fn set_rules(&self, rules: Vec<Rule>) {
        let mut g = self.lock();
        g.rules = Some(rules);
        g.rules_gen += 1;
        self.rules_cv.notify_all();
    }

    fn set_detail(&self, detail: String) {
        self.lock().detail = Some(detail);
    }

    #[cfg(test)]
    pub fn mark_connected_for_test(&self) {
        self.set_state(ConnState::Connected, None);
    }

    /// Whether the daemon-confirmation record of an alert still exists
    /// (answered or not).
    #[cfg(test)]
    pub fn has_alert_record(&self) -> bool {
        self.lock().alert.is_some()
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
    let line = encode(msg)?;
    writer.send(line).await.map_err(|e| e.to_string())
}

/// Run one connected session on `stream` until it ends.
pub async fn run_session<S>(
    stream: S,
    shared: &Shared,
    cmds: &mut UnboundedReceiver<Outgoing>,
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
                    Some(out) => {
                        let written = writer.send(out.line).await.map_err(|e| e.to_string());
                        let failed = written.is_err();
                        if let Some(ack) = out.ack {
                            // The caller may have given up waiting.
                            let _ = ack.send(written);
                        }
                        if failed {
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
        Ok(ServerMessage::Snapshot { connections }) => {
            shared.set_connections(connections);
            // An alert the user has not answered (for example because the
            // alert window was closed) is offered again with every snapshot.
            if let Some(pending) = shared.alert() {
                let _ = events.send(Event::AlertPending(pending.id));
            }
        }
        Ok(ServerMessage::AlertRequest { id, alert }) => {
            shared.set_alert(PendingAlert { id, alert: *alert });
            let _ = events.send(Event::Alert(id));
        }
        Ok(ServerMessage::AlertCleared { id }) => shared.clear_alert(id),
        Ok(ServerMessage::Rules { rules }) => shared.set_rules(rules),
        Ok(ServerMessage::Error { message }) => shared.set_detail(message),
        Ok(ServerMessage::HelloAck { .. }) | Err(_) => {}
    }
}

/// Connect, run sessions and reconnect with backoff, forever (until the
/// command channel closes). `connect` is the OS-specific opener.
pub async fn run_client<C, Fut, S>(
    connect: C,
    shared: &Shared,
    cmds: &mut UnboundedReceiver<Outgoing>,
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

/// A small in-memory daemon for tests: the same wire protocol, a rule set in
/// memory (`GetRules` / `SetRules`), the 64 KiB inbound line limit.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    pub struct FakeDaemon {
        pub rules: Mutex<Vec<Rule>>,
        pub received: Mutex<Vec<ClientMessage>>,
        /// Set when the daemon dropped the session (oversized line).
        pub dropped_session: AtomicBool,
    }

    impl FakeDaemon {
        pub fn received(&self) -> Vec<ClientMessage> {
            self.received.lock().unwrap().clone()
        }
    }

    pub async fn serve(io: tokio::io::DuplexStream, state: Arc<FakeDaemon>) {
        let (r, w) = tokio::io::split(io);
        let mut reader = FramedRead::new(r, LinesCodec::new_with_max_length(MAX_CLIENT_LINE));
        let mut writer = FramedWrite::new(w, LinesCodec::new_with_max_length(MAX_SERVER_LINE));
        loop {
            let line = match reader.next().await {
                Some(Ok(line)) => line,
                Some(Err(_)) => {
                    state.dropped_session.store(true, Ordering::SeqCst);
                    return;
                }
                None => return,
            };
            let Ok(msg) = ClientMessage::from_json_str(&line) else {
                return;
            };
            let reply = match &msg {
                ClientMessage::Hello { .. } => Some(ServerMessage::HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                }),
                ClientMessage::GetRules => Some(ServerMessage::Rules {
                    rules: state.rules.lock().unwrap().clone(),
                }),
                ClientMessage::SetRules { rules } => {
                    *state.rules.lock().unwrap() = rules.clone();
                    None
                }
                ClientMessage::AlertAnswer { id, .. } => {
                    Some(ServerMessage::AlertCleared { id: *id })
                }
            };
            state.received.lock().unwrap().push(msg);
            if let Some(reply) = reply {
                if writer.send(reply.to_string().unwrap()).await.is_err() {
                    return;
                }
            }
        }
    }
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
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Outgoing>();
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
            .send(
                Outgoing::new(&ClientMessage::AlertAnswer {
                    id: 9,
                    verdict: Verdict::Deny,
                    scope: AnswerScope::Host,
                    lifetime: Lifetime::Forever,
                })
                .unwrap(),
            )
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
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Outgoing>();
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

    // ---- rules over IPC, write results, alert lifecycle ----

    fn rule(path: &str) -> Rule {
        crate::rules::build_rule(&crate::rules::NewRule {
            app: path.to_string(),
            action: "deny".to_string(),
            remote: String::new(),
        })
        .unwrap()
    }

    #[test]
    fn oversized_rules_are_refused_before_anything_is_written() {
        let small = ClientMessage::SetRules {
            rules: vec![rule("/a")],
        };
        assert!(encode(&small).is_ok());
        let big = ClientMessage::SetRules {
            rules: (0..600).map(|i| rule(&format!("/opt/app/{i}"))).collect(),
        };
        let err = encode(&big).unwrap_err();
        assert!(err.starts_with("too many rules for one update: "), "{err}");
        assert!(err.ends_with("bytes, limit 65536"), "{err}");
        assert!(Outgoing::new(&big).is_err());
    }

    struct Live {
        shared: Arc<Shared>,
        cmd_tx: tokio::sync::mpsc::UnboundedSender<Outgoing>,
        daemon: Arc<fake::FakeDaemon>,
        ev_rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
    }

    use std::sync::Arc;

    /// A session against the fake daemon, already past the handshake.
    async fn live() -> Live {
        let (client_io, daemon_io) = tokio::io::duplex(1 << 20);
        let shared = Arc::new(Shared::new());
        let daemon = Arc::new(fake::FakeDaemon::default());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Outgoing>();
        let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(fake::serve(daemon_io, daemon.clone()));
        let s = shared.clone();
        tokio::spawn(async move {
            run_session(client_io, &s, &mut cmd_rx, &ev_tx).await;
        });
        wait_for(|| shared.status().code == ConnState::Connected).await;
        Live {
            shared,
            cmd_tx,
            daemon,
            ev_rx,
        }
    }

    /// Send `msg` and wait (off the runtime threads) for its write result.
    async fn send_acked(l: &Live, msg: ClientMessage) -> Result<(), String> {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        l.cmd_tx
            .send(Outgoing::with_ack(&msg, ack_tx)?)
            .map_err(|_| "closed".to_string())?;
        tokio::task::spawn_blocking(move || {
            ack_rx.recv_timeout(IO_TIMEOUT).map_err(|e| e.to_string())?
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_rules_is_answered_from_the_daemon_set() {
        let l = live().await;
        l.daemon.rules.lock().unwrap().push(rule("/from/daemon"));
        let gen = l.shared.rules_generation();
        send_acked(&l, ClientMessage::GetRules).await.unwrap();
        let s = l.shared.clone();
        let got = tokio::task::spawn_blocking(move || s.wait_rules_after(gen, IO_TIMEOUT))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].process_path.as_deref(), Some("/from/daemon"));
        // A second wait with the new generation has nothing newer: times out.
        let gen2 = l.shared.rules_generation();
        assert!(gen2 > gen);
        assert!(l
            .shared
            .wait_rules_after(gen2, Duration::from_millis(50))
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_acked_write_reports_success_and_reaches_the_daemon() {
        let l = live().await;
        send_acked(
            &l,
            ClientMessage::SetRules {
                rules: vec![rule("/x")],
            },
        )
        .await
        .unwrap();
        wait_for(|| l.daemon.rules.lock().unwrap().len() == 1).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_that_cannot_happen_is_reported_not_swallowed() {
        // Commands queued while no session runs are stale: the sender of
        // the ack is dropped, so the waiting caller sees a failure at once.
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Outgoing>();
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        cmd_tx
            .send(Outgoing::with_ack(&ClientMessage::GetRules, ack_tx).unwrap())
            .unwrap();
        let (client_io, daemon_io) = tokio::io::duplex(1 << 12);
        drop(daemon_io);
        let (ev_tx, _ev_rx) = tokio::sync::mpsc::unbounded_channel();
        let shared = Shared::new();
        let end = run_session(client_io, &shared, &mut cmd_rx, &ev_tx).await;
        assert_eq!(end, SessionEnd::Handshake);
        assert!(ack_rx.recv_timeout(Duration::from_secs(1)).is_err());
    }

    #[test]
    fn lost_connection_wakes_a_rules_waiter_with_an_error() {
        let shared = Arc::new(Shared::new());
        shared.set_state(ConnState::Connected, None);
        let s = shared.clone();
        let waiter = std::thread::spawn(move || s.wait_rules_after(0, Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(50));
        shared.set_state(ConnState::Connecting, None);
        let err = waiter.join().unwrap().unwrap_err();
        assert!(err.contains("not connected"), "{err}");
    }

    #[test]
    fn an_answered_alert_stays_on_record_until_the_daemon_clears_it() {
        let shared = Shared::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        shared.mark_connected_for_test();
        shared.set_alert_for_test(7);
        shared.mark_answered(7);
        // Not offered to the UI again, but not forgotten either.
        assert!(shared.alert().is_none());
        assert!(shared.has_alert_record());
        // A different id does not clear it.
        handle_server_line(r#"{"AlertCleared":{"id":8}}"#, &shared, &tx);
        assert!(shared.has_alert_record());
        handle_server_line(r#"{"AlertCleared":{"id":7}}"#, &shared, &tx);
        assert!(!shared.has_alert_record());
    }

    #[test]
    fn a_pending_alert_is_offered_again_with_every_snapshot() {
        let shared = Shared::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        shared.mark_connected_for_test();
        let snap = r#"{"Snapshot":{"connections":[]}}"#;

        // No alert: a snapshot is just a snapshot.
        handle_server_line(snap, &shared, &tx);
        assert!(rx.try_recv().is_err());

        // The user closed the alert window without answering: the alert is
        // still pending, the next snapshot asks the shell to reopen it.
        shared.set_alert_for_test(4);
        handle_server_line(snap, &shared, &tx);
        assert_eq!(rx.try_recv().unwrap(), Event::AlertPending(4));

        // Once answered it is not offered again, even before the daemon
        // confirms.
        shared.mark_answered(4);
        handle_server_line(snap, &shared, &tx);
        assert!(rx.try_recv().is_err());

        // A new alert is pending again.
        handle_server_line(
            &ServerMessage::AlertRequest {
                id: 5,
                alert: Box::new(alert()),
            }
            .to_string()
            .unwrap(),
            &shared,
            &tx,
        );
        assert_eq!(rx.try_recv().unwrap(), Event::Alert(5));
        assert_eq!(shared.alert().unwrap().id, 5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn alert_cleared_from_the_daemon_removes_the_record_over_a_session() {
        let mut l = live().await;
        l.shared.set_alert_for_test(3);
        send_acked(
            &l,
            ClientMessage::AlertAnswer {
                id: 3,
                verdict: Verdict::Allow,
                scope: AnswerScope::Any,
                lifetime: Lifetime::Once,
            },
        )
        .await
        .unwrap();
        wait_for(|| !l.shared.has_alert_record()).await;
        while l.ev_rx.try_recv().is_ok() {}
    }
}
