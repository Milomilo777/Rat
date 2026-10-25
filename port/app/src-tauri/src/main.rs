#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod rules;
mod update;

use daemon::{ConnState, DaemonStatus, Event, Outgoing, PendingAlert, Shared, IO_TIMEOUT};
use rat_core::{Lifetime, Rule, Verdict};
use rat_daemon::msg::ClientMessage;
use rat_ledger::{Alert, AnswerScope, ConnectionDetails};
use rat_types::{Connection, ProcessInfo, Protocol};
use rules::{NewRule, RuleView};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;
use tauri::State;
use tauri::WebviewUrl;
use tauri::WebviewWindowBuilder;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Serialize, Debug, Clone)]
pub struct ConnectionView {
    pub conn: Connection,
    pub process_behind: Option<String>,
    pub network_owner: Option<String>,
    pub vpn_mark: Option<String>,
    pub proxy_mark: Option<String>,
    pub service_name: Option<String>,
}

pub trait DataSource: Send + Sync {
    fn get_connections(&self) -> Result<Vec<ConnectionView>, String>;
    fn get_geoip_databases(&self) -> Result<Vec<String>, String>;
    fn get_rules(&self) -> Result<Vec<RuleView>, String>;
    /// Add a rule; returns the new rule list.
    fn add_rule(&self, rule: NewRule) -> Result<Vec<RuleView>, String>;
    /// Delete a rule by id; returns the new rule list.
    fn delete_rule(&self, id: &str) -> Result<Vec<RuleView>, String>;
    fn status(&self) -> DaemonStatus;
    fn pending_alert(&self) -> Option<PendingAlert>;
    fn answer_alert(
        &self,
        id: u64,
        verdict: Verdict,
        scope: AnswerScope,
        lifetime: Lifetime,
    ) -> Result<(), String>;
}

/// Usual service name of a remote port (what the daemon snapshot lacks); the
/// Monitor tab groups connections by it.
pub fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "ftp",
        22 => "ssh",
        25 | 465 | 587 => "smtp",
        53 => "domain",
        67 | 68 => "dhcp",
        80 | 8080 => "http",
        110 | 995 => "pop3",
        123 => "ntp",
        143 | 993 => "imap",
        443 | 8443 => "https",
        445 => "smb",
        3389 => "rdp",
        _ => return None,
    })
}

pub fn view_from(conn: Connection) -> ConnectionView {
    let service_name = conn
        .remote
        .and_then(|r| service_for_port(r.port()))
        .map(str::to_string);
    let vpn_mark = conn.via_vpn.then(|| "VPN".to_string());
    ConnectionView {
        conn,
        process_behind: None,
        network_owner: None,
        vpn_mark,
        proxy_mark: None,
        service_name,
    }
}

// ---------------------------------------------------------------------------
// Real daemon
// ---------------------------------------------------------------------------

pub struct DaemonDataSource {
    shared: Arc<Shared>,
    cmd_tx: UnboundedSender<Outgoing>,
    /// Serializes read-modify-send of the rule list.
    rules_lock: Mutex<()>,
}

const NOT_CONNECTED: &str = "The Rat service is not connected";

impl DaemonDataSource {
    pub fn new(shared: Arc<Shared>, cmd_tx: UnboundedSender<Outgoing>) -> Self {
        Self {
            shared,
            cmd_tx,
            rules_lock: Mutex::new(()),
        }
    }

    fn require_connected(&self) -> Result<(), String> {
        if self.shared.status().code == ConnState::Connected {
            Ok(())
        } else {
            Err("The Rat service is not connected".to_string())
        }
    }

    /// Serialize `msg` (refused when over the daemon's line limit, nothing
    /// is sent then), queue it and wait until the session has really written
    /// it to the daemon, or failed to.
    fn send_and_confirm(&self, msg: &ClientMessage) -> Result<(), String> {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let out = Outgoing::with_ack(msg, ack_tx)?;
        self.cmd_tx
            .send(out)
            .map_err(|_| NOT_CONNECTED.to_string())?;
        match ack_rx.recv_timeout(IO_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("could not send to the Rat service: {e}")),
            // The session dropped the command unwritten (connection lost).
            Err(RecvTimeoutError::Disconnected) => Err(NOT_CONNECTED.to_string()),
            Err(RecvTimeoutError::Timeout) => {
                Err("The Rat service did not accept the request in time".to_string())
            }
        }
    }

    /// The daemon is the only source of rules: ask it over the pipe. The
    /// rules file is never read here (the daemon may have refused it).
    fn fetch_rules(&self) -> Result<Vec<Rule>, String> {
        let gen = self.shared.rules_generation();
        self.send_and_confirm(&ClientMessage::GetRules)?;
        self.shared.wait_rules_after(gen, IO_TIMEOUT)
    }

    /// The rule list as the daemon holds it after our last edit. The edit and
    /// this `GetRules` travel on one connection, so the daemon handles them
    /// in order.
    fn rule_views(&self) -> Result<Vec<RuleView>, String> {
        Ok(self.fetch_rules()?.iter().map(rules::view_of).collect())
    }
}

impl DataSource for DaemonDataSource {
    fn get_connections(&self) -> Result<Vec<ConnectionView>, String> {
        let mut views: Vec<ConnectionView> = self
            .shared
            .connections()
            .into_iter()
            .map(view_from)
            .collect();
        views.sort_by(|a, b| {
            (&a.conn.process.name, a.conn.process.pid, a.conn.remote).cmp(&(
                &b.conn.process.name,
                b.conn.process.pid,
                b.conn.remote,
            ))
        });
        Ok(views)
    }

    fn get_geoip_databases(&self) -> Result<Vec<String>, String> {
        // GeoIP databases belong to the daemon; the protocol does not expose them.
        Ok(Vec::new())
    }

    fn get_rules(&self) -> Result<Vec<RuleView>, String> {
        self.require_connected()?;
        let _guard = self.rules_lock.lock().map_err(|_| "rules lock poisoned")?;
        Ok(self.fetch_rules()?.iter().map(rules::view_of).collect())
    }

    fn add_rule(&self, new: NewRule) -> Result<Vec<RuleView>, String> {
        self.require_connected()?;
        let rule = rules::build_rule(&new)?;
        let _guard = self.rules_lock.lock().map_err(|_| "rules lock poisoned")?;
        // One incremental message: rules the daemon creates meanwhile (alert
        // answers) are never overwritten, unlike a whole-list SetRules.
        self.send_and_confirm(&ClientMessage::AddRule {
            rule: Box::new(rule),
        })?;
        self.rule_views()
    }

    fn delete_rule(&self, id: &str) -> Result<Vec<RuleView>, String> {
        self.require_connected()?;
        let _guard = self.rules_lock.lock().map_err(|_| "rules lock poisoned")?;
        let id = rules::find_rule(&self.fetch_rules()?, id)?.id;
        self.send_and_confirm(&ClientMessage::RemoveRule { id })?;
        self.rule_views()
    }

    fn status(&self) -> DaemonStatus {
        self.shared.status()
    }

    fn pending_alert(&self) -> Option<PendingAlert> {
        self.shared.alert()
    }

    fn answer_alert(
        &self,
        id: u64,
        verdict: Verdict,
        scope: AnswerScope,
        lifetime: Lifetime,
    ) -> Result<(), String> {
        self.require_connected()?;
        match self.shared.alert() {
            Some(a) if a.id == id => {}
            _ => return Err("This alert is no longer pending".to_string()),
        }
        self.send_and_confirm(&ClientMessage::AlertAnswer {
            id,
            verdict,
            scope,
            lifetime,
        })?;
        // The alert stays on record until the daemon confirms it is gone.
        self.shared.mark_answered(id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Demo data (RAT_DEMO=1 only)
// ---------------------------------------------------------------------------

pub struct FakeDataSource {
    // Configurable for testing
    pub return_bad_data: bool,
    rules: Mutex<Vec<RuleView>>,
}

impl FakeDataSource {
    pub fn new(return_bad_data: bool) -> Self {
        Self {
            return_bad_data,
            rules: Mutex::new(vec![
                RuleView {
                    id: "1".to_string(),
                    app: "firefox".to_string(),
                    action: "allow".to_string(),
                    remote: "1.1.1.1".to_string(),
                },
                RuleView {
                    id: "2".to_string(),
                    app: "curl".to_string(),
                    action: "deny".to_string(),
                    remote: "8.8.8.8".to_string(),
                },
            ]),
        }
    }
}

impl DataSource for FakeDataSource {
    fn get_connections(&self) -> Result<Vec<ConnectionView>, String> {
        let (local_1_str, local_2_str) = if self.return_bad_data {
            ("127.0.0.1:54321_BAD", "192.168.1.5:12345_BAD")
        } else {
            ("127.0.0.1:54321", "192.168.1.5:12345")
        };

        let local_1 = local_1_str.parse().map_err(|e| format!("Bad IP: {}", e))?;
        let remote_1 = "1.1.1.1:443"
            .parse()
            .map_err(|e| format!("Bad IP: {}", e))?;
        let local_2 = local_2_str.parse().map_err(|e| format!("Bad IP: {}", e))?;
        let remote_2 = "8.8.8.8:53".parse().map_err(|e| format!("Bad IP: {}", e))?;

        Ok(vec![
            ConnectionView {
                conn: Connection {
                    process: ProcessInfo {
                        pid: 1234,
                        exe: Some(PathBuf::from("/usr/bin/firefox")),
                        name: "firefox".to_string(),
                        user: Some("demo".to_string()),
                    },
                    protocol: Protocol::Tcp,
                    local: local_1,
                    remote: Some(remote_1),
                    listening: false,
                    bytes_in: Some(1024),
                    bytes_out: Some(2048),
                    via_vpn: true,
                },
                process_behind: Some("via helper-process".to_string()),
                network_owner: Some("Cloudflare, Inc. (ASN 13335)".to_string()),
                vpn_mark: Some("WireGuard".to_string()),
                proxy_mark: None,
                service_name: Some("https".to_string()),
            },
            ConnectionView {
                conn: Connection {
                    process: ProcessInfo {
                        pid: 5678,
                        exe: Some(PathBuf::from("/usr/bin/curl")),
                        name: "curl".to_string(),
                        user: Some("demo".to_string()),
                    },
                    protocol: Protocol::Tcp,
                    local: local_2,
                    remote: Some(remote_2),
                    listening: false,
                    bytes_in: Some(512),
                    bytes_out: Some(512),
                    via_vpn: false,
                },
                process_behind: None,
                network_owner: Some("Google LLC".to_string()),
                vpn_mark: None,
                proxy_mark: Some("SOCKS5 Proxy".to_string()),
                service_name: Some("domain".to_string()),
            },
        ])
    }

    fn get_geoip_databases(&self) -> Result<Vec<String>, String> {
        Ok(vec!["dbip-asn-lite.mmdb".to_string()])
    }

    fn get_rules(&self) -> Result<Vec<RuleView>, String> {
        Ok(self.rules.lock().map_err(|_| "lock")?.clone())
    }

    fn add_rule(&self, new: NewRule) -> Result<Vec<RuleView>, String> {
        let rule = rules::build_rule(&new)?;
        let mut g = self.rules.lock().map_err(|_| "lock")?;
        g.push(rules::view_of(&rule));
        Ok(g.clone())
    }

    fn delete_rule(&self, id: &str) -> Result<Vec<RuleView>, String> {
        let mut g = self.rules.lock().map_err(|_| "lock")?;
        let before = g.len();
        g.retain(|r| r.id != id);
        if g.len() == before {
            return Err("no such rule".to_string());
        }
        Ok(g.clone())
    }

    fn status(&self) -> DaemonStatus {
        DaemonStatus {
            code: ConnState::Connected,
            detail: None,
            demo: true,
        }
    }

    fn pending_alert(&self) -> Option<PendingAlert> {
        let remote: SocketAddr = "1.1.1.1:443".parse().ok()?;
        Some(PendingAlert {
            id: 0,
            alert: Alert {
                app: "/usr/bin/firefox".to_string(),
                app_name: "Firefox".to_string(),
                host: "1.1.1.1".to_string(),
                remote,
                proto: Protocol::Tcp,
                details: ConnectionDetails::default(),
                reported_ms: 0,
            },
        })
    }

    fn answer_alert(&self, _: u64, _: Verdict, _: AnswerScope, _: Lifetime) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub struct AppState {
    data_source: Arc<dyn DataSource>,
}

type AppStateHandle<'a> = State<'a, Mutex<AppState>>;

fn with_source<T>(
    state: &AppStateHandle<'_>,
    f: impl FnOnce(&dyn DataSource) -> Result<T, String>,
) -> Result<T, String> {
    let source = state
        .lock()
        .map_err(|_| "Failed to lock state")?
        .data_source
        .clone();
    f(source.as_ref())
}

/// Run a data source call that waits for the daemon (rules, answers) on a
/// blocking thread, so neither the UI thread nor the async runtime stalls.
async fn with_source_blocking<T: Send + 'static>(
    state: &AppStateHandle<'_>,
    f: impl FnOnce(&dyn DataSource) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let source = state
        .lock()
        .map_err(|_| "Failed to lock state")?
        .data_source
        .clone();
    tauri::async_runtime::spawn_blocking(move || f(source.as_ref()))
        .await
        .map_err(|e| format!("background task failed: {e}"))?
}

#[tauri::command]
fn get_connections(state: AppStateHandle<'_>) -> Result<Vec<ConnectionView>, String> {
    with_source(&state, |s| s.get_connections())
}

#[tauri::command]
fn get_geoip_databases(state: AppStateHandle<'_>) -> Result<Vec<String>, String> {
    with_source(&state, |s| s.get_geoip_databases())
}

/// Update check (UpdateChecker.swift): the frontend fetches the GitHub
/// `releases` body (the webview owns HTTP), Rust picks the newest release
/// and compares it with the running version. `Ok(None)` = up to date.
#[tauri::command]
fn evaluate_update(
    releases_json: String,
    current_version: String,
    include_pre_releases: bool,
) -> Result<Option<update::Release>, String> {
    let release = update::newest_release(&releases_json, include_pre_releases)
        .ok_or_else(|| "no published releases found".to_string())?;
    Ok(if update::is_newer(&release.tag, &current_version) {
        Some(release)
    } else {
        None
    })
}

#[tauri::command]
async fn get_rules(state: AppStateHandle<'_>) -> Result<Vec<RuleView>, String> {
    with_source_blocking(&state, |s| s.get_rules()).await
}

#[tauri::command]
async fn add_rule(state: AppStateHandle<'_>, rule: NewRule) -> Result<Vec<RuleView>, String> {
    with_source_blocking(&state, move |s| s.add_rule(rule)).await
}

#[tauri::command]
async fn delete_rule(state: AppStateHandle<'_>, id: String) -> Result<Vec<RuleView>, String> {
    with_source_blocking(&state, move |s| s.delete_rule(&id)).await
}

#[tauri::command]
fn get_status(state: AppStateHandle<'_>) -> Result<DaemonStatus, String> {
    with_source(&state, |s| Ok(s.status()))
}

#[tauri::command]
fn get_pending_alert(state: AppStateHandle<'_>) -> Result<Option<PendingAlert>, String> {
    with_source(&state, |s| Ok(s.pending_alert()))
}

/// Answer the alert `id`. The strings use the daemon's spelling: verdict
/// "allow" | "deny", scope "any" | "domain" | "host" | "port", lifetime
/// "once" | "untilQuit" | "forever". The alert window closes on success.
#[tauri::command]
async fn answer_alert(
    app: tauri::AppHandle,
    state: AppStateHandle<'_>,
    id: u64,
    verdict: String,
    scope: String,
    lifetime: String,
) -> Result<(), String> {
    let verdict: Verdict = rules::parse_enum("verdict", &verdict)?;
    if verdict == Verdict::Ask {
        return Err("an answer must be allow or deny".to_string());
    }
    let scope: AnswerScope = rules::parse_enum("scope", &scope)?;
    let lifetime: Lifetime = rules::parse_enum("lifetime", &lifetime)?;
    with_source_blocking(&state, move |s| {
        s.answer_alert(id, verdict, scope, lifetime)
    })
    .await?;
    close_alert_window(&app);
    Ok(())
}

#[tauri::command]
fn close_alert(app: tauri::AppHandle) {
    close_alert_window(&app);
}

fn close_alert_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("alert") {
        let _ = w.close();
    }
}

fn open_alert_window(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("alert") {
        let _ = w.set_focus();
        return Ok(());
    }
    build_alert_window(app)
}

/// An alert is still unanswered: bring the window back if it was closed.
/// An open window is left alone (no focus stealing on every snapshot).
fn reopen_alert_window(app: &tauri::AppHandle) -> Result<(), String> {
    if app.get_webview_window("alert").is_some() {
        return Ok(());
    }
    build_alert_window(app)
}

fn build_alert_window(app: &tauri::AppHandle) -> Result<(), String> {
    WebviewWindowBuilder::new(app, "alert", WebviewUrl::App("src/alert.html".into()))
        .title("Connection Alert")
        .inner_size(450.0, 250.0)
        .always_on_top(true)
        .build()
        .map_err(|e| format!("Failed to build window: {}", e))?;
    Ok(())
}

/// Demo mode only: open the alert window with the fake alert.
#[tauri::command]
async fn simulate_alert(app: tauri::AppHandle, state: AppStateHandle<'_>) -> Result<(), String> {
    let demo = with_source(&state, |s| Ok(s.status().demo))?;
    if !demo {
        return Err("simulated alerts exist only in demo mode (RAT_DEMO=1)".to_string());
    }
    open_alert_window(&app)
}

fn demo_requested() -> bool {
    std::env::var("RAT_DEMO").map(|v| v == "1").unwrap_or(false)
}

fn main() {
    let (data_source, events): (Arc<dyn DataSource>, _) = if demo_requested() {
        (Arc::new(FakeDataSource::new(false)), None)
    } else {
        let shared = Arc::new(Shared::new());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
        let task_shared = shared.clone();
        tauri::async_runtime::spawn(async move {
            let endpoint = daemon::endpoint();
            daemon::run_client(
                || daemon::connect(&endpoint),
                &task_shared,
                &mut cmd_rx,
                &ev_tx,
            )
            .await;
        });
        (Arc::new(DaemonDataSource::new(shared, cmd_tx)), Some(ev_rx))
    };

    tauri::Builder::default()
        .manage(Mutex::new(AppState { data_source }))
        .setup(move |app| {
            if let Some(mut ev_rx) = events {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    while let Some(event) = ev_rx.recv().await {
                        let opened = match event {
                            Event::Alert(_) => open_alert_window(&handle),
                            Event::AlertPending(_) => reopen_alert_window(&handle),
                        };
                        if let Err(e) = opened {
                            eprintln!("rat-app: {e}");
                        }
                    }
                });
            }

            let show_i = MenuItemBuilder::with_id("show", "Show Monitor").build(app)?;
            let quit_i = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app).items(&[&show_i, &quit_i]).build()?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        std::process::exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_connections,
            get_geoip_databases,
            get_rules,
            add_rule,
            delete_rule,
            get_status,
            get_pending_alert,
            answer_alert,
            close_alert,
            simulate_alert,
            evaluate_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_data_source_handles_bad_data() {
        let source = FakeDataSource::new(true);
        let res = source.get_connections();

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Bad IP:"));
    }

    #[test]
    fn test_fake_data_source_valid_data() {
        let source = FakeDataSource::new(false);
        let res = source.get_connections();

        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 2);
    }

    #[test]
    fn demo_data_uses_a_neutral_user_name() {
        let conns = FakeDataSource::new(false).get_connections().unwrap();
        for c in conns {
            assert_eq!(c.conn.process.user.as_deref(), Some("demo"));
        }
    }

    #[test]
    fn demo_rules_can_be_added_and_deleted() {
        let s = FakeDataSource::new(false);
        let after_add = s
            .add_rule(NewRule {
                app: "/usr/bin/wget".to_string(),
                action: "deny".to_string(),
                remote: String::new(),
            })
            .unwrap();
        assert_eq!(after_add.len(), 3);
        let id = after_add[2].id.clone();
        assert_eq!(s.delete_rule(&id).unwrap().len(), 2);
        assert!(s.delete_rule(&id).is_err());
    }

    #[test]
    fn service_names_come_from_the_remote_port() {
        assert_eq!(service_for_port(443), Some("https"));
        assert_eq!(service_for_port(53), Some("domain"));
        assert_eq!(service_for_port(60001), None);
        let conns = FakeDataSource::new(false).get_connections().unwrap();
        let v = view_from(conns[0].conn.clone());
        assert_eq!(v.service_name.as_deref(), Some("https"));
        assert_eq!(v.vpn_mark.as_deref(), Some("VPN"));
    }

    // ---- DaemonDataSource against an in-memory fake daemon (real session) ----

    use crate::daemon::fake::{serve, FakeDaemon};
    use crate::daemon::run_session;

    struct Fixture {
        src: Arc<DaemonDataSource>,
        shared: Arc<Shared>,
        daemon: Arc<FakeDaemon>,
    }

    /// Connected session over an in-memory pipe to a fake daemon.
    async fn fixture() -> Fixture {
        let (client_io, daemon_io) = tokio::io::duplex(1 << 20);
        let shared = Arc::new(Shared::new());
        let daemon = Arc::new(FakeDaemon::default());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Outgoing>();
        let (ev_tx, _ev_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(serve(daemon_io, daemon.clone()));
        let s = shared.clone();
        tokio::spawn(async move {
            let _keep = _ev_rx;
            run_session(client_io, &s, &mut cmd_rx, &ev_tx).await;
        });
        for _ in 0..200 {
            if shared.status().code == ConnState::Connected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(shared.status().code, ConnState::Connected);
        Fixture {
            src: Arc::new(DaemonDataSource::new(shared.clone(), cmd_tx)),
            shared,
            daemon,
        }
    }

    /// Run a blocking data source call off the runtime threads.
    async fn run<T: Send + 'static>(
        f: &Fixture,
        call: impl FnOnce(&DaemonDataSource) -> T + Send + 'static,
    ) -> T {
        let src = f.src.clone();
        tokio::task::spawn_blocking(move || call(&src))
            .await
            .unwrap()
    }

    fn new_rule(app: &str, action: &str) -> NewRule {
        NewRule {
            app: app.to_string(),
            action: action.to_string(),
            remote: String::new(),
        }
    }

    /// Wait (bounded) until the fake daemon holds `n` rules: the write ack
    /// means "written", the daemon applies it a moment later.
    async fn daemon_has_rules(f: &Fixture, n: usize) -> Vec<Rule> {
        for _ in 0..200 {
            let rules = f.daemon.rules.lock().unwrap().clone();
            if rules.len() == n {
                return rules;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the daemon never reached {n} rules");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rule_changes_need_a_connected_daemon() {
        let shared = Arc::new(Shared::new());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let src = DaemonDataSource::new(shared, cmd_tx);
        assert!(src.add_rule(new_rule("/a", "allow")).is_err());
        assert!(src.delete_rule("x").is_err());
        assert!(src.get_rules().is_err());
        assert!(cmd_rx.try_recv().is_err(), "nothing may be sent");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rules_come_from_the_daemon_and_changes_keep_existing_rules() {
        let f = fixture().await;
        // A rule only the daemon knows (e.g. created from an alert answer).
        let existing = rules::build_rule(&new_rule("/existing", "deny")).unwrap();
        f.daemon.rules.lock().unwrap().push(existing.clone());

        let listed = run(&f, |s| s.get_rules()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].app, "/existing");

        let views = run(&f, |s| s.add_rule(new_rule("/new", "allow")))
            .await
            .unwrap();
        assert_eq!(views.len(), 2);
        let daemon_rules = daemon_has_rules(&f, 2).await;
        assert_eq!(daemon_rules[0], existing);
        assert_eq!(daemon_rules[1].process_path.as_deref(), Some("/new"));

        let id = existing.id.to_string();
        let views = run(&f, move |s| s.delete_rule(&id)).await.unwrap();
        assert_eq!(views.len(), 1);
        let daemon_rules = daemon_has_rules(&f, 1).await;
        assert_eq!(daemon_rules[0].process_path.as_deref(), Some("/new"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn single_rule_edits_send_incremental_messages_never_the_whole_list() {
        let f = fixture().await;
        // A list far over the 64 KiB line limit of a whole-list SetRules.
        {
            let mut g = f.daemon.rules.lock().unwrap();
            for i in 0..600 {
                g.push(rules::build_rule(&new_rule(&format!("/opt/app/{i}"), "deny")).unwrap());
            }
        }
        let views = run(&f, |s| s.add_rule(new_rule("/one/more", "allow")))
            .await
            .unwrap();
        assert_eq!(views.len(), 601);
        let id = f.daemon.rules.lock().unwrap()[0].id.to_string();
        let views = run(&f, move |s| s.delete_rule(&id)).await.unwrap();
        assert_eq!(views.len(), 600);
        // Deleting an id the daemon does not know is an error, nothing sent.
        let sent_before = f.daemon.received().len();
        assert!(run(&f, |s| s.delete_rule("no-such-id")).await.is_err());
        let received = f.daemon.received();
        assert!(received[sent_before..]
            .iter()
            .all(|m| matches!(m, ClientMessage::GetRules)));
        assert!(
            received
                .iter()
                .any(|m| matches!(m, ClientMessage::AddRule { .. }))
                && received
                    .iter()
                    .any(|m| matches!(m, ClientMessage::RemoveRule { .. })),
            "incremental messages were sent"
        );
        assert!(
            !received
                .iter()
                .any(|m| matches!(m, ClientMessage::SetRules { .. })),
            "a single edit must never replace the whole list"
        );
        assert!(!f
            .daemon
            .dropped_session
            .load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(f.shared.status().code, ConnState::Connected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn answer_alert_checks_the_id_and_waits_for_the_daemon() {
        let f = fixture().await;
        f.shared.set_alert_for_test(7);
        assert!(run(&f, |s| s.answer_alert(
            8,
            Verdict::Allow,
            AnswerScope::Any,
            Lifetime::Forever
        ))
        .await
        .is_err());
        run(&f, |s| {
            s.answer_alert(7, Verdict::Deny, AnswerScope::Domain, Lifetime::Once)
        })
        .await
        .unwrap();
        // Not offered again, but the local record goes only when the daemon
        // confirms (the fake daemon answers AlertCleared).
        assert!(f.src.pending_alert().is_none());
        for _ in 0..200 {
            if !f.shared.has_alert_record() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!f.shared.has_alert_record());
        assert!(f.daemon.received().iter().any(|m| matches!(
            m,
            ClientMessage::AlertAnswer {
                id: 7,
                verdict: Verdict::Deny,
                scope: AnswerScope::Domain,
                lifetime: Lifetime::Once
            }
        )));
        // A second answer for the same alert is stale.
        assert!(run(&f, |s| s.answer_alert(
            7,
            Verdict::Deny,
            AnswerScope::Domain,
            Lifetime::Once
        ))
        .await
        .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_answer_keeps_the_alert_pending() {
        // No session runs: the command can never be written.
        let shared = Arc::new(Shared::new());
        shared.mark_connected_for_test();
        shared.set_alert_for_test(7);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        drop(cmd_rx);
        let src = DaemonDataSource::new(shared.clone(), cmd_tx);
        assert!(src
            .answer_alert(7, Verdict::Deny, AnswerScope::Any, Lifetime::Once)
            .is_err());
        assert_eq!(shared.alert().unwrap().id, 7);
    }

    // The rules file is the daemon's business only.
    #[test]
    fn the_app_never_reads_the_rules_file() {
        let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for entry in std::fs::read_dir(here).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            // Built from pieces so this test does not match itself.
            for needle in [
                ["rules", ".json"].concat(),
                ["default_rules", "_path"].concat(),
                ["Rule", "Store"].concat(),
            ] {
                let hits: Vec<&str> = text
                    .lines()
                    .filter(|l| l.contains(needle.as_str()))
                    .filter(|l| !l.trim_start().starts_with("//"))
                    .collect();
                assert!(hits.is_empty(), "{}: {needle}: {hits:?}", path.display());
            }
        }
    }
}
