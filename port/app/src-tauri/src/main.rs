#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod rules;
mod update;

use daemon::{ConnState, DaemonStatus, Event, PendingAlert, Shared};
use rat_core::{Lifetime, Rule, RuleStore, Verdict};
use rat_daemon::msg::ClientMessage;
use rat_ledger::{Alert, AnswerScope, ConnectionDetails};
use rat_types::{Connection, ProcessInfo, Protocol};
use rules::{NewRule, RuleView};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    cmd_tx: UnboundedSender<ClientMessage>,
    rules_path: PathBuf,
    /// Serializes read-modify-send of the rule list.
    rules_lock: Mutex<()>,
}

impl DaemonDataSource {
    pub fn new(
        shared: Arc<Shared>,
        cmd_tx: UnboundedSender<ClientMessage>,
        rules_path: PathBuf,
    ) -> Self {
        Self {
            shared,
            cmd_tx,
            rules_path,
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

    fn load_rules(&self) -> Result<Vec<Rule>, String> {
        RuleStore::new(self.rules_path.clone())
            .load()
            .map_err(|e| format!("cannot read the rules file: {e}"))
    }

    fn send_rules(&self, rules: Vec<Rule>) -> Result<Vec<RuleView>, String> {
        let views = rules.iter().map(rules::view_of).collect();
        self.cmd_tx
            .send(ClientMessage::SetRules { rules })
            .map_err(|_| "The Rat service is not connected".to_string())?;
        Ok(views)
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
        Ok(self.load_rules()?.iter().map(rules::view_of).collect())
    }

    fn add_rule(&self, new: NewRule) -> Result<Vec<RuleView>, String> {
        self.require_connected()?;
        let rule = rules::build_rule(&new)?;
        let _guard = self.rules_lock.lock().map_err(|_| "rules lock poisoned")?;
        let mut all = self.load_rules()?;
        all.push(rule);
        self.send_rules(all)
    }

    fn delete_rule(&self, id: &str) -> Result<Vec<RuleView>, String> {
        self.require_connected()?;
        let _guard = self.rules_lock.lock().map_err(|_| "rules lock poisoned")?;
        let mut all = self.load_rules()?;
        rules::remove_rule(&mut all, id)?;
        self.send_rules(all)
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
        self.cmd_tx
            .send(ClientMessage::AlertAnswer {
                id,
                verdict,
                scope,
                lifetime,
            })
            .map_err(|_| "The Rat service is not connected".to_string())?;
        self.shared.clear_alert(id);
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
    data_source: Box<dyn DataSource>,
}

type AppStateHandle<'a> = State<'a, Mutex<AppState>>;

fn with_source<T>(
    state: &AppStateHandle<'_>,
    f: impl FnOnce(&dyn DataSource) -> Result<T, String>,
) -> Result<T, String> {
    let app_state = state.lock().map_err(|_| "Failed to lock state")?;
    f(app_state.data_source.as_ref())
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
fn get_rules(state: AppStateHandle<'_>) -> Result<Vec<RuleView>, String> {
    with_source(&state, |s| s.get_rules())
}

#[tauri::command]
fn add_rule(state: AppStateHandle<'_>, rule: NewRule) -> Result<Vec<RuleView>, String> {
    with_source(&state, |s| s.add_rule(rule))
}

#[tauri::command]
fn delete_rule(state: AppStateHandle<'_>, id: String) -> Result<Vec<RuleView>, String> {
    with_source(&state, |s| s.delete_rule(&id))
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
fn answer_alert(
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
    with_source(&state, |s| s.answer_alert(id, verdict, scope, lifetime))?;
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
    let (data_source, events): (Box<dyn DataSource>, _) = if demo_requested() {
        (Box::new(FakeDataSource::new(false)), None)
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
        (
            Box::new(DaemonDataSource::new(
                shared,
                cmd_tx,
                rat_daemon::default_rules_path(),
            )),
            Some(ev_rx),
        )
    };

    tauri::Builder::default()
        .manage(Mutex::new(AppState { data_source }))
        .setup(move |app| {
            if let Some(mut ev_rx) = events {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    while let Some(Event::Alert(_)) = ev_rx.recv().await {
                        if let Err(e) = open_alert_window(&handle) {
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

    // ---- DaemonDataSource against a temp rules file and a fake channel ----

    struct Fixture {
        src: DaemonDataSource,
        shared: Arc<Shared>,
        cmd_rx: tokio::sync::mpsc::UnboundedReceiver<ClientMessage>,
        dir: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only the unique temp dir this fixture created.
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rat-app-test-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let shared = Arc::new(Shared::new());
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let src = DaemonDataSource::new(shared.clone(), cmd_tx, dir.join("rules.json"));
        Fixture {
            src,
            shared,
            cmd_rx,
            dir,
        }
    }

    fn new_rule(app: &str, action: &str) -> NewRule {
        NewRule {
            app: app.to_string(),
            action: action.to_string(),
            remote: String::new(),
        }
    }

    #[test]
    fn rule_changes_need_a_connected_daemon() {
        let mut f = fixture("offline");
        assert!(f.src.add_rule(new_rule("/a", "allow")).is_err());
        assert!(f.src.delete_rule("x").is_err());
        assert!(f.cmd_rx.try_recv().is_err(), "nothing may be sent");
    }

    #[test]
    fn add_rule_sends_the_whole_list_including_existing_rules() {
        let mut f = fixture("add");
        // An existing rule (e.g. created by the daemon from an alert answer).
        let existing = rules::build_rule(&new_rule("/existing", "deny")).unwrap();
        RuleStore::new(f.dir.join("rules.json"))
            .save(vec![existing.clone()])
            .unwrap();
        f.shared.mark_connected_for_test();

        let views = f.src.add_rule(new_rule("/new", "allow")).unwrap();
        assert_eq!(views.len(), 2);
        match f.cmd_rx.try_recv().unwrap() {
            ClientMessage::SetRules { rules } => {
                assert_eq!(rules.len(), 2);
                assert_eq!(rules[0], existing);
                assert_eq!(rules[1].process_path.as_deref(), Some("/new"));
            }
            other => panic!("unexpected message {other:?}"),
        }
        // Delete the existing one: the rest is sent.
        let id = existing.id.to_string();
        let views = f.src.delete_rule(&id).unwrap();
        assert!(views.is_empty());
        match f.cmd_rx.try_recv().unwrap() {
            ClientMessage::SetRules { rules } => assert!(rules.is_empty()),
            other => panic!("unexpected message {other:?}"),
        }
    }

    #[test]
    fn unreadable_rules_file_is_an_error_not_an_empty_list() {
        let mut f = fixture("corrupt");
        std::fs::write(f.dir.join("rules.json"), b"{ truncated").unwrap();
        f.shared.mark_connected_for_test();
        assert!(f.src.get_rules().is_err());
        assert!(f.src.add_rule(new_rule("/a", "allow")).is_err());
        assert!(
            f.cmd_rx.try_recv().is_err(),
            "must not replace rules with an empty set"
        );
    }

    #[test]
    fn answer_alert_checks_the_id_and_clears_it() {
        let mut f = fixture("answer");
        f.shared.mark_connected_for_test();
        f.shared.set_alert_for_test(7);
        assert!(f
            .src
            .answer_alert(8, Verdict::Allow, AnswerScope::Any, Lifetime::Forever)
            .is_err());
        f.src
            .answer_alert(7, Verdict::Deny, AnswerScope::Domain, Lifetime::Once)
            .unwrap();
        assert!(f.src.pending_alert().is_none());
        match f.cmd_rx.try_recv().unwrap() {
            ClientMessage::AlertAnswer {
                id,
                verdict,
                scope,
                lifetime,
            } => {
                assert_eq!(
                    (id, verdict, scope, lifetime),
                    (7, Verdict::Deny, AnswerScope::Domain, Lifetime::Once)
                );
            }
            other => panic!("unexpected message {other:?}"),
        }
        // A second answer for the same alert is stale.
        assert!(f
            .src
            .answer_alert(7, Verdict::Deny, AnswerScope::Domain, Lifetime::Once)
            .is_err());
    }
}
