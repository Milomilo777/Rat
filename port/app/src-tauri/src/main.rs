#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rat_types::{Connection, ProcessInfo, Protocol};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;
use tauri::tray::TrayIconBuilder;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::WebviewWindowBuilder;
use tauri::WebviewUrl;
use tauri::State;

#[derive(Serialize)]
pub struct ConnectionView {
    pub conn: Connection,
    pub process_behind: Option<String>,
    pub network_owner: Option<String>,
    pub vpn_mark: Option<String>,
    pub proxy_mark: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Serialize)]
pub struct RuleView {
    pub id: String,
    pub app: String,
    pub action: String,
    pub remote: String,
}

pub trait DataSource: Send + Sync {
    fn get_connections(&self) -> Vec<ConnectionView>;
    fn get_geoip_databases(&self) -> Vec<String>;
    fn get_rules(&self) -> Vec<RuleView>;
}

pub struct FakeDataSource;

impl DataSource for FakeDataSource {
    fn get_connections(&self) -> Vec<ConnectionView> {
        vec![
            ConnectionView {
                conn: Connection {
                    process: ProcessInfo {
                        pid: 1234,
                        exe: Some(PathBuf::from("/usr/bin/firefox")),
                        name: "firefox".to_string(),
                        user: Some("jules".to_string()),
                    },
                    protocol: Protocol::Tcp,
                    local: "127.0.0.1:54321".parse().unwrap(),
                    remote: Some("1.1.1.1:443".parse().unwrap()),
                    listening: false,
                    bytes_in: Some(1024),
                    bytes_out: Some(2048),
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
                        user: Some("jules".to_string()),
                    },
                    protocol: Protocol::Tcp,
                    local: "192.168.1.5:12345".parse().unwrap(),
                    remote: Some("8.8.8.8:53".parse().unwrap()),
                    listening: false,
                    bytes_in: Some(512),
                    bytes_out: Some(512),
                },
                process_behind: None,
                network_owner: Some("Google LLC".to_string()),
                vpn_mark: None,
                proxy_mark: Some("SOCKS5 Proxy".to_string()),
                service_name: Some("domain".to_string()),
            }
        ]
    }

    fn get_geoip_databases(&self) -> Vec<String> {
        vec![
            "dbip-asn-lite.mmdb".to_string(),
        ]
    }

    fn get_rules(&self) -> Vec<RuleView> {
        vec![
            RuleView { id: "1".to_string(), app: "firefox".to_string(), action: "allow".to_string(), remote: "1.1.1.1".to_string() },
            RuleView { id: "2".to_string(), app: "curl".to_string(), action: "deny".to_string(), remote: "8.8.8.8".to_string() },
        ]
    }
}

pub struct AppState {
    data_source: Box<dyn DataSource>,
}

#[tauri::command]
fn get_connections(state: State<'_, Mutex<AppState>>) -> Vec<ConnectionView> {
    state.lock().unwrap().data_source.get_connections()
}

#[tauri::command]
fn get_geoip_databases(state: State<'_, Mutex<AppState>>) -> Vec<String> {
    state.lock().unwrap().data_source.get_geoip_databases()
}

#[tauri::command]
fn get_rules(state: State<'_, Mutex<AppState>>) -> Vec<RuleView> {
    state.lock().unwrap().data_source.get_rules()
}

#[tauri::command]
fn simulate_alert(app: tauri::AppHandle) {
    let _window = WebviewWindowBuilder::new(
        &app,
        "alert",
        WebviewUrl::App("src/alert.html".into())
    )
    .title("Connection Alert")
    .inner_size(450.0, 250.0)
    .build()
    .unwrap();
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(AppState {
            data_source: Box::new(FakeDataSource),
        }))
        .setup(|app| {
            let show_i = MenuItemBuilder::with_id("show", "Show Monitor").build(app)?;
            let quit_i = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app)
                .items(&[&show_i, &quit_i])
                .build()?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        std::process::exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            window.show().unwrap();
                            window.set_focus().unwrap();
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_connections, get_geoip_databases, get_rules, simulate_alert])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
