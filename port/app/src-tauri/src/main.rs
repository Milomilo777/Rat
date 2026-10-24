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

#[derive(Serialize, Debug, Clone)]
pub struct ConnectionView {
    pub conn: Connection,
    pub process_behind: Option<String>,
    pub network_owner: Option<String>,
    pub vpn_mark: Option<String>,
    pub proxy_mark: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct RuleView {
    pub id: String,
    pub app: String,
    pub action: String,
    pub remote: String,
}

pub trait DataSource: Send + Sync {
    fn get_connections(&self) -> Result<Vec<ConnectionView>, String>;
    fn get_geoip_databases(&self) -> Result<Vec<String>, String>;
    fn get_rules(&self) -> Result<Vec<RuleView>, String>;
}

pub struct FakeDataSource {
    // Configurable for testing
    pub return_bad_data: bool,
}

impl DataSource for FakeDataSource {
    fn get_connections(&self) -> Result<Vec<ConnectionView>, String> {
        let (local_1_str, local_2_str) = if self.return_bad_data {
            ("127.0.0.1:54321_BAD", "192.168.1.5:12345_BAD")
        } else {
            ("127.0.0.1:54321", "192.168.1.5:12345")
        };

        let local_1 = local_1_str.parse().map_err(|e| format!("Bad IP: {}", e))?;
        let remote_1 = "1.1.1.1:443".parse().map_err(|e| format!("Bad IP: {}", e))?;
        let local_2 = local_2_str.parse().map_err(|e| format!("Bad IP: {}", e))?;
        let remote_2 = "8.8.8.8:53".parse().map_err(|e| format!("Bad IP: {}", e))?;

        Ok(vec![
            ConnectionView {
                conn: Connection {
                    process: ProcessInfo {
                        pid: 1234,
                        exe: Some(PathBuf::from("/usr/bin/firefox")),
                        name: "firefox".to_string(),
                        user: Some("jules".to_string()),
                    },
                    protocol: Protocol::Tcp,
                    local: local_1,
                    remote: Some(remote_1),
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
                    local: local_2,
                    remote: Some(remote_2),
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
        ])
    }

    fn get_geoip_databases(&self) -> Result<Vec<String>, String> {
        Ok(vec![
            "dbip-asn-lite.mmdb".to_string(),
        ])
    }

    fn get_rules(&self) -> Result<Vec<RuleView>, String> {
        Ok(vec![
            RuleView { id: "1".to_string(), app: "firefox".to_string(), action: "allow".to_string(), remote: "1.1.1.1".to_string() },
            RuleView { id: "2".to_string(), app: "curl".to_string(), action: "deny".to_string(), remote: "8.8.8.8".to_string() },
        ])
    }
}

pub struct AppState {
    data_source: Box<dyn DataSource>,
}

#[tauri::command]
fn get_connections(state: State<'_, Mutex<AppState>>) -> Result<Vec<ConnectionView>, String> {
    let app_state = state.lock().map_err(|_| "Failed to lock state")?;
    app_state.data_source.get_connections()
}

#[tauri::command]
fn get_geoip_databases(state: State<'_, Mutex<AppState>>) -> Result<Vec<String>, String> {
    let app_state = state.lock().map_err(|_| "Failed to lock state")?;
    app_state.data_source.get_geoip_databases()
}

#[tauri::command]
fn get_rules(state: State<'_, Mutex<AppState>>) -> Result<Vec<RuleView>, String> {
    let app_state = state.lock().map_err(|_| "Failed to lock state")?;
    app_state.data_source.get_rules()
}

#[tauri::command]
fn simulate_alert(app: tauri::AppHandle) -> Result<(), String> {
    WebviewWindowBuilder::new(
        &app,
        "alert",
        WebviewUrl::App("src/alert.html".into())
    )
    .title("Connection Alert")
    .inner_size(450.0, 250.0)
    .build()
    .map_err(|e| format!("Failed to build window: {}", e))?;

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(AppState {
            data_source: Box::new(FakeDataSource { return_bad_data: false }),
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
                            let _ = window.show();
                            let _ = window.set_focus();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_data_source_handles_bad_data() {
        let source = FakeDataSource { return_bad_data: true };
        let res = source.get_connections();

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Bad IP:"));
    }

    #[test]
    fn test_fake_data_source_valid_data() {
        let source = FakeDataSource { return_bad_data: false };
        let res = source.get_connections();

        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 2);
    }
}
