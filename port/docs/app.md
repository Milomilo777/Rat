# Rat Desktop Shell (Tauri)

## Purpose
This document provides an overview of the Rat desktop shell implemented using Tauri v2, built to act as the primary cross-platform GUI for the Rat network monitor and firewall on Windows and Linux.

## Public API
The application core primarily exposes functionality to the frontend through the Tauri command system and the injected `DataSource` trait.

### `DataSource` Trait
```rust
pub trait DataSource: Send + Sync {
    fn get_connections(&self) -> Result<Vec<ConnectionView>, String>;
    fn get_geoip_databases(&self) -> Result<Vec<String>, String>;
    fn get_rules(&self) -> Result<Vec<RuleView>, String>;
}
```

#### Usage Example
`DaemonDataSource` (src-tauri/src/daemon.rs) is the real implementation: it speaks the daemon's IPC protocol v1
(Hello/HelloAck, Snapshot, GetRules/Rules, SetRules, AlertRequest/AlertAnswer/AlertCleared), keeps the latest
snapshot in a background task and reconnects with backoff.

Rules: the daemon is the single source. `get_rules`, `add_rule` and `delete_rule` ask the daemon with `GetRules`,
change the list and send it back with `SetRules`; the app never reads the rules file (the daemon may have refused
that file). The message is serialized first: over the daemon's 64 KiB line limit the command fails with "too many
rules for one update: N bytes, limit 65536" and nothing is written. The commands wait (5 s) until the session
wrote the line, so a failed write is reported to the UI. They run on a blocking thread.

Alerts: answering waits for the write; the alert stays on record (not offered to the UI again) until the daemon
sends `AlertCleared`. A pending alert whose window was closed is reopened with the next snapshot (an open window is
not touched).
 `FakeDataSource` serves fixed demo data and is used only when `RAT_DEMO=1` is set:
```rust
let source = FakeDataSource;
match source.get_connections() {
    Ok(connections) => {
        // connections is a Vec<ConnectionView> containing network routing details
        // and process ownership information
    }
    Err(e) => {
        // handle the error safely
    }
}
```

## Platform Notes
- **Windows**: The daemon runs as a `LocalSystem` service and enforces blocks with Windows Defender Firewall
  (`netsh advfirewall` rules: per-program rules for apps and local-port rules). The Tauri UI app runs in user mode;
  the daemon's named pipe admits only elevated administrators and SYSTEM.
- **Linux**: The daemon runs as root and enforces blocks with `nftables` (table `inet rat`, port sets for the local
  ports of denied programs). The Tauri UI app runs unprivileged and reaches the daemon through the Unix socket
  `/run/rat/rat.sock` (members of the `rat` group).
- **macOS**: The codebase explicitly skips the macOS port for this specific crate, deferring to the native Swift implementation.

## Known Limits
- The app shows demo data only with `RAT_DEMO=1`; otherwise it needs the running daemon and shows a clear message
  when the service is not running or access is denied.
- The `DataSource` implementation can fail dynamically (e.g. if the daemon pipe crashes or IPC is lost). The `unwrap` instances on invalid data have been replaced with `Result<T, String>` to bubble up parsing and connectivity errors to the frontend safely instead of panicking.
