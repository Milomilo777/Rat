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
A mock implementation is provided via `FakeDataSource`:
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
- The Tauri app is not yet connected to the daemon in every build and may show demo data; see the status in `port/README.md`.
- The `DataSource` implementation can fail dynamically (e.g. if the daemon pipe crashes or IPC is lost). The `unwrap` instances on invalid data have been replaced with `Result<T, String>` to bubble up parsing and connectivity errors to the frontend safely instead of panicking.
