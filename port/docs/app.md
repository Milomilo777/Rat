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
- **Windows**: The interception architecture relies on the Windows Filtering Platform (WFP), necessitating that the daemon component run with Administrative privileges to register the provider and sublayer. The Tauri UI app runs in user-mode but may require UAC elevation if it needs to adjust the firewall rules directly.
- **Linux**: Interception relies on `nftables` and `nfqueue`. The daemon component requires root/`CAP_NET_ADMIN` to manipulate the netfilter queues. The Tauri UI app runs unprivileged.
- **macOS**: The codebase explicitly skips the macOS port for this specific crate, deferring to the native Little Snitch-modeled Swift implementation.
- Both supported ports utilize a backend-agnostic stateless pf anchor (or WFP/nftables equivalent) allowing the root daemon to enforce rules by terminating localized ports without tracking remote IP addresses.

## Known Limits
- The current WFP and nftables configurations are not actively integrated; the Tauri app only displays demo data.
- The `DataSource` implementation can fail dynamically (e.g. if the daemon pipe crashes or IPC is lost). The `unwrap` instances on invalid data have been replaced with `Result<T, String>` to bubble up parsing and connectivity errors to the frontend safely instead of panicking.
