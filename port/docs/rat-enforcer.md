# rat-enforcer

The `rat-enforcer` crate provides a cross-platform interface for applying firewall rules. It reacts to a list of denied programs or local ports and applies necessary stateful rules on the machine to block their network access.

## Public API

The `Enforcer` trait abstracts away plan generation and application of the firewall rules.

```rust
use std::io;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Blocklist {
    /// List of denied application paths (for Windows).
    pub paths: Vec<String>,
    /// List of denied local ports (for Linux).
    pub local_ports: Vec<u16>,
}

pub trait Enforcer {
    type Plan;

    /// Generates a plan that represents the firewall state transitions without side effects.
    fn plan(&self, wanted: &Blocklist) -> Self::Plan;

    /// Applies the generated plan to the system.
    fn apply(&self, plan: &Self::Plan) -> io::Result<()>;
}

/// Validates that a path does not contain illegal characters used for command injection.
pub fn validate_path(path: &str) -> Result<String, &'static str>;
```

### Usage Example

```rust
use rat_enforcer::{Blocklist, Enforcer, validate_path};

#[cfg(not(windows))]
use rat_enforcer::linux::LinuxEnforcer;
#[cfg(windows)]
use rat_enforcer::windows::WindowsEnforcer;

fn main() -> std::io::Result<()> {
    let mut blocklist = Blocklist::default();

    let path = validate_path("/usr/bin/curl").map_err(|e| std::io::Error::other(e))?;
    blocklist.paths.push(path);
    blocklist.local_ports.push(8080);

    #[cfg(not(windows))]
    let enforcer = LinuxEnforcer;

    #[cfg(windows)]
    let enforcer = WindowsEnforcer { current: Blocklist::default() };

    let plan = enforcer.plan(&blocklist);
    enforcer.apply(&plan)?;

    Ok(())
}
```

## Platform Notes

### Linux (`nftables`)
The Linux backend drops outgoing and incoming connections based on the active local ports of the denied applications. It runs via the `nft -f` command, replacing an `inet rat` table containing `rat_ports`.
- **Requirements**: Needs `CAP_NET_ADMIN` (or root) to run `nft`. Requires `nftables` to be installed.
- **Limits**: Drops traffic by local ports only, not app paths, because of dependency and complexity. It means that `rat-enforcer` relies on an up-to-date `local_ports` list.

### Windows (Windows Defender Firewall)
The Windows backend generates individual rules per application path using `netsh advfirewall`. It implements a diff mechanism to only add or remove rules that have changed.
- **Requirements**: Needs Administrator privileges to run `netsh advfirewall`.
- **Port rules** (review-01 R5): the denied sockets' LOCAL ports are enforced too — one rule per (direction, protocol) per port (`dir=out|in`, `protocol=TCP|UDP`, `localport=N`), named `Rat:port:<n>` so one delete removes all four variants. This mirrors the Linux backend's `rat_ports` set (sport out / dport in) and the macOS Ledger's local-port blocks (Ledger.swift:330-332); it is also what a refused shared service host's denied socket gets instead of a silent no-op ("block by port instead").
- **Limits**: Per-program rules do not follow Electron helpers or versioned install paths (review-01 product note); inbound blocks are by local port only.

### Safety Notes
`apply` enforces for real by default (update-08 S7: a privileged enforcer that silently does nothing unless `RAT_ENFORCE=1` was set is its own misconfiguration). Tests and dry runs opt out explicitly with `RAT_DRY_RUN=1`, which makes `apply` print the commands instead of running them.
