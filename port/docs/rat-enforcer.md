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

    /// Applies the generated plan to the system. Owns the enforcer's view of
    /// the current state: advances `current` to the applied outcome on
    /// success, leaves it behind on failure.
    fn apply(&mut self, plan: &Self::Plan) -> io::Result<()>;
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
    let mut enforcer = WindowsEnforcer { current: Blocklist::default(), runner: None };

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
The Windows backend generates individual rules per application path using `netsh advfirewall`: two rules per program under one name `Rat:path:<path>` (`dir=out` and `dir=in`, both `action=block`), so one delete by name removes both and the start-up read-back sees the program once per rule (it sorts and deduplicates). When `Rat:path:<path>` would be longer than 200 characters (`RULE_NAME_MAX`; Microsoft documents no limit for the rule name and netsh's own limit is unverified, so the value is conservative) the name is `Rat:path:#<32 hex of SHA-256(path)>` instead; the full path is always the rules' `program=` field, which is what the read-back returns. It implements a diff mechanism to only add or remove rules that have changed.
- **Requirements**: Needs Administrator privileges to run `netsh advfirewall`.
- **Port rules**: the denied sockets' LOCAL ports are enforced too — one rule per (direction, protocol) per port (`dir=out|in`, `protocol=TCP|UDP`, `localport=N`), named `Rat:port:<n>` so one delete removes all four variants. This mirrors the Linux backend's `rat_ports` set (sport out / dport in) and the macOS Ledger's local-port blocks (Ledger.swift:330-332); it is also what a refused shared service host's denied socket gets instead of a silent no-op ("block by port instead").
- **Idempotent apply, no gap**: netsh `add rule` DUPLICATES a rule whose display name already exists, so `apply` first probes `show rule name=<n>` (exit code, locale-stable; path and port axis). Name absent: add the rules, then sweep a leftover `Rat:tmp:` name. Name present: add the new rules under the temporary name `Rat:tmp:<rest of the name>` (delete a leftover one first), delete the old rules by name, then `set rule name=<tmp> new name=<n>`. The temporary name is `Rat:tmp:#<32 hex of SHA-256(name)>` when the plain form would pass 200 characters. At every step a block is in place; a failure leaves the old or the temporary block and `current` behind, so the next diff retries. A path that fails to install does not stop the other paths: the loop goes on, the failed path stays out of `current` and the first error is returned at the end. The cleanup wildcard includes `Rat:tmp:*`; the read-back does not. On success `apply` advances the enforcer's `current` to the applied state — using the validated names the rules were created under — so re-planning an unchanged wanted state is an empty diff and a stale diff (restart with a failed read-back, a canonicalized rename) re-applies without duplicating. On failure `current` stays behind so the next diff retries the same change.
- **Reconcile deletes tolerate no-match**: the remove loops (path and port axis) must survive a rule the user or GPO already deleted — netsh answers that delete with exit 1 "No rules match the specified criteria". `apply` captures the child's output and treats exactly that exit as success (the verified-gone entry also leaves `current`, so the diff does not retry it); any other delete failure still aborts fail-closed. On a non-English Windows the message differs, so such a delete fails as before (no regression).
- **Test seam**: `WindowsEnforcer.runner: Option<NetshRunner>` — when set, every `apply` command is routed through the injected executor instead of spawning netsh (the dry-run flag is not consulted; the seam owns execution). The crate's tests inject a fake that models netsh's real duplicate-on-add semantics to pin "apply twice -> live rule count == plan size"; on `delete rule` commands its `Ok(false)` models the no-match exit (tolerated) and a real failure is `Err`.
- **`cleanup()` empties the in-memory state**: `Enforcer::cleanup` takes `&mut self`; after a successful Windows cleanup `current` is empty again (a failed cleanup leaves it), so a later plan re-adds what it wants instead of assuming the removed rules still exist. The Linux enforcer holds no state.
- **One invalid path is reported and skipped, never fatal**: `validate_path` accepts `'` (a legal Windows filename character; no shell is involved — netsh is spawned via `Command::args`), and its rejection rules (`"`, `;`, CR, LF, relative, `..`, and UNC/device/verbatim prefixes `\\host`, `\\?\`, `\\.\`, checked as plain string work BEFORE any canonicalisation, which on a UNC target would do network I/O) live in `path_validation_error`, the exact apply() rejection set. `generate_windows_plan` reports entries failing those rules in `WindowsPlan.rejected` (like `refused`, the caller tells the user): an invalid wanted path never becomes a rule, an invalid current path (e.g. a hostile hand-made `Rat:path:*` rule name from the read-back) never enters `remove` — it stays in `current` (no diff churn) and only the uninstall cleanup removes it. `apply` partitions BOTH axes the same way, so a hand-built plan also cannot be bricked by one bad entry; no rule is ever created from or deleted by an unvalidated string, and the shared-host refusal remains the one whole-plan abort (it refuses to create a dangerous rule). The rule checks are byte scans — plan() runs them per path per tick and the char-pattern iterators measured ~4µs/path in a debug build.
- **Tool time limit**: netsh and PowerShell (and nft on Linux) run through `run_with_timeout`: stdout/stderr are captured by reader threads, the child is killed and reaped at `TOOL_TIMEOUT` (30 s) with a `TimedOut` error naming the tool and the limit; `tool_failure` puts a failed tool's own stderr into the error.
- **Limits**: Per-program rules do not follow Electron helpers or versioned install paths.

### Safety Notes
`apply` enforces for real by default (a privileged enforcer that silently does nothing unless an opt-in variable is set would be its own misconfiguration). Tests and dry runs opt out explicitly with `RAT_DRY_RUN=1`, which makes `apply` print the commands instead of running them.
