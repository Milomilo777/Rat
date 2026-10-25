# rat-daemon

## Purpose
`rat-daemon` is the privileged background daemon component of the Rat network monitor port. It runs the whole
data path — monitor -> ledger -> policy (rule engine) -> enforcer — and serves unprivileged GUI clients over a
local IPC channel (Unix Domain Socket on Linux, Named Pipe on Windows).

## Public API

The crate exposes its internals for integration, but is primarily meant to be run as a standalone binary or service.
The main components are:
* `rat_daemon::msg::{ClientMessage, ServerMessage}`: the two IPC JSON-lines directions, versioned
  by `msg::PROTOCOL_VERSION`.
* `rat_daemon::core::run_pipeline`: the sampling/enforcement loop (monitor sample -> `rat_ledger::Ledger::ingest`
  under the `RuleEnginePolicy` -> alert fan-out -> enforcement plan -> `EnforcementBackend`), re-judging the last
  sample whenever a command arrives so SetRules/AlertAnswer take effect immediately.
* `rat_daemon::core::Command`: what IPC clients may ask the pipeline to do (`SetRules`, `AddRule`, `RemoveRule`, `AlertAnswer`).
* `rat_daemon::core::{EnforcementBackend, WindowsBackend, LinuxBackend}`: the enforcer seam — netsh advfirewall
  per-program rules plus per-port rules for the denied sockets' local ports (`Rat:port:<n>`) on
  Windows, the whole `inet rat` nft table on Linux.
* `rat_daemon::ipc::start_ipc_server`: asynchronous IPC listener handling framed JSON lines.
* `rat_daemon::run_components`: daemon shell — loads the saved rule set (`rat_core::RuleStore`, `RAT_RULES_FILE`
  or `%ProgramData%\rat\rules.json` / `/etc/rat/rules.json`), RECONCILES the firewall at startup (read back the
  daemon's own `Rat:path:*` and `Rat:port:*` rules, adopt them as the diff baseline, enforce the saved plan's
  static anchor — never wipe-then-apply) all BEFORE the IPC endpoint serves, then pipeline
  + IPC until shutdown. A clean stop KEEPS the rules (macOS persistent-anchor parity): enforcement
  stays active while the daemon is down and the next startup reconciles. `run_daemon` is the production wiring;
  `run_cleanup` backs the uninstall path (`rat-daemon --cleanup`), the ONLY full removal (both rule families).

## IPC protocol (v1)

Line-delimited JSON. **The FIRST client message must be `Hello`**; the server answers
`HelloAck` (version matched) or `Error` + close (mismatch), and pushes NO server messages before the handshake
completed. A client that does not handshake within 10 s is dropped. Bump `PROTOCOL_VERSION` on breaking changes.

Client -> server:
```json
{"Hello":{"protocol_version":1}}
{"SetRules":{"rules":[ ...rat-core v2 rule objects (camelCase)... ]}}
{"AddRule":{"rule":{ ...one rat-core v2 rule object (camelCase)... }}}
{"RemoveRule":{"id":"6ec0bd7f-11d0-4c7d-a9bf-96f16b1c3f2c"}}
"GetRules"
{"AlertAnswer":{"id":7,"verdict":"deny","scope":"any","lifetime":"forever"}}
```
* `GetRules` (a plain string, no fields) asks for the current in-memory rule set. The daemon answers with
  `Rules`, taken from the pipeline's rule engine, never from the rules file; so a client does not need (and must
  not use) read access to the rules directory. Session rules (once / until quit) are included. The answer goes
  out on the same broadcast as snapshots, so every handshaked client sees it. Additive: protocol version stays 1,
  existing messages are unchanged.
* A client line is limited to 64 KiB (65536 bytes); a longer line (for example a very large `SetRules`) makes the
  daemon drop that connection. Clients check the size before sending.
* `SetRules` replaces the daemon's rule set wholesale; the rules are the same JSON the Swift app persists
  (`rat_core::Rule`, camelCase). Runs of queued `SetRules` coalesce to the newest list.
* `AddRule` / `RemoveRule` are incremental edits (additive: protocol version stays 1; a daemon without them
  drops the connection on the unknown variant). `AddRule` upserts by rule id (a new id is appended, the same id
  replaces that rule in place, an identical re-delivery changes nothing), so a client retry never duplicates.
  `RemoveRule` removes by id; an unknown id is logged and ignored. Both are applied in arrival order (they stop
  the `SetRules` coalescing drain, never reordered around it), keep every other rule, and are saved like
  `SetRules`. Neither sends a reply: ask with `GetRules` afterwards (same connection, so ordered).
* `AlertAnswer` answers the `AlertRequest` with the matching `id` (stale ids are ignored). `scope` is one of
  `any` | `domain` | `host` | `port` (`rat_ledger::AnswerScope`); `verdict` is `allow` | `deny` | `ask`;
  `lifetime` is `once` | `untilQuit` | `forever`. The answer creates a rule exactly like the macOS
  `RulesModel.addRule(from:verdict:scope:lifetime:)` port in rat-ledger.

Server -> client:
```json
{"HelloAck":{"protocol_version":1}}
{"Snapshot":{"connections":[ ...rat-types Connections... ]}}
{"AlertRequest":{"id":7,"alert":{"app":"...","app_name":"...","host":"...","remote":"203.0.113.9:443", ...}}}
{"Error":{"message":"..."}}
{"Rules":{"rules":[ ...rat-core v2 rule objects... ]}}
{"AlertCleared":{"id":7}}
```
* `Rules` answers `GetRules`. `AlertCleared` is pushed when the alert with that `id` is no longer pending
  (answered, or gone); a client may keep showing an alert it answered until this arrives. Both are new server
  messages: a client that cannot parse them must ignore unknown lines (the desktop app does).
* `Snapshot` is pushed after every sampling pass (1.5 s) and after every applied command.
* `AlertRequest` goes out once per NEW current alert (one prompt per app|domain key until answered, AlertCenter
  parity); the id must be echoed back in `AlertAnswer`.

### Example usage (Client side receiving Snapshot)

```rust
use rat_daemon::msg::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};
use futures::{SinkExt, StreamExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = UnixStream::connect("/run/rat/rat.sock").await?;
    let (r, w) = tokio::io::split(stream);
    let mut writer = FramedWrite::new(w, LinesCodec::new());
    let mut reader = FramedRead::new(r, LinesCodec::new_with_max_length(10 * 1024 * 1024));

    writer.send(serde_json::to_string(&ClientMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
    })?).await?;
    // first reply is HelloAck or Error (then the server closes)
    let _ack: ServerMessage = serde_json::from_str(&reader.next().await.unwrap()?)?;

    while let Some(Ok(line)) = reader.next().await {
        let msg: ServerMessage = serde_json::from_str(&line)?;
        if let ServerMessage::Snapshot { connections } = msg {
            println!("Received {} connections", connections.len());
        }
    }
    Ok(())
}
```

## Enforcement model
* The ledger recomputes its `EnforcementPlan` on every pass: whole apps by exe path and the LOCAL ports of
  rule-denied sockets — never server addresses (Ledger.swift parity). `<unknown>` (no visible exe) is never
  sent to the enforcer.
* Whole-program blocks come only from unscoped, enabled deny rules (no domain, host, address, port or protocol)
  of the active profile and the enabled groups (`static_blocklist`). A scoped deny rule never blocks the whole
  app; it is enforced per connection through the local ports of the sockets it denies.
* Windows: `netsh advfirewall` per-program rules, diffed against the backend's applied state (no churn per tick);
  whole-program blocks of shared service hosts (`SHARED_SERVICE_HOSTS` in rat-enforcer: svchost.exe, dllhost.exe,
  RuntimeBroker.exe and others) are REFUSED. Local ports are the Linux axis.
* Every firewall tool child (netsh, PowerShell, nft) runs under `rat_enforcer::run_with_timeout` and is killed
  after `TOOL_TIMEOUT` (30 s), so a hung tool cannot stall the pipeline or the start-up read-back.
* Linux: the whole `inet rat` nft table is rebuilt on change, so a closed socket's local port drops out of the
  next diff (no stale per-port rule).
* `RAT_DRY_RUN=1` keeps every enforcer call a printed no-op. Without it the enforcer really applies its rules.
* A failed apply leaves the backend's applied state behind, so the next tick retries the same diff; the pipeline
  logs and continues (one read hiccup must not become an enforcement outage).
* The enforcer crate owns that `current` state — `Enforcer::apply` is `&mut self`, advances
  `current` on success and leaves it behind on failure; the daemon no longer patches it by hand, and the
  enforcer's delete-before-add makes a retried (or read-back-missed) re-apply idempotent instead of
  duplicating netsh rules.

## Platform Notes
* **Linux**:
  * Needs root to initially write to `/run/rat/rat.sock`, or `/run/rat/` directory must be writable by the user running the daemon.
  * The socket file is created with `0o660` permissions; a directory the daemon creates is `0o750`.
  * Clients are checked with SO_PEERCRED: root, the daemon's own uid, or the `rat` group (override with
    `RAT_IPC_GROUP`); `peer_cred()` errors fail closed.
  * Stops gracefully on `SIGTERM` and `SIGINT`, cleaning up the socket file. The nft table stays in place when the
    daemon stops or crashes, so blocks keep working (the unit has no ExecStopPost); `Restart=on-failure` restarts
    the daemon and the next start reconciles. `rat-daemon --cleanup` removes the table.
* **Windows**:
  * Runs as a Windows Service by default. Service mode requires administrative privileges to install.
  * Creates a named pipe `\\.\pipe\rat` with protected DACL
    `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)` : SYSTEM/Administrators full, Interactive Users
    read/write only.
  * Per-client identity : before a connection reaches a handler, the daemon reads the client
    process's primary token (`GetNamedPipeClientProcessId` -> `OpenProcessToken`) and admits only the daemon's
    own user or a member of Builtin Administrators; every FFI error fails closed.
  * The rules directory (`%ProgramData%\rat`) is created with a protected SYSTEM + Administrators DACL. An
    existing directory owned by SYSTEM or Administrators (and not a reparse point) gets the same protected DACL
    re-applied; if that fails, or the owner is anyone else, the directory is not used and rules are not saved.
  * Silent-disable watch (`fw_status`): once a minute the daemon reads (never changes) the Defender Firewall
    profiles with `Get-NetFirewallProfile` as JSON (30 s tool timeout). A change is logged once; while a profile
    is off, an `Error` message "Windows Firewall is turned off for: ..." goes out on every pass so a client that
    connects later sees it too (the desktop app shows it as the connection detail), and a message follows when
    all profiles are on again. A profile that policy leaves "not configured" is never reported as off.
* **Both**: a second daemon refuses to start while the endpoint is owned by a live one;
  concurrent clients are capped at 4; inbound lines cap at 64 KiB.

## Known Limits
* Reverse-DNS display names (`ConnectionDetails.host_name`), ASN `network_owner`, VPN/proxy marks and GeoIP
  country are not filled yet — the details closure only wires the std-only parts (well-known service names from
  rat-names, shared-service-host classification). rDNS needs an async resolver with a cache, not a blocking
  lookup inside the pipeline.
* The rule set is persisted daemon-side: every SetRules/AddRule/RemoveRule/AlertAnswer-created rule is
  written back to the store (`save_set` keeps Forever rules only — UntilQuit session rules die with the daemon),
  reloaded at the next startup, and its static anchor is reconciled into the firewall before the IPC serves.
  The GUI no longer has to re-send the rules at startup (it still may: SetRules is authoritative when it does).
  A save writes a temporary file with an unpredictable name next to `rules.json`, keeps the previous content as
  `rules.json.bak` and renames the temporary file over `rules.json` (atomic). A crash in between leaves
  `rules.json.<32 hex>.tmp`; start-up removes exactly that naming (regular files only) when the directory is
  trusted, never any other file. On Windows the daemon creates the
  parent directory (see above); on Linux create `/etc/rat` first (see the Linux install guide). A failed save is
  logged and retried on the next change, never fatal.
* IPC drops clients that lag too much instead of buffering infinitely.
* Malformed JSON messages are rejected with an `Error` response but won't cause the server to crash.
