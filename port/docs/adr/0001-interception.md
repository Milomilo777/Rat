# Traffic Interception Mechanisms for Windows and Linux

## Context and Problem Statement

Rat is a reactive application firewall and network monitor on macOS. The goal is to port Rat to Windows and Linux, supporting both Version 1 (reactive, matching the macOS app's current capabilities) and Version 2 (pre-connection prompt, intercepting and pending connections like Little Snitch). We must evaluate available intercept and filtering technologies to choose the right mechanisms for both platforms and phases.

**Update for v1.2.0:** Rat never blocks remote addresses, as an address is shared by every app (including DNS). Instead, the macOS version blocks the **local ports** of every socket that belongs to a denied app. The chosen mechanisms for Windows and Linux must support this approach for Version 1.

## Decision Drivers

* **Pend connection capability:** Version 2 requires holding a connection while a user prompt is displayed.
* **Local port blocking (v1.2.0 compatibility):** Version 1 must block by the local port of the socket rather than the remote destination address, to prevent collateral damage to other apps.
* **Driver signing requirements (Windows):** Kernel drivers require an EV Code Signing certificate and Microsoft attestation signing.
* **License compatibility:** Mechanisms should be MIT-compatible where possible, or avoid restrictive copyleft (GPL) if statically linked.
* **Admin requirements:** User-mode versus kernel-mode deployment complexity.
* **Maintenance and ecosystem:** Active development, stability, and release cadence.

## Considered Options

* **OpenSnitch (Linux):** Uses `nfqueue` + eBPF.
* **Portmaster (Windows/Linux):** Uses a Windows kernel driver (kext) and Linux `nfqueue`.
* **simplewall (Windows):** Uses the Windows Filtering Platform (WFP) from user mode.
* **TinyWall (Windows):** Uses WFP to block outbound by default and whitelist apps.
* **WinDivert (Windows):** Bundles a WFP callout driver with a user-mode API.
* **Windows Firewall (Windows):** Built-in "block outbound by default" with allow rules.

## Evaluation of Options

### OpenSnitch (Linux)
* **Mechanism:** `nfqueue` + eBPF.
* **Local Port Blocking:** Yes. `nfqueue` can match on local ports, or drop packets originating from a specific PID (via eBPF).
* **Pend connection:** Yes, `nfqueue` allows userspace to hold packets and issue a verdict later.
* **Privileges:** Requires root / `CAP_NET_ADMIN`. No driver signing needed.
* **License:** GPLv3.
* **Last release:** 2025-12-15.
* **Link:** https://github.com/evilsocket/opensnitch

### Portmaster (Windows/Linux)
* **Mechanism:** Windows kernel driver + Linux `nfqueue`.
* **Local Port Blocking:** Yes.
* **Pend connection:** Yes, the custom kernel driver pauses connections for user prompts.
* **Privileges:** Requires kernel driver installation (EV cert + Microsoft attestation signing).
* **License:** GPLv3.
* **Last release:** 2026-08-14 (Main), 2023-08-17 (Windows kext).
* **Link:** https://github.com/safing/portmaster

### simplewall (Windows)
* **Mechanism:** Windows Filtering Platform (WFP) user-mode API.
* **Local Port Blocking:** Yes. WFP rules can be configured to block specific local ports or drop traffic from specific app paths using the `FWPM_CONDITION_ALE_APP_ID` condition.
* **Pend connection:** No, standard user-mode WFP drops or allows based on rules. It doesn't hold packets for a prompt without a callout driver.
* **Privileges:** Requires Admin rights to add WFP filters.
* **License:** GPLv3.
* **Last release:** 2025-08-08.
* **Link:** https://github.com/henrypp/simplewall

### TinyWall (Windows)
* **Mechanism:** WFP user-mode API.
* **Local Port Blocking:** Yes.
* **Pend connection:** No. It blocks outbound by default and waits for the user to whitelist apps.
* **Privileges:** Requires Admin rights.
* **License:** Freeware / Proprietary.
* **Last release:** Active development.
* **Link:** https://tinywall.pados.hu/

### WinDivert (Windows)
* **Mechanism:** Pre-compiled WFP callout driver with user-mode DLL.
* **Local Port Blocking:** Yes.
* **Pend connection:** Yes, diverts packets to user-mode where they can be held, modified, or dropped.
* **Privileges:** Requires Admin rights to load the driver. Pre-signed binaries exist, but for production use without AV flags, a self-signed driver (requiring EV cert and MS attestation) is usually needed.
* **License:** LGPL.
* **Last release:** 2022-09-21.
* **Link:** https://github.com/basil00/WinDivert

### Windows Firewall (Windows)
* **Mechanism:** Native firewall rules API.
* **Local Port Blocking:** Yes.
* **Pend connection:** No.
* **Privileges:** Admin rights to modify rules.
* **License:** N/A (OS built-in).

## Decision Outcome

### Version 1 (Reactive)
For Version 1, which mimics the macOS reactive approach:
* **Windows:** Use **WFP from user mode** (similar to simplewall). It requires admin privileges but no kernel drivers, avoiding the EV certificate and attestation signing requirements. To align with Rat v1.2.0, WFP filters will be configured to target specific applications via `FWPM_CONDITION_ALE_APP_ID` (process path matching), which naturally isolates the block to the denied app without needing to enumerate and block its individual local ports.
  > **Amended 2026-10-25 (V1):** superseded by `netsh advfirewall` per-program rules — the shipped
  > `rat-enforcer` backend. See "Amendment 2026-10-25" at the end of this document.
* **Linux:** Use **eBPF or netlink socket polling** for monitoring, and **iptables/nftables** rules for enforcement. To align with Rat v1.2.0, nftables rules can be updated dynamically to drop traffic originating from specific local ports or via cgroup matching (`meta cgroup` paths, not raw PIDs - netfilter cannot match PIDs; per-PID attribution needs eBPF).

### Version 2 (Pre-connection prompt)
For Version 2, which requires holding connections:
* **Windows:** Use a **WFP callout driver** (either building a custom one or using WinDivert). This provides the ability to pend connections. *Consequence:* This will require an EV Code Signing certificate and Microsoft attestation signing via the Hardware Dev Center.
* **Linux:** Use **nfqueue**. It is a native mechanism for sending packets to userspace for a verdict, requiring no custom kernel modules, only standard root privileges.

### Consequences

* **Good:** Version 1 can be shipped quickly without going through Microsoft's driver signing process.
* **Good:** Linux implementation for Version 2 is straightforward and uses built-in kernel features (`nfqueue`).
* **Bad:** Windows Version 2 will have a high barrier to entry due to the cost and complexity of obtaining an EV certificate and Microsoft attestation signing for the WFP callout driver.

## Implementation Details

### Windows WFP Setup (User-Mode)
To implement Version 1 enforcement on Windows using the Windows Filtering Platform (WFP), the following setup is recommended:

*   **Provider and Sublayer:** Create a dedicated WFP Provider and a high-weight custom Sublayer (e.g., `FWPM_SUBLAYER_WEIGHT_MAX`) so Rat's rules take precedence over standard filters.
    *   *Docs:* [Providers](https://learn.microsoft.com/en-us/windows/win32/fwp/providers), [Sublayers](https://learn.microsoft.com/en-us/windows/win32/fwp/sublayers)
*   **Layers:** Hook into `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6` to control outbound TCP connections, and `ALE layering note (corrected 2026-10-25: `FWPM_LAYER_ALE_AUTH_SEND_RECV_V4/V6` does not exist). Outbound UDP is authorized at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`V6` (each connect/sendto to a new peer); inbound authorization uses `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`/`V6`.
    *   *Docs:* [ALE Layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
*   **App Identification / Process Blocking:** Use `FwpmGetAppIdFromFileName0` to derive the `FWP_BYTE_BLOB` for matching a process by its executable path. Use the `FWPM_CONDITION_ALE_APP_ID` filter condition to drop connections directly from the denied app, fulfilling the v1.2.0 requirement to isolate blocking per app without blocking remote addresses.
    *   *Docs:* [FwpmGetAppIdFromFileName0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0)
*   **Persistence:** Use Dynamic Sessions (`FWPM_SESSION_FLAG_DYNAMIC`) for rules so they automatically clean up if Rat crashes.
    *   *Docs:* [Object Management (Dynamic Sessions)](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)

### Linux nftables / nfqueue Setup
To implement Version 2 (and V1 enforcement) on Linux, the following setup is recommended:

*   **Base Table & Chain:** Create an `nftables` family `inet` (or separate `ip`/`ip6`) table with a base chain hooked to the `output` hook.
    *   *Docs:* [nftables Base chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain)
*   **Local Port Blocking (v1.2.0 compatibility):** For v1 (reactive), dynamically generate `nftables` rules that drop traffic matching `tcp sport { port1, port2 }` or `udp sport { port1, port2 }`, corresponding to the sockets held by denied apps.
    *   *Docs:* [nftables Match expression (sport)](https://wiki.nftables.org/wiki-nftables/index.php/Matching_transport_protocol)
*   **Queue Target:** Use the `queue` statement to divert matching outbound traffic to userspace via `nfqueue`.
    *   Example rule: `nft add rule inet filter output ct state new tcp dport { 80, 443 } queue num 1  # ct state new: without it every packet of a flow is queued`
    *   *Docs:* [nftables queueing to userspace](https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace)
*   **Userspace Handling:** A daemon binds to the netlink queue (e.g., queue number 1). It reads the packet, correlates it with a socket/process using Netlink/procfs, holds it while a user prompt is active (V2), and issues an `NF_ACCEPT` or `NF_DROP` verdict.
    *   *Docs:* [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/)

## Linux Prototype (Spike) Results
A spike was attempted to build a small Rust program in `port/spikes/linux-prompt/` that uses `nfqueue` inside a network namespace (`unshare -n -r`).
However, the required netfilter kernel modules (`nftables`, `nfnetlink_queue`, `iptable_filter`) are not loaded or not permitted in the current container/VM environment.
Attempting to insert a rule via `iptables` resulted in:
`Warning: Extension NFQUEUE revision 0 not supported, missing kernel module?`
`iptables v1.8.10 (nf_tables):  RULE_APPEND failed (No such file or directory): rule in chain OUTPUT`

Attempting to insert via `nft` resulted in:
`Error: Could not process rule: Operation not supported`
`add table inet filter`

Consequently, the spike was stopped as the environment forbids the needed privileges and lacks the required kernel modules for nfqueue interception.

## Windows WFP Prototype (Spike) Results
A compile-only spike was created in `port/spikes/windows-wfp/`. It uses the `windows` crate to call the WFP API (`FwpmEngineOpen0`, `FwpmFilterAdd0`, etc.).

**How to run on real Windows:**
1. Compile the binary for Windows (`cargo build --release --target x86_64-pc-windows-gnu` or `msvc`).
2. Open an **Administrator** command prompt (required to open the WFP engine via `FwpmEngineOpen0`).
3. Run the compiled executable `windows-wfp.exe`.
4. While the program is running and waiting at the "Press Enter" prompt, open a regular command prompt and try running `curl.exe https://example.com`.
5. **Observation:** The `curl` command should fail (e.g., connection timed out or blocked) because the program actively blocks outbound TCP connections from `curl.exe` at the `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `V6` layers.
6. Press Enter in the spike window to exit. The spike uses a dynamic session (`FWPM_SESSION_FLAG_DYNAMIC`), so Windows will automatically clean up and remove the provider, sublayer, and filters upon exit.
7. Attempt the `curl.exe` command again, and it should succeed.

**Learnings:**
* WFP API in Rust (via the `windows` crate) is extremely verbose due to the complex C-struct setup (e.g., unions for `FWP_CONDITION_VALUE0`).
* Utilizing a dynamic session (`FWPM_SESSION_FLAG_DYNAMIC`) is highly recommended for Rat's enforcement. It eliminates the need to manually clean up rules if Rat crashes, preventing the firewall from being left in a permanently broken state.
* App-ID mapping via `FwpmGetAppIdFromFileName0` integrates perfectly into the V1 requirement of blocking by process path rather than remote IP.

> **Note (2026-10-25):** this spike is COMPILE-ONLY. It was checked to compile for
> `x86_64-pc-windows-gnu` and was never executed - it was written on Linux without admin. The run steps
> above are prospective and the "Learnings" beyond verbosity are UNVERIFIED claims. `port/spikes/windows-wfp`
> pins `windows = 0.58.0`; the integrated workspace uses `windows 0.52.0` (rat-monitor-windows) and
> `windows-sys 0.59` (rat-daemon).

## Amendment 2026-10-25

**V1 Windows enforcement backend = `netsh advfirewall` per-program rules** — the backend `rat-enforcer`
ships today (`port/crates/rat-enforcer/src/windows.rs`). The WFP user-mode decision above is superseded
for V1 and kept as the documented upgrade path. The original text is retained for the record. Rationale,
with evidence:

1. **macOS parity is persistent firewall state, not auto-cleanup.** On macOS the pf anchor
   `com.apple/rat` lives in the system firewall across process deaths: `rat-enforcerd` is a LaunchDaemon
   with `KeepAlive=true` (App/Model/Enforcer.swift:144), the daemon only trusts the denied-ports file
   while it is fresh ("a crashed Rat must not leave ports blocked", :110-111), and the anchor is cleared
   only on "Remove Helper" (`pfctl -a com.apple/rat -F all`, :179). Persistent netsh rules + `Enforcer::cleanup()`
   (windows.rs, `Rat:path:*` wildcard removal, run by `rat-daemon --cleanup`) reproduce this model: blocks
   keep working while the daemon is down, and the next start reconciles the firewall with the saved rules. A dynamic WFP session would DIVERGE
   from macOS: any enforcer crash silently un-blocks everything (fail-open).
2. **The V1 per-app requirement is already met without WFP.** `netsh advfirewall firewall add rule
   program="..."` scopes the block to the denied executable (the Windows analogue of `ALE_APP_ID`),
   so the v1.2.0 isolation property holds; per-program rules also have no recycled-local-port exposure
   (recycled local ports are a Linux-only concern). The crate is std-only ([dependencies] empty), hardened
   (absolute-path resolution from %SystemRoot%, dry-run opt-out, refusal of whole-program blocks of shared
   service hosts), and exercised by real-OS end-to-end tests on GitHub Actions runners (Windows and Linux).
3. **Cost/risk of a WFP port now is high and unverifiable here.** It means porting unexecuted unsafe
   FFI (FWP_VALUE0/FWP_CONDITION_VALUE0 unions, byte-blob lifetimes) into the enforcement path, adding
   a `windows`-crate dependency to a std-only crate (with the version-mix question noted above), and
   it can only be exercised with administrator rights (adding filters requires admin). The unit tests of the
   enforcer run with `RAT_DRY_RUN=1`; the real `netsh` apply is covered by the end-to-end suite on a Windows
   runner. netsh runtime behavior is a documented Windows facility.
4. **V2 supersedes a user-mode WFP backend anyway.** Per the Decision Outcome above, Windows V2
   (pend connection) requires a WFP callout driver with EV signing and Microsoft attestation. A
   user-mode WFP V1 backend would be throwaway work at that point; netsh keeps V1 cheap and is
   cleanly replaced.

Tradeoffs accepted: netsh rules persist across crashes and clean stops, so blocks stay in force until the
daemon next starts. The daemon does not wipe the rules at startup (that would open a fail-open window); it
reads back its own `Rat:*` rules and reconciles them with the saved rule set. Full removal is
`rat-daemon --cleanup`, the uninstall path (parity with `pfctl -F all`). The rule namespace stays `Rat:path:*`; whole-program blocks of shared service hosts
stay refused. Per-service scoping does not require WFP:
`netsh advfirewall` supports `service=<short name>` compound rules — UNVERIFIED here, verify on an
admin runner when wiring. If the stale-block window ever proves unacceptable, the WFP dynamic-session
port remains the fallback and this amendment gets revisited.

