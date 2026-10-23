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
* **Local Port Blocking:** Yes. WFP rules can be configured to block specific local ports or drop traffic from specific PIDs using the `FWPM_CONDITION_ALE_APP_ID` condition.
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
* **Linux:** Use **eBPF or netlink socket polling** for monitoring, and **iptables/nftables** rules for enforcement. To align with Rat v1.2.0, nftables rules can be updated dynamically to drop traffic originating from specific local ports or via cgroups/skb matching for specific process IDs.

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
*   **Layers:** Hook into `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6` to control outbound TCP connections, and `FWPM_LAYER_ALE_AUTH_SEND_RECV_V4`/`V6` for UDP.
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
    *   Example rule: `nft add rule inet filter output tcp dport { 80, 443 } queue num 1`
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
