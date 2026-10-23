# Traffic Interception Mechanisms for Windows and Linux

## Context and Problem Statement

Rat is a reactive application firewall and network monitor on macOS. The goal is to port Rat to Windows and Linux, supporting both Version 1 (reactive, matching the macOS app's current capabilities) and Version 2 (pre-connection prompt, intercepting and pending connections like Little Snitch). We must evaluate available intercept and filtering technologies to choose the right mechanisms for both platforms and phases.

## Decision Drivers

* **Pend connection capability:** Version 2 requires holding a connection while a user prompt is displayed.
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
* **Pend connection:** Yes, `nfqueue` allows userspace to hold packets and issue a verdict later.
* **Privileges:** Requires root / `CAP_NET_ADMIN`. No driver signing needed.
* **License:** GPLv3.
* **Last release:** 2025-12-15.
* **Link:** https://github.com/evilsocket/opensnitch

### Portmaster (Windows/Linux)
* **Mechanism:** Windows kernel driver + Linux `nfqueue`.
* **Pend connection:** Yes, the custom kernel driver pauses connections for user prompts.
* **Privileges:** Requires kernel driver installation (EV cert + Microsoft attestation signing).
* **License:** GPLv3.
* **Last release:** 2026-08-14 (Main), 2023-08-17 (Windows kext).
* **Link:** https://github.com/safing/portmaster

### simplewall (Windows)
* **Mechanism:** Windows Filtering Platform (WFP) user-mode API.
* **Pend connection:** No, standard user-mode WFP drops or allows based on rules. It doesn't hold packets for a prompt without a callout driver.
* **Privileges:** Requires Admin rights to add WFP filters.
* **License:** GPLv3.
* **Last release:** 2025-08-08.
* **Link:** https://github.com/henrypp/simplewall

### TinyWall (Windows)
* **Mechanism:** WFP user-mode API.
* **Pend connection:** No. It blocks outbound by default and waits for the user to whitelist apps.
* **Privileges:** Requires Admin rights.
* **License:** Freeware / Proprietary.
* **Last release:** Active development.
* **Link:** https://tinywall.pados.hu/

### WinDivert (Windows)
* **Mechanism:** Pre-compiled WFP callout driver with user-mode DLL.
* **Pend connection:** Yes, diverts packets to user-mode where they can be held, modified, or dropped.
* **Privileges:** Requires Admin rights to load the driver. Pre-signed binaries exist, but for production use without AV flags, a self-signed driver (requiring EV cert and MS attestation) is usually needed.
* **License:** LGPL.
* **Last release:** 2022-09-21.
* **Link:** https://github.com/basil00/WinDivert

### Windows Firewall (Windows)
* **Mechanism:** Native firewall rules API.
* **Pend connection:** No.
* **Privileges:** Admin rights to modify rules.
* **License:** N/A (OS built-in).

## Decision Outcome

### Version 1 (Reactive)
For Version 1, which mimics the macOS reactive approach:
* **Windows:** Use **WFP from user mode** (similar to simplewall). It requires admin privileges but no kernel drivers, avoiding the EV certificate and attestation signing requirements.
* **Linux:** Use **eBPF or netlink socket polling** for monitoring, and **iptables/nftables** rules for enforcement.

### Version 2 (Pre-connection prompt)
For Version 2, which requires holding connections:
* **Windows:** Use a **WFP callout driver** (either building a custom one or using WinDivert). This provides the ability to pend connections. *Consequence:* This will require an EV Code Signing certificate and Microsoft attestation signing via the Hardware Dev Center.
* **Linux:** Use **nfqueue**. It is a native mechanism for sending packets to userspace for a verdict, requiring no custom kernel modules, only standard root privileges.

### Consequences

* **Good:** Version 1 can be shipped quickly without going through Microsoft's driver signing process.
* **Good:** Linux implementation for Version 2 is straightforward and uses built-in kernel features (`nfqueue`).
* **Bad:** Windows Version 2 will have a high barrier to entry due to the cost and complexity of obtaining an EV certificate and Microsoft attestation signing for the WFP callout driver.
