# Lane Report: research-interception

## Requirements Map
| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1: Research interception mechanisms | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R2: Compare OpenSnitch, Portmaster, simplewall, TinyWall, WinDivert, Windows Firewall | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R3: Recommend one mechanism per OS for v1 and v2 | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R4: Detail exact WFP and nftables/nfqueue setups | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |

## Actions Taken
* Read context and problem descriptions, including `README.md`, `CLAUDE.md`, and `docs/ARCHITECTURE.md`.
* Investigated various interception mechanisms and tools: OpenSnitch, Portmaster, simplewall, TinyWall, WinDivert, and Windows Firewall.
* Authored `port/docs/adr/0001-interception.md` containing the MADR 4.0 format decision record evaluating the options for both platforms (Windows and Linux) and both phases (Version 1 - reactive; Version 2 - pre-connection).
* Generated this report in `port/reports/research-interception.md`.
* Updated `port/docs/adr/0001-interception.md` with a follow-up section detailing the exact WFP and nftables/nfqueue setups, with official documentation links.

## Decisions and Reasons
* **Decision:** Excluded the creation of the Rust boilerplate code files (`port/Cargo.toml` and `port/crates/rat-types/*`).
  * **Reason:** This lane (`research-interception`) is explicitly described as a "report-only lane, no code". Furthermore, the instructions strictly mandate: "Touch ONLY the paths your lane names. Do not edit any other file (no README, CLAUDE.md, CHANGELOG, root files, other lanes' folders)." The allowed paths were specifically limited to `port/docs/adr/0001-interception.md` and `port/reports/research-interception.md`. Creating other files would violate these constraints.
* **Decision:** Recommended Windows Filtering Platform (WFP) user-mode for Windows V1, and WFP callout driver for Windows V2. Recommended eBPF/netlink for Linux V1, and nfqueue for Linux V2.
  * **Reason:** This approach allows for a faster rollout of V1 without kernel driver signing hurdles, while preserving a clear path to V2 capabilities (pending connections) using native or well-established driver architectures.
* **Decision:** Detailed specific WFP API elements (FwpmGetAppIdFromFileName0, Dynamic Sessions, ALE layers) and nftables queues.
  * **Reason:** To guide developers directly to the necessary components and their official documentation without ambiguity, addressing R4.

## Exact Commands Ran and Output
(No new code to build in Step 2; just appended to the markdown files.)

## What could not be verified and why
* Actual build processes or kernel driver implementations could not be verified, as this is purely a research task in an offline/simulated environment. Code compilation for WFP or eBPF was not in scope.
* No tests were written as this is a report-only lane. Therefore, mutation testing was NOT TESTABLE HERE.
