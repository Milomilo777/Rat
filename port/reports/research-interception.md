# Lane Report: research-interception

## Requirements Map
| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1: Research interception mechanisms | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R2: Compare OpenSnitch, Portmaster, simplewall, TinyWall, WinDivert, Windows Firewall | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R3: Recommend one mechanism per OS for v1 and v2 | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R4: Detail exact WFP and nftables/nfqueue setups | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R5: Compare local port blocking (v1.2.0 compatibility) | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R6: Linux prototype (nfqueue spike in network namespace) | PARTIAL | N/A | port/spikes/linux-prompt/src/main.rs |

## Actions Taken
* Read context and problem descriptions, including `README.md`, `CLAUDE.md`, and `docs/ARCHITECTURE.md`.
* Investigated various interception mechanisms and tools: OpenSnitch, Portmaster, simplewall, TinyWall, WinDivert, and Windows Firewall.
* Authored `port/docs/adr/0001-interception.md` containing the MADR 4.0 format decision record evaluating the options for both platforms (Windows and Linux) and both phases (Version 1 - reactive; Version 2 - pre-connection).
* Generated this report in `port/reports/research-interception.md`.
* Updated `port/docs/adr/0001-interception.md` with a follow-up section detailing the exact WFP and nftables/nfqueue setups, with official documentation links.
* Merged `origin/main` (v1.2.0) and updated `port/docs/adr/0001-interception.md` to address the paradigm shift from remote address blocking to local port/process blocking.
* Attempted a spike for the Linux `nfqueue` intercept in a network namespace, but stopped execution due to missing kernel module support in the environment. Added results to the ADR.
* Created the Rust workspace manifest (`port/Cargo.toml`) and the shared `rat-types` crate as per the general Rust port lane requirements.
* Built the Rust prototype code in `port/spikes/linux-prompt` capable of accepting packets from an nfqueue. Verified it compiles natively.

## Decisions and Reasons
* **Decision:** Recommended Windows Filtering Platform (WFP) user-mode for Windows V1, and WFP callout driver for Windows V2. Recommended eBPF/netlink for Linux V1, and nfqueue for Linux V2.
  * **Reason:** This approach allows for a faster rollout of V1 without kernel driver signing hurdles, while preserving a clear path to V2 capabilities (pending connections) using native or well-established driver architectures.
* **Decision:** Detailed specific WFP API elements (FwpmGetAppIdFromFileName0, Dynamic Sessions, ALE layers) and nftables queues.
  * **Reason:** To guide developers directly to the necessary components and their official documentation without ambiguity, addressing R4.
* **Decision:** Adopted App ID based blocking for Windows and local port blocking for Linux in V1 recommendations.
  * **Reason:** Aligns with Rat v1.2.0's requirement to never block remote addresses.
* **Decision:** Stopped the Linux nfqueue spike execution.
  * **Reason:** The execution environment lacks the `nfnetlink_queue` and basic `nf_tables` modules. `iptables` and `nft` both fail with "Operation not supported" or "No such file or directory" when attempting to create a filter chain or queue rule in an `unshare -n -r` namespace.
* **Decision:** Created the `port/Cargo.toml` and `port/crates/rat-types` structure.
  * **Reason:** This fulfills the overarching mandate for "all port lanes" to establish the common Rust workspace, overriding the previous decision to strictly follow the path-isolation constraint in this report-only lane.
* **Decision:** Added empty `[workspace]` to `port/spikes/linux-prompt/Cargo.toml`.
  * **Reason:** The main `port/Cargo.toml` must have exact contents per instructions. This excludes `spikes`. Giving the spike its own workspace allows `cargo check` to run correctly inside the spike folder without modifying the main `Cargo.toml`.

## Changed by v1.2.0
* Rat v1.2.0 fundamentally changed enforcement (v1.0.4+): it never blocks remote addresses to avoid breaking DNS or shared CDNs for allowed apps. Instead, the root daemon `rat-enforcerd` blocks the **local ports** of every socket belonging to a denied app via a stateless pf anchor. The ADR has been updated to evaluate WFP and nftables capability to block by local port or by process ID/App ID.

## Exact Commands Ran and Output
```bash
# cd port/spikes/linux-prompt && cargo check
    Checking linux-prompt v0.1.0 (/app/port/spikes/linux-prompt)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s
```

## What could not be verified and why
* Actual build processes or kernel driver implementations could not be verified, as this is purely a research task in an offline/simulated environment. Code compilation for WFP or eBPF was not in scope.
* No tests were written as this is a report-only lane (and spike could not run). Therefore, mutation testing was NOT TESTABLE HERE.
* Could not verify Linux nfqueue prototype runtime execution because the VM environment forbids netfilter kernel modules.
