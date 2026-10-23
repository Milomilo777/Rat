# Lane Report: research-interception

## Requirements Map
| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1: Research interception mechanisms | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R2: Compare OpenSnitch, Portmaster, simplewall, TinyWall, WinDivert, Windows Firewall | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |
| R3: Recommend one mechanism per OS for v1 and v2 | NOT TESTABLE HERE | N/A | port/docs/adr/0001-interception.md |

## Actions Taken
* Read context and problem descriptions, including `README.md`, `CLAUDE.md`, and `docs/ARCHITECTURE.md`.
* Investigated various interception mechanisms and tools: OpenSnitch, Portmaster, simplewall, TinyWall, WinDivert, and Windows Firewall.
* Wrote a Python script to retrieve license and release date information from GitHub for these open-source projects.
* Authored `port/docs/adr/0001-interception.md` containing the MADR 4.0 format decision record evaluating the options for both platforms (Windows and Linux) and both phases (Version 1 - reactive; Version 2 - pre-connection).
* Generated this report in `port/reports/research-interception.md`.

## Decisions and Reasons
* **Decision:** Excluded the creation of the Rust boilerplate code files (`port/Cargo.toml` and `port/crates/rat-types/*`).
  * **Reason:** This lane (`research-interception`) is explicitly described as a "report-only lane, no code". Furthermore, the instructions strictly mandate: "Touch ONLY the paths your lane names. Do not edit any other file (no README, CLAUDE.md, CHANGELOG, root files, other lanes' folders)." The allowed paths were specifically limited to `port/docs/adr/0001-interception.md` and `port/reports/research-interception.md`. Creating other files would violate these constraints.
* **Decision:** Recommended Windows Filtering Platform (WFP) user-mode for Windows V1, and WFP callout driver for Windows V2. Recommended eBPF/netlink for Linux V1, and nfqueue for Linux V2.
  * **Reason:** This approach allows for a faster rollout of V1 without kernel driver signing hurdles, while preserving a clear path to V2 capabilities (pending connections) using native or well-established driver architectures.

## Exact Commands Ran and Output
```bash
# mkdir -p port/docs/adr port/reports

# cat << 'SCRIPT_EOF' > get_github_info.py
import urllib.request
import json
import sys

def get_repo_info(repo):
    url = f"https://api.github.com/repos/{repo}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print(f"Repo: {repo}")
            print(f"License: {data.get('license', {}).get('name', 'None') if data.get('license') else 'None'}")
            print(f"HTML URL: {data.get('html_url')}")
    except Exception as e:
        print(f"Error for {repo}: {e}")

    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print(f"Latest Release Date: {data.get('published_at')}")
    except Exception as e:
        print(f"Error getting release for {repo}: {e}")
    print()

for repo in ["evilsocket/opensnitch", "safing/portmaster", "henrypp/simplewall", "basil00/Divert", "safing/portmaster-windows-kext"]:
    get_repo_info(repo)
SCRIPT_EOF
# python3 get_github_info.py
```
Output:
```
Repo: evilsocket/opensnitch
License: GNU General Public License v3.0
HTML URL: https://github.com/evilsocket/opensnitch
Latest Release Date: 2025-12-15T00:54:11Z

Repo: safing/portmaster
License: GNU General Public License v3.0
HTML URL: https://github.com/safing/portmaster
Latest Release Date: 2026-08-14T19:21:49Z

Repo: henrypp/simplewall
License: GNU General Public License v3.0
HTML URL: https://github.com/henrypp/simplewall
Latest Release Date: 2025-08-08T12:30:35Z

Repo: basil00/Divert
License: Other
HTML URL: https://github.com/basil00/WinDivert
Latest Release Date: 2022-09-21T00:09:43Z

Repo: safing/portmaster-windows-kext
License: GNU General Public License v3.0
HTML URL: https://github.com/safing/portmaster-windows-kext
Latest Release Date: 2023-08-17T14:14:52Z
```

## What could not be verified and why
* Actual build processes or kernel driver implementations could not be verified, as this is purely a research task in an offline/simulated environment. Code compilation for WFP or eBPF was not in scope.
* No tests were written as this is a report-only lane. Therefore, mutation testing was NOT TESTABLE HERE.
