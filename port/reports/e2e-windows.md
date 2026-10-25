# Verification Contract - Windows E2E

## Requirement Map

| Req | Status | Test | Evidence |
|---|---|---|---|
| W1 | PASS | e2e-windows run_w1 | CI run https://github.com/Milomilo777/Rat/actions/runs/40162164734 (W1 PASSED in logs) |
| W2 | PASS | e2e-windows run_w2 | CI run https://github.com/Milomilo777/Rat/actions/runs/40162164734 (W2 PASSED in logs: rules 340 -> 341, blocked client exit 1, normal curl exit 0) |
| W3 | PASS | e2e-windows run_w3 | CI run https://github.com/Milomilo777/Rat/actions/runs/40162164734 (W3 PASSED in logs) |
| W4 | FAIL-PRODUCT | e2e-windows run_w4 | CI run https://github.com/Milomilo777/Rat/actions/runs/40162164734 (W4 Failed: Stale rules remained after service restart in run_w4) |
| W5 | PASS | e2e-windows run_w5 | CI run https://github.com/Milomilo777/Rat/actions/runs/40162164734 (W5 PASSED in logs) |
| W6 | NOT RUN | e2e-windows run_w6 | Needs to be re-run since W6 previously had no assertions |

## Findings

*   Rat daemon does not clean up stale firewall rules on restart. W4 Failed: Stale rules remained after service restart.

## Decisions

- Created standalone workspace for Windows E2E in `port/e2e/windows`
- Wrote basic Windows logic wrapped around cargo build. Implemented cleanup drop guards for tests to ensure no leakages. Noted CI failure due to no tokens.
- Added additional checks for negative controls and test logic missing.
- Added firewall leftover check in github actions.
- Updated W6 to add real assertions for pass/fail
- Updated W4 to check output/exit code of sc.exe and wait 30s.
