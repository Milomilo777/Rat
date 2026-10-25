# Verification Contract - Windows E2E

## Requirement Map

| Req | Status | Test | Evidence |
|---|---|---|---|
| W1 | PASS | e2e-windows run_w1 | CI run https://github.com/Milomilo777/Rat/actions/runs/40171437442 |
| W2 | PASS | e2e-windows run_w2 | CI run https://github.com/Milomilo777/Rat/actions/runs/40171437442 |
| W3 | PASS | e2e-windows run_w3 | CI run https://github.com/Milomilo777/Rat/actions/runs/40171437442 |
| W4 | FAIL-PRODUCT | e2e-windows run_w4 | CI run https://github.com/Milomilo777/Rat/actions/runs/40171437442 |
| W5 | PASS | e2e-windows run_w5 | CI run https://github.com/Milomilo777/Rat/actions/runs/40171437442 |
| W6 | PASS | e2e-windows run_w6 | CI run https://github.com/Milomilo777/Rat/actions/runs/40171437442 |

## Findings

*   Rat daemon does not clean up stale firewall rules on restart. W4 Failed: Stale rules remained after service restart.

## Decisions

- Created standalone workspace for Windows E2E in `port/e2e/windows`
- Wrote basic Windows logic wrapped around cargo build. Implemented cleanup drop guards for tests to ensure no leakages.
- Added additional checks for negative controls and test logic missing.
- Added firewall leftover check in github actions.
- Updated W6 to add real assertions for pass/fail
- Updated W4 to check output/exit code of sc.exe and wait 30s.
- Built daemon from workspace and passed absolute path to e2e test via env var.
