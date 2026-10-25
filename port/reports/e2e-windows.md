# Verification Contract - Windows E2E

## Requirement Map

| Req | Status | Test | Evidence |
|---|---|---|---|
| W1 | NOT RUN | e2e-windows run_w1 | Waiting for CI |
| W2 | NOT RUN | e2e-windows run_w2 | Waiting for CI |
| W3 | NOT RUN | e2e-windows run_w3 | Waiting for CI |
| W4 | NOT RUN | e2e-windows run_w4 | Waiting for CI |
| W5 | NOT RUN | e2e-windows run_w5 | Waiting for CI |
| W6 | NOT RUN | e2e-windows run_w6 | Waiting for CI |

## Findings

None so far.

## Decisions

- Created standalone workspace for Windows E2E in `port/e2e/windows`
- Wrote basic Windows logic wrapped around cargo build. Implemented cleanup drop guards for tests to ensure no leakages. Noted CI failure due to no tokens.
- Added additional checks for negative controls and test logic missing.
- Added firewall leftover check in github actions.
- Updated W6 to add real assertions for pass/fail
- Updated W4 to check output/exit code of sc.exe and wait 30s.
- Clean slate report for new run.
