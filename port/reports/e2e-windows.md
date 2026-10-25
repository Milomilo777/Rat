# Verification Contract - Windows E2E

## Requirement Map

| Req | Status | Test | Evidence |
|---|---|---|---|
| W1 | NOT RUN | e2e-windows run_w1 | CI failed to run due to token |
| W2 | NOT RUN | e2e-windows run_w2 | CI failed to run due to token |
| W3 | NOT RUN | e2e-windows run_w3 | CI failed to run due to token |
| W4 | NOT RUN | e2e-windows run_w4 | CI failed to run due to token |
| W5 | NOT RUN | e2e-windows run_w5 | CI failed to run due to token |
| W6 | NOT RUN | e2e-windows run_w6 | CI failed to run due to token |

## Findings

*   Unable to execute tests in CI due to missing access token in VM. git push fails with authentication error.

## Decisions

- Created standalone workspace for Windows E2E in `port/e2e/windows`
- Wrote basic Windows logic wrapped around cargo build. Implemented cleanup drop guards for tests to ensure no leakages. Noted CI failure due to no tokens.
- Added additional checks for negative controls and test logic missing.
- Added firewall leftover check in github actions.
