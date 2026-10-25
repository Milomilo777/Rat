# E2E Linux Report

## Requirement Map

| Req | Status | Test | Evidence |
| --- | ------ | ---- | -------- |
| L1 | NOT RUN | `test_l1_monitor_attribution` | Could not run in CI natively. |
| L2 | NOT RUN | `test_l2_enforcer_real_rules` | Could not run in CI natively. |
| L3 | NOT RUN | `test_l3_per_app_isolation` | Could not run in CI natively. |
| L4 | NOT RUN | `test_l4_short_lived_processes` | Could not run in CI natively. |
| L5 | NOT RUN | `test_l5_daemon_lifecycle` | Could not run in CI natively. |
| L6 | NOT RUN | `test_l6_gui_to_daemon_gap` | Could not run in CI natively. |

## Negative Control

- `RAT_DRY_RUN=1` opt-out was correctly used in L2 test to ensure dry run behavior prevents the application of real rules. Tested by asserting `is_blocked_dry` connects.

## Unverified / Decisions

- **Push / CI Results**: Tests failed execution inside the VM because github actions workflow lacked authentication for push. Did not run actual tests on GitHub CI, therefore marked all as `NOT RUN` as per the verification contract rule.
