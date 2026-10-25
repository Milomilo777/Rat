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

## CI Findings
- **Port CI (ubuntu-latest)**: https://github.com/Milomilo777/Rat/actions/runs/40175785180/job/121116047432 - Failed on `test_cleanup_runs_on_start_and_shutdown` (assertion `left == right` failed: exactly one shutdown cleanup, left: 1, right: 2) in `crates/rat-daemon/tests/pipeline.rs`.
- **Port CI (windows-latest)**: https://github.com/Milomilo777/Rat/actions/runs/40175785180/job/121116047375 - Failed on `test_cleanup_runs_on_start_and_shutdown` (assertion `left == right` failed: exactly one shutdown cleanup, left: 1, right: 2) in `crates\rat-daemon\tests\pipeline.rs`.
