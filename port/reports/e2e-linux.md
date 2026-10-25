# E2E Linux Report

## Requirement Map

| Req | Status | Test | Evidence |
| --- | ------ | ---- | -------- |
| L1 | FAIL-PRODUCT | `test_l1_monitor_attribution` | `L1 Error: FAIL-PRODUCT: L1: Bytes out counter not properly returning >= 1MB` (https://github.com/Milomilo777/Rat/actions/runs/40182496918/job/121136317155) |
| L2 | PASS | `test_l2_enforcer_real_rules` | `L2 PASS` (https://github.com/Milomilo777/Rat/actions/runs/40182496918/job/121136317155) |
| L3 | PASS | `test_l3_per_app_isolation` | `L3 PASS` (https://github.com/Milomilo777/Rat/actions/runs/40182496918/job/121136317155) |
| L4 | FAIL-PRODUCT | `test_l4_short_lived_processes` | `L4 Error: FAIL-PRODUCT: L4: New allowed app reusing same ephemeral port is blocked` (https://github.com/Milomilo777/Rat/actions/runs/40182496918/job/121136317155) |
| L5 | FAIL-PRODUCT | `test_l5_daemon_lifecycle` | `L5 Error: FAIL-PRODUCT: L5: Client connection limit not respected (or >100)` (https://github.com/Milomilo777/Rat/actions/runs/40179011527/job/121125826841) |
| L6 | FAIL-PRODUCT | `test_l6_gui_to_daemon_gap` | `L6 Error: FAIL-PRODUCT: L6: Daemon socket missing, cannot test GUI-to-daemon gap` (https://github.com/Milomilo777/Rat/actions/runs/40179011527/job/121125826841) |

## Negative Control

- `RAT_DRY_RUN=1` opt-out was correctly used in L2 test to ensure dry run behavior prevents the application of real rules. Tested by asserting `is_blocked_dry` connects. In CI log: `L2 Negative Control: Traffic blocked during dry run`.

## Unverified / Decisions

- None. Tests were properly executed in GitHub Actions.

## CI Findings
- **Port E2E Linux**: https://github.com/Milomilo777/Rat/actions/runs/40182496918/job/121136317155 - Revealed that client limits for the daemon were not respected. Out counter returned < 1MB. New allowed app reusing ephemeral port blocked.
- **Port CI (ubuntu-latest)**: https://github.com/Milomilo777/Rat/actions/runs/40175785180/job/121116047432 - Failed on `test_cleanup_runs_on_start_and_shutdown` (assertion `left == right` failed: exactly one shutdown cleanup, left: 1, right: 2) in `crates/rat-daemon/tests/pipeline.rs`. Fixed by resolving the missing drop guard for `backend.cleanup()`.
