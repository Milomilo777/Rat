# QA Report: qa-helper-shell

## Requirements Map

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1 | MET | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R1: shellcheck clean` | `App/Resources/rat-pf-helper.sh:1`, `scripts/fetch-geoip.sh:1`, `scripts/verify-blocking.sh:1`, `scripts/test-proxy.py:1` |
| R2 | MET | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R2: rat-pf-helper snapshot side-effects` | `App/Resources/rat-pf-helper.sh:13` |
| R3 | NOT TESTABLE HERE |  | `RatFilter/Sources/RatEnforce/Rules.swift:10` |
| R4 | NOT TESTABLE HERE |  | `RatFilter/Sources/RatEnforce/Rules.swift:10` |
| R5 | PARTIAL | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R5: snapshot output format` | `App/Resources/rat-pf-helper.sh:13` |
| R6 | MET | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R6: fetch script verifies download`, `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R6: fetch script fails cleanly offline` | `scripts/fetch-geoip.sh:12` |

## Changed by v1.2.0
- R3, R4 (Apply Mode): `rat-pf-helper.sh` apply mode was removed. Blocking logic shifted to `rat-enforcerd`.
- R6 (Fetch Script): The fetch script now downloads both city and asn databases.
- Mocking: Using `sed` to mock absolute paths is prohibited; testing must run against production file directly.
- R1: `verify-blocking.sh` had several shellcheck errors fixed to allow `R1` to pass.

## Mutation Tests
- R1 mutation | `App/Resources/rat-pf-helper.sh:1` | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R1: shellcheck clean`
- R2 mutation | `App/Resources/rat-pf-helper.sh:14` | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R2: rat-pf-helper snapshot side-effects`
- R5 mutation | `App/Resources/rat-pf-helper.sh:13` | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R5: snapshot output format`
- R6 mutation | `scripts/fetch-geoip.sh:12` | `tests/shell/qa-helper.bats::tests/shell/qa-helper.bats::R6: fetch script fails cleanly offline`

## Raw Output Log

See `docs/qa/qa-helper-shell.log`.
