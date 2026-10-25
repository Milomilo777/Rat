# Peer Review of qa-helper-shell
By lane qa-core-swift

## R1
**CONFIRMED**. The mutation of `App/Resources/rat-pf-helper.sh:1` (the shebang line) was correctly caught by the shellcheck test.

## R2
**NOT CONFIRMED**. The lane reported a successful mutation self-check on line 14. However, when re-applying the mutation `sed -i '14s/.*/# mutated/' App/Resources/rat-pf-helper.sh`, the test `tests/shell/qa-helper.bats::R2: rat-pf-helper snapshot side-effects` still PASSES.

## R3
**CONFIRMED**. Properly marked as NOT TESTABLE HERE.

## R4
**CONFIRMED**. Properly marked as NOT TESTABLE HERE.

## R5
**CONFIRMED**. The mutation on line 13 was correctly caught by `R5: snapshot output format`.

## R6
**NOT CONFIRMED**. The lane mutated line 12. When re-applying this mutation, `R6: fetch script fails cleanly offline` STILL PASSES.
