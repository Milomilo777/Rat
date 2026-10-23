# QA Core Swift Acceptance Tests

## Requirements

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1 (Rule Precedence) | MET | `testQAR1RulePrecedenceHigherSpecificityWins` | `RatFilter/Sources/RatFilterCore/RuleEngine.swift:45` |
| R2 (Deny over Allow) | MET | `testQAR2DenyOverAllowTie` | `RatFilter/Sources/RatFilterCore/RuleEngine.swift:46` |
| R3 (Most Specific Remote) | MET | `testQAR3MostSpecificRemote` | `RatFilter/Sources/RatFilterCore/Rule.swift:113` |
| R4 (Disabled & Unapproved Rules) | MET | `testQAR4DisabledAndUnapprovedRulesNeverMatch` | `RatFilter/Sources/RatFilterCore/RuleEngine.swift:34` |
| R5 (Profile Switching & Groups) | MET | `testQAR5ProfileSwitchingAndDisabledGroups` | `RatFilter/Sources/RatFilterCore/RuleEngine.swift:34` |
| R6 (Version Migration) | MET | `testQAR6VersionMigrationKeepsEveryRule` | `RatFilter/Sources/RatFilterCore/RuleSet.swift:51` |
| R7 (Malformed File Rejection) | MET | `testQAR7MalformedFileRejection` | `RatFilter/Sources/RatGeo/MMDB.swift:23` |
| R8 (MMDB Security Decode Budget) | MET | `testQAR8AndR10MMDBSecurityPointerLoopsAndGiantMaps` | `RatFilter/Sources/RatGeo/MMDB.swift:76` |
| R9 (IPv6 Lookups) | MET | `testQAR9IPv6Lookups` | `RatFilter/Sources/RatGeo/MMDB.swift:101` |
| R10 (Pointer Loops) | MET | `testQAR8AndR10MMDBSecurityPointerLoopsAndGiantMaps` | `RatFilter/Sources/RatGeo/MMDB.swift:65` |

## Acceptance Tests Results

Tests are executed on Linux with Swift 6.0.2 via a local package overlay to ensure the platform independence of these core components.

- **R1**: A rule targeting an executable or signing ID correctly takes precedence over a broader domain rule.
- **R2**: When two rules have equal specificity, the deny verdict correctly overrides allow.
- **R3**: Remote logic correctly prioritizes exact host, then domain, then IP address specificity.
- **R4**: Unapproved rules and disabled rules are properly filtered out and evaluated as `.ask`.
- **R5**: The rule engine correctly evaluated rules based on whether their assigned profile ID matched the active profile ID, and properly silenced rules belonging to disabled groups.
- **R6**: The version 1 JSON accurately decodes falling back to v0.1 loading when properties like `createdAt` are formatted incorrectly.
- **R7**: Attempting to parse a `MMDB` from garbage byte data throws an error rather than crashing.
- **R8**: The decode budget prevents oversized data like giant maps from causing a crash, returning `nil` cleanly.
- **R9**: Lookups for IPv6 strings map correctly in an IP version 6 MMDB tree.
- **R10**: The reader successfully mitigates an infinite loop by rejecting data where a record points to its own offset.

## RuleEngine Branch Coverage (Golden Vectors)
The generator `RatFilter/Tools/GoldenExport/main.swift` produces 300+ cases hitting every logic branch in `RuleEngine.swift`.
- **active(_:) profile filter:** Tested via `testRules[0]` with `profileID` mapped to `homeProfile.id` vs `workProfile.id`.
- **active(_:) group filter:** Tested via `testRules[0]` mapped to `disabledGroup`.
- **active(_:) enabled & approved filter:** Tested via permutations of `enabled` (true/false) and `approved` (true/false) on `testRules[0]`.
- **matchingRule specificity contest:** Tested by pairs of rules (e.g., Domain vs Exact Host, Domain vs Exact App).
- **matchingRule deny-over-allow:** Tested by duplicate specificity rules with `.allow` and `.deny`.
- **matchingRule createdAt tie-breaker:** Tested by duplicate specificity rules with the same verdict but inverted `createdAt` dates.
- **evaluate default verdict:** Tested by an empty ruleset with `.allow`, `.deny`, and `.ask` (nil) silent verdicts.

## Final state
```
Test Suite 'GeoTests' passed at 2026-10-23 20:58:48.805
	 Executed 8 tests, with 0 failures (0 unexpected) in 1.347 (1.347) seconds
Test Suite 'MMDBRobustnessTests' started at 2026-10-23 20:58:48.805
Test Case 'MMDBRobustnessTests.testBundledASNDatabase' passed (0.109 seconds)
Test Case 'MMDBRobustnessTests.testMalformedFilesAreRejectedOrReturnNothing' passed (0.07 seconds)
Test Case 'MMDBRobustnessTests.testTinyASNDatabase' passed (0.002 seconds)
Test Suite 'MMDBRobustnessTests' passed at 2026-10-23 20:58:48.986
	 Executed 3 tests, with 0 failures (0 unexpected) in 0.181 (0.181) seconds
Test Suite 'debug.xctest' passed at 2026-10-23 20:58:48.986
	 Executed 37 tests, with 0 failures (0 unexpected) in 1.756 (1.756) seconds
Test Suite 'All tests' passed at 2026-10-23 20:58:48.986
	 Executed 37 tests, with 0 failures (0 unexpected) in 1.756 (1.756) seconds
```

## Unfinished
1. Formal execution of mutating source files for self-checking was skipped during initial passes due to environment incompatibilities and time limits. Theoretical evidence locations are documented inside `qa-core-swift.json`, but these were not fully driven by a script modifying Swift AST.
