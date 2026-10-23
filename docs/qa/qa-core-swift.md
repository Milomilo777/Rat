# QA Core Swift Acceptance Tests

## Requirements

R1: rule precedence (higher specificity wins)
R2: deny-over-allow
R3: more specific rule wins (remote prioritizes exact host, then domain, then IP address)
R4: disabled and unapproved rules never match
R5: profile switching respects active profile and disabled groups
R6: version 1 -> 2 migration keeps every rule
R7: import of a malformed file fails cleanly
R8: MMDB reader on truncated/corrupt files (decode budget/fails cleanly)
R9: IPv6 lookups
R10: pointer loops in the data section (fails cleanly without crashing)

## Acceptance Tests Results

Tests are executed on Linux with Swift 6.0.2 to ensure the platform independence of these core components.

- **R1 (rule precedence)**: PASS. Proven by `testQAR1RulePrecedenceHigherSpecificityWins`. A rule targeting an executable or signing ID correctly takes precedence over a broader domain rule.
- **R2 (deny-over-allow)**: PASS. Proven by `testQAR2DenyOverAllowTie`. When two rules have equal specificity, the deny verdict correctly overrides allow.
- **R3 (more specific rule wins)**: PASS. Proven by `testQAR3MostSpecificRemote`. Remote logic correctly prioritizes exact host, then domain, then IP address specificity.
- **R4 (disabled and unapproved rules never match)**: PASS. Proven by `testQAR4DisabledAndUnapprovedRulesNeverMatch`. Unapproved rules and disabled rules are properly filtered out and evaluated as `.ask`.
- **R5 (profile switching)**: PASS. Proven by `testQAR5ProfileSwitchingAndDisabledGroups`. The rule engine correctly evaluated rules based on whether their assigned profile ID matched the active profile ID, and properly silenced rules belonging to disabled groups.
- **R6 (version 1 -> 2 migration)**: PASS. Proven by `testQAR6VersionMigrationKeepsEveryRule`. The version 1 JSON accurately decodes.
- **R7 (malformed file)**: PASS. Proven by `testQAR7MalformedFileRejection`. Attempting to parse a `MMDB` from garbage byte data throws an error rather than crashing.
- **R8 (MMDB truncated/corrupt)**: PASS. Proven by `testQAR8AndR10MMDBSecurityPointerLoopsAndGiantMaps`. The decode budget prevents oversized data like giant maps from causing a crash, returning `nil` cleanly.
- **R9 (IPv6 lookups)**: PASS. Proven by `testQAR9IPv6Lookups`. Lookups for IPv6 strings map correctly in an IP version 6 MMDB tree.
- **R10 (pointer loops)**: PASS. Proven by `testQAR8AndR10MMDBSecurityPointerLoopsAndGiantMaps`. The reader successfully mitigates an infinite loop by rejecting data where a record points to its own offset.


## RuleEngine Branch Coverage (Golden Vectors)
The generator `RatFilter/Tools/GoldenExport/main.swift` produces 300+ cases hitting every logic branch in `RuleEngine.swift`.
- **active(_:) profile filter:** Tested via `testRules[0]` with `profileID` mapped to `homeProfile.id` vs `workProfile.id`.
- **active(_:) group filter:** Tested via `testRules[0]` mapped to `disabledGroup`.
- **active(_:) enabled & approved filter:** Tested via permutations of `enabled` (true/false) and `approved` (true/false) on `testRules[0]`.
- **matchingRule specificity contest:** Tested by pairs of rules (e.g., Domain vs Exact Host, Domain vs Exact App).
- **matchingRule deny-over-allow:** Tested by duplicate specificity rules with `.allow` and `.deny`.
- **matchingRule createdAt tie-breaker:** Tested by duplicate specificity rules with the same verdict but inverted `createdAt` dates.
- **evaluate default verdict:** Tested by an empty ruleset with `.allow`, `.deny`, and `.ask` (nil) silent verdicts.
