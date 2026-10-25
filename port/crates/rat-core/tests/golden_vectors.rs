//! Consumes the golden verdict corpus exported from the Swift engine
//! (port/testdata/rules-golden: 300 cases + the v1→v2 migration pair,
//! qa-core-swift lane). Proves two things at once: rat-core decodes
//! Swift's rules.json encoding (camelCase keys with `ID` spellings,
//! ClosedRange port arrays, keyed unknownNetworkAction, lowercase protos),
//! and the engine reproduces Swift's verdicts — including the
//! enabled && approved semantics fixed on both sides (PROPOSALS #11).

use rat_core::{AppConnection, AppIdentity, RuleEngine, RuleSet, RuleStore, Verdict};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct GoldenConnection {
    address: String,
    port: u16,
    #[serde(default)]
    host: Option<String>,
    process: AppIdentity,
    proto: rat_types::Protocol,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenCase {
    connection: GoldenConnection,
    rule_set: RuleSet,
    verdict: Verdict,
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rules-golden")
}

#[test]
fn test_golden_vectors_match_swift_verdicts() {
    let data = std::fs::read_to_string(golden_dir().join("cases.jsonl")).expect("cases.jsonl");
    let mut total = 0usize;
    for (idx, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let case: GoldenCase = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {}: decode failed: {e}", idx + 1));
        let engine = RuleEngine::with_rule_set(case.rule_set);
        let conn = AppConnection::new(
            case.connection.process,
            case.connection.host,
            case.connection.address,
            case.connection.port,
            case.connection.proto,
        );
        assert_eq!(
            engine.evaluate(&conn),
            case.verdict,
            "line {}: verdict mismatch",
            idx + 1,
        );
        total += 1;
    }
    assert_eq!(total, 300, "expected the full 300-case corpus");
}

#[test]
fn test_golden_v1_migration_matches_swift() {
    let dir = tempfile::tempdir().unwrap();
    let url = dir.path().join("rules.json");
    std::fs::write(
        &url,
        std::fs::read_to_string(golden_dir().join("migration/v1_in.json")).unwrap(),
    )
    .unwrap();

    let migrated = RuleStore::new(url).load_set().unwrap();
    let expected: RuleSet = serde_json::from_str(
        &std::fs::read_to_string(golden_dir().join("migration/v2_migrated.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(migrated, expected);
    assert_eq!(migrated.version, 2);
    assert_eq!(migrated.silent_verdict, Some(Verdict::Allow));
}
