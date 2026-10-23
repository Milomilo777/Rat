import json

data = {
    "lane": "port-geo",
    "step": 1,
    "requirements": [
        {
            "id": "R1",
            "status": "MET",
            "tests": ["test_geo::test_geoip_lookup"],
            "evidence": ["port/crates/rat-geo/src/lib.rs:26"],
            "mutation": {"where": "port/crates/rat-geo/src/lib.rs:26", "caught_by": "test_geo::test_geoip_lookup"}
        },
        {
            "id": "R2",
            "status": "MET",
            "tests": ["test_geo::test_geoip_lookup"],
            "evidence": ["port/crates/rat-geo/tests/test_geo.rs:7"],
            "mutation": {"where": "port/crates/rat-geo/tests/test_geo.rs:25", "caught_by": "test_geo::test_geoip_lookup"}
        },
        {
            "id": "R3",
            "status": "MET",
            "tests": ["test_geo::test_parse_iso6709", "test_geo::test_zone_tab"],
            "evidence": ["port/crates/rat-geo/src/lib.rs:114", "port/crates/rat-geo/src/lib.rs:141", "port/crates/rat-geo/src/windows_tz.rs:4"],
            "mutation": {"where": "port/crates/rat-geo/src/lib.rs:163", "caught_by": "test_geo::test_zone_tab"}
        },
        {
            "id": "R4",
            "status": "MET",
            "tests": ["test_geo::test_default_db_path"],
            "evidence": ["port/crates/rat-geo/src/lib.rs:74"],
            "mutation": {"where": "port/crates/rat-geo/src/lib.rs:75", "caught_by": "test_geo::test_default_db_path"}
        }
    ],
    "files_changed": ["port/Cargo.toml", "port/crates/rat-types/Cargo.toml", "port/crates/rat-types/src/lib.rs", "port/crates/rat-geo/Cargo.toml", "port/crates/rat-geo/src/lib.rs", "port/crates/rat-geo/src/windows_tz.rs", "port/crates/rat-geo/tests/test_geo.rs", "port/crates/rat-geo/tests/test_fixture.rs"],
    "existing_tests_modified": [],
    "commands": [{"cmd": "cargo test --manifest-path port/crates/rat-geo/Cargo.toml", "exit_code": 0}],
    "unverified": [],
    "decisions": [
        {"what": "Used maxminddb crate rather than porting the custom MMDB.swift", "why": "The maxminddb crate is mature, well-tested, and significantly reduces the maintenance burden compared to porting a custom implementation."}
    ]
}

with open("port/reports/port-geo.json", "w") as f:
    json.dump(data, f, indent=4)
