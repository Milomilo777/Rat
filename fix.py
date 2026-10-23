import sys
import json

def main():
    content = ""
    with open("port/reports/port-core.json", "r") as f:
        content = json.load(f)

    content["requirements"].append({
      "id": "Deep Layer 4 (Performance & Budgets)",
      "status": "MET",
      "tests": [
        "rat_core::perf_tests::test_performance_budget_5000_rules"
      ],
      "evidence": [
        "port/crates/rat-core/benches/engine_bench.rs",
        "port/crates/rat-core/src/lib.rs:530-555"
      ],
      "mutation": {
        "where": "port/crates/rat-core/src/lib.rs:1330",
        "caught_by": "rat_core::perf_tests::test_performance_budget_5000_rules"
      }
    })

    with open("port/reports/port-core.json", "w") as f:
        f.write(json.dumps(content, indent=2))

if __name__ == "__main__":
    main()
