import sys
import json

def main():
    content = ""
    with open("port/reports/port-core.json", "r") as f:
        content = json.load(f)

    content["requirements"].append({
      "id": "Edge Cases (Malformed)",
      "status": "MET",
      "tests": [
        "rat_core::load_tests::test_malformed_lines_handled_gracefully"
      ],
      "evidence": [
        "port/crates/rat-core/src/lib.rs:668"
      ],
      "mutation": {
        "where": "port/crates/rat-core/src/lib.rs:668",
        "caught_by": "rat_core::load_tests::test_malformed_lines_handled_gracefully"
      }
    })

    with open("port/reports/port-core.json", "w") as f:
        f.write(json.dumps(content, indent=2))

if __name__ == "__main__":
    main()
