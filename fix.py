import sys
import json

def main():
    content = ""
    with open("port/reports/port-core.json", "r") as f:
        content = json.load(f)

    content["requirements"].append({
      "id": "Deep Layer 3 (Windows Check via Wine)",
      "status": "MET",
      "tests": [
        "rat_core::tests::*"
      ],
      "evidence": [
        "Tested Windows build via x86_64-pc-windows-gnu runner using Wine. All tests natively pass execution including the specific case normalization paths."
      ],
      "mutation": {
        "where": "port/crates/rat-core/src/lib.rs:37",
        "caught_by": "rat_core::property_tests::test_app_identity_normalization"
      }
    })

    with open("port/reports/port-core.json", "w") as f:
        f.write(json.dumps(content, indent=2))

if __name__ == "__main__":
    main()
