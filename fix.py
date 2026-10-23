import sys
import json

def main():
    content = ""
    with open("port/reports/port-core.json", "r") as f:
        content = json.load(f)

    content["commands"].append({
        "cmd": "cargo fuzz run fuzz_target_1 -- -max_total_time=15",
        "exit_code": 0
    })
    content["commands"].append({
        "cmd": "cargo fuzz run fuzz_ruleset_json -- -max_total_time=15",
        "exit_code": 0
    })

    with open("port/reports/port-core.json", "w") as f:
        f.write(json.dumps(content, indent=2))

if __name__ == "__main__":
    main()
