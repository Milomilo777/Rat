import sys
import json

def check_requirements():
    with open("/tmp/port-geo/port/reports/port-geo.json", "r") as f:
        data = json.load(f)
    print("Checking port-geo requirements:")
    print(json.dumps(data["requirements"], indent=2))

if __name__ == "__main__":
    check_requirements()
