import json

with open("docs/qa/qa-helper-shell.json", "r") as f:
    data = json.load(f)

data["step"] = 3
data["files_changed"].append("tests/shell/qa-generator.py")
data["unverified"].append("Deep layer generator execution skipped: The instruction requires testing blocklist parsing, but in v1.2.0 this moved to rat-enforcerd (Swift). The macOS-only Swift daemon cannot be compiled or run in this Linux environment. The generator was written but not executed against the daemon.")
data["decisions"].append({
    "what": "Skipped running rat-enforcerd with generated inputs",
    "why": "The instruction asks to run the helper with the generated blocklists. Since blocklist parsing moved to rat-enforcerd in 1.2.0 and macOS-only Swift code cannot run here, I only wrote the generator."
})

with open("docs/qa/qa-helper-shell.json", "w") as f:
    json.dump(data, f, indent=2)
