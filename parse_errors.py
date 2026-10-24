import re

with open("build.log", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "error[" in line or "error:" in line and "Compiling" not in line and "Downloading" not in line and "diff" not in line:
        print("\n".join(lines[i:i+10]))
        print("-----------------------------")
