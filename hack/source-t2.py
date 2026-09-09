#!/usr/bin/env python3
"""Real local HTTP/Git seams. Run both targets and collect failures."""
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def main():
    failed = []
    for package, target in [("rss-mdm-winget-source", "t2_http"), ("rss-mdm-brew-source", "t2_git")]:
        result = subprocess.run(["cargo", "test", "--locked", "-p", package, "--test", target, "--", "--ignored"], cwd=ROOT)
        if result.returncode:
            failed.append(target)
    if failed:
        print("Failed source T2 targets: " + ", ".join(failed), file=sys.stderr)
    return int(bool(failed))

if __name__ == "__main__":
    sys.exit(main())
