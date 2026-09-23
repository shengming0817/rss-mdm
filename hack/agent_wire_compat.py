#!/usr/bin/env python3
"""Freeze the strict V1 surface against an immutable, reviewed Git candidate.

ref: bufbuild/buf private/bufpkg/bufcheck/bufcheck.go (current/against inputs).
V1 has no extension points: conservatively require structural JSON equality.
"""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# Reviewed candidate from PR 1082, not evidence of a registry release.
BASELINE = "0637e0c4024673d79aaa6562018c96e667e694e3"
SCHEMA_PATH = "crates/agent-wire/schema"
MANIFEST = "agent-v1.schema-manifest.json"


def baseline_file(name):
    result = subprocess.run(
        ["/usr/bin/git", "show", f"{BASELINE}:{SCHEMA_PATH}/{name}"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if result.returncode:
        raise ValueError(f"V1 baseline unavailable: fetch commit {BASELINE}; cannot skip compatibility")
    return json.loads(result.stdout)


def check(schema_dir):
    manifest = baseline_file(MANIFEST)
    # Read the surface from the baseline, never from the candidate's mutable manifest.
    for name in [MANIFEST, *(entry["file"] for entry in manifest["schemas"])]:
        expected = manifest if name == MANIFEST else baseline_file(name)
        actual = json.loads((schema_dir / name).read_text())
        # JSON types remain distinct (Python otherwise equates True and 1).
        if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError(
                f"{name}: frozen V1 contract changed; introduce a new wire major "
                "and its explicit baseline instead of updating SCHEMA_FINGERPRINT"
            )


def main():
    try:
        check(ROOT / SCHEMA_PATH)
    except (ValueError, OSError) as error:
        print(f"agent-wire compatibility: {error}", file=sys.stderr)
        return 1
    print(f"Agent V1 matches immutable candidate {BASELINE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
