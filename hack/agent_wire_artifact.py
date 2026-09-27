#!/usr/bin/env python3
"""Validate the current V3 wire artifact without an obsolete-major baseline."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "crates/agent-wire/schema"
MANIFEST = SCHEMAS / "agent-v3.schema-manifest.json"
LIB = ROOT / "crates/agent-wire/src/lib.rs"


def check():
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("wireVersion") != 3:
        raise ValueError("manifest must declare Agent V3")
    files = [entry["file"] for entry in manifest["schemas"]]
    if len(files) != len(set(files)) or not files or any(not name.endswith("-v3.schema.json") for name in files):
        raise ValueError("manifest has duplicate or non-V3 schema entries")
    actual = {path.name for path in SCHEMAS.glob("*.json")}
    if actual != set(files) | {MANIFEST.name}:
        raise ValueError("schema directory differs from the V3 manifest")
    digest = hashlib.sha256()
    for name in files:
        data = (SCHEMAS / name).read_bytes()
        schema = json.loads(data)
        if "/agent/v3/" not in schema.get("$id", ""):
            raise ValueError(f"{name}: non-V3 schema identifier")
        digest.update(data)
    expected = re.search(r'pub const SCHEMA_FINGERPRINT: &str =\s*"([0-9a-f]{64})"', LIB.read_text())
    if expected is None or expected.group(1) != digest.hexdigest():
        raise ValueError("schema fingerprint differs from the declared V3 artifact")


def main():
    try:
        check()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"agent-wire artifact: {error}", file=sys.stderr)
        return 1
    print("Agent V3 manifest and schemas are complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
