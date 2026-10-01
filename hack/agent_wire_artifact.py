#!/usr/bin/env python3
"""Task payload schema is canonical; derive embeddings, then verify the V4 artifact."""
import hashlib
import json
from pathlib import Path
import re
import sys
import copy

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "crates/agent-wire/schema"
MANIFEST = SCHEMAS / "agent-v4.schema-manifest.json"
LIB = ROOT / "crates/agent-wire/src/lib.rs"
EMBEDDED = {
    "signed-task-v4.schema.json": ("properties", "payload"),
    "task-claim-response-v4.schema.json": ("properties", "task", "oneOf", 1, "properties", "payload"),
    "task-event-ack-v4.schema.json": ("properties", "permit", "oneOf", 1, "properties", "payload"),
}


def embedded(schema, path):
    for part in path:
        schema = schema[part]
    return schema


def software_result_event(payload):
    result=payload["$defs"]["SoftwareTaskResult"]
    return {"type":"object","additionalProperties":False,"required":["kind",*result["required"]],"properties":{"kind":{"const":"software_result"},**copy.deepcopy(result["properties"])}}

def event_variant(schema):
    return next(value for value in schema["properties"]["event"]["oneOf"] if value["properties"]["kind"].get("const")=="software_result")


def write():
    payload = json.loads((SCHEMAS / "task-payload-v4.schema.json").read_text())
    for name, path in EMBEDDED.items():
        file = SCHEMAS / name
        schema = json.loads(file.read_text())
        embedded(schema, path)["oneOf"] = copy.deepcopy(payload["oneOf"])
        schema["$defs"] = copy.deepcopy(payload["$defs"])
        file.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n")
    event_file=SCHEMAS / "task-event-request-v4.schema.json"
    event_schema=json.loads(event_file.read_text())
    variant=event_variant(event_schema);variant.clear();variant.update(software_result_event(payload))
    event_schema["$defs"]=copy.deepcopy(payload["$defs"])
    event_file.write_text(json.dumps(event_schema,indent=2,ensure_ascii=False)+"\n")
    manifest = json.loads(MANIFEST.read_text())
    digest = hashlib.sha256()
    for entry in manifest["schemas"]:
        digest.update((SCHEMAS / entry["file"]).read_bytes())
    source = LIB.read_text()
    source, count = re.subn(r'(pub const SCHEMA_FINGERPRINT: &str =\s*")[0-9a-f]{64}(";)',
                            lambda match: match.group(1) + digest.hexdigest() + match.group(2), source)
    if count != 1:
        raise ValueError("wire fingerprint declaration missing")
    LIB.write_text(source)


def check():
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("wireVersion") != 4:
        raise ValueError("manifest must declare Agent V4")
    files = [entry["file"] for entry in manifest["schemas"]]
    if len(files) != len(set(files)) or not files or any(not name.endswith("-v4.schema.json") for name in files):
        raise ValueError("manifest has duplicate or non-V4 schema entries")
    actual = {path.name for path in SCHEMAS.glob("*.json")}
    if actual != set(files) | {MANIFEST.name}:
        raise ValueError("schema directory differs from the V4 manifest")
    payload = json.loads((SCHEMAS / "task-payload-v4.schema.json").read_text())
    for name, path in EMBEDDED.items():
        schema = json.loads((SCHEMAS / name).read_text())
        if embedded(schema, path)["oneOf"] != payload["oneOf"] or schema.get("$defs") != payload["$defs"]:
            raise ValueError(f"{name}: embedded task contract differs from the canonical payload")
    event=json.loads((SCHEMAS / "task-event-request-v4.schema.json").read_text())
    if event_variant(event)!=software_result_event(payload) or event.get("$defs")!=payload["$defs"]:
        raise ValueError("task-event-request-v4.schema.json: software result differs from the canonical contract")
    digest = hashlib.sha256()
    for name in files:
        data = (SCHEMAS / name).read_bytes()
        schema = json.loads(data)
        if "/agent/v4/" not in schema.get("$id", ""):
            raise ValueError(f"{name}: non-V4 schema identifier")
        digest.update(data)
    expected = re.search(r'pub const SCHEMA_FINGERPRINT: &str =\s*"([0-9a-f]{64})"', LIB.read_text())
    if expected is None or expected.group(1) != digest.hexdigest():
        raise ValueError("schema fingerprint differs from the declared V4 artifact")


def main():
    try:
        if sys.argv[1:] == ["--write"]:
            write()
        elif len(sys.argv) != 1:
            raise ValueError("usage: agent_wire_artifact.py [--write]")
        check()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"agent-wire artifact: {error}", file=sys.stderr)
        return 1
    print("Agent V4 manifest and schemas are complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
