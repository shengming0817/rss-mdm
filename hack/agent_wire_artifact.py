#!/usr/bin/env python3
"""Task payload schema is canonical; derive embeddings, then verify the V5 artifact."""
import hashlib
import json
from pathlib import Path
import re
import sys
import copy

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "crates/agent-wire/schema"
MANIFEST = SCHEMAS / "agent-v5.schema-manifest.json"
LIB = ROOT / "crates/agent-wire/src/lib.rs"
EMBEDDED = {
    "signed-task-v5.schema.json": ("properties", "payload"),
    "task-claim-response-v5.schema.json": ("properties", "task", "oneOf", 1, "properties", "payload"),
    "task-event-ack-v5.schema.json": ("properties", "permit", "oneOf", 1, "properties", "payload"),
}


def embedded(schema, path):
    for part in path:
        schema = schema[part]
    return schema


def collection_definitions():
    def obj(properties):
        return {"type":"object","additionalProperties":False,"required":list(properties),"properties":properties}
    def ref(name):
        return {"$ref":"#/$defs/"+name}
    key={"type":"string","maxLength":128,"pattern":r"^(device|custom|channel)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"}
    prop={"type":"string","maxLength":64,"pattern":"^[a-z][a-z0-9_]*$"}
    bounded={"type":"string","minLength":1,"maxLength":128,"pattern":r"^[^\u0000-\u001F\u007F]+$"}
    types=[obj({"kind":{"const":kind}}) for kind in ("integer","number","boolean","time")]
    types += [obj({"kind":{"const":"string"},"maxLength":{"type":"integer","minimum":1,"maximum":65536},"allowEmpty":{"type":"boolean"}}),
        obj({"kind":{"const":"enum"},"values":{"type":"array","minItems":1,"maxItems":128,"uniqueItems":True,"items":{"type":"string","minLength":1,"maxLength":256}}}),
        obj({"kind":{"const":"array"},"items":ref("fieldType"),"maxItems":{"type":"integer","minimum":1,"maximum":100000}}),
        obj({"kind":{"const":"object"},"properties":{"type":"object","minProperties":1,"maxProperties":64,"propertyNames":prop,"additionalProperties":ref("fieldType")}})]
    sources=["mdm.windows","mdm.apple","agent.builtin","agent.script","agent.osquery"]
    field=obj({"key":key,"version":{"type":"integer","minimum":1,"maximum":9223372036854775807},"valueType":ref("fieldType"),
        "nullable":{"type":"boolean"},"manual":{"type":"boolean"},"sources":{"type":"object","minProperties":1,"propertyNames":{"enum":sources+["manual"]},"additionalProperties":{"type":"integer","minimum":0,"maximum":65535}},
        "platforms":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":True,"items":{"enum":["windows","macos"]}},
        "sensitivity":{"enum":["standard","sensitive"]},"unit":{"type":["string","null"],"minLength":1,"maxLength":64},"searchable":{"type":"boolean"},"itemKey":{"anyOf":[prop,{"type":"null"}]}})
    scalar=[]
    for kind,shape in [("string",{"type":"string","maxLength":65536}),("integer",{"type":"integer","minimum":-9223372036854775808,"maximum":9223372036854775807}),
        ("number",{"type":"number"}),("boolean",{"type":"boolean"}),("time",{"type":"integer"}),
        ("array",{"type":"array","maxItems":100000,"items":ref("scalar")}),
        ("object",{"type":"object","maxProperties":64,"propertyNames":prop,"additionalProperties":ref("scalar")})]:
        scalar.append(obj({"kind":{"const":kind},"value":shape}))
    return {"fieldType":{"oneOf":types},"fieldDefinition":field,"scalar":{"oneOf":scalar},
        "collection":obj({"dataset":bounded,"version":bounded,"source":{"enum":sources},"fields":{"type":"array","minItems":1,"maxItems":128,"items":ref("fieldDefinition")}}),
        "fieldValue":obj({"field":key,"value":{"oneOf":[obj({"kind":{"const":"value"},"value":ref("scalar")}),obj({"kind":{"const":"null"}}),obj({"kind":{"const":"deleted"}}),obj({"kind":{"const":"unsupported"}})]}})}


def write_collections():
    for name in ["report-request-v5.schema.json","registration-receipt-v5.schema.json"]:
        path=SCHEMAS/name
        schema=json.loads(path.read_text())
        schema.setdefault("$defs",{}).update(collection_definitions())
        if name.startswith("report-"):
            schema["required"]=list(dict.fromkeys(schema["required"]+["collection"]))
            schema["properties"]["collection"]={"$ref":"#/$defs/collection"}
            schema["$defs"]["valuesBody"]["properties"]["values"]={"type":"array","maxItems":128,"items":{"$ref":"#/$defs/fieldValue"}}
        else:
            schema["required"]=list(dict.fromkeys(schema["required"]+["collections"]))
            schema["properties"]["collections"]={"type":"array","minItems":1,"maxItems":16,"items":{"$ref":"#/$defs/collection"}}
        path.write_text(json.dumps(schema,indent=2)+"\n")


def write():
    write_collections()
    payload = json.loads((SCHEMAS / "task-payload-v5.schema.json").read_text())["oneOf"]
    for name, path in EMBEDDED.items():
        file = SCHEMAS / name
        schema = json.loads(file.read_text())
        embedded(schema, path)["oneOf"] = copy.deepcopy(payload)
        file.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n")
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
    if manifest.get("wireVersion") != 5:
        raise ValueError("manifest must declare Agent V5")
    files = [entry["file"] for entry in manifest["schemas"]]
    if len(files) != len(set(files)) or not files or any(not name.endswith("-v5.schema.json") for name in files):
        raise ValueError("manifest has duplicate or non-V5 schema entries")
    actual = {path.name for path in SCHEMAS.glob("*.json")}
    if actual != set(files) | {MANIFEST.name}:
        raise ValueError("schema directory differs from the V5 manifest")
    for name in ["report-request-v5.schema.json","registration-receipt-v5.schema.json"]:
        definitions=json.loads((SCHEMAS/name).read_text()).get("$defs",{})
        if any(definitions.get(key)!=value for key,value in collection_definitions().items()):
            raise ValueError(f"{name}: collection contracts differ from their canonical schema")
    payload = json.loads((SCHEMAS / "task-payload-v5.schema.json").read_text())["oneOf"]
    for name, path in EMBEDDED.items():
        if embedded(json.loads((SCHEMAS / name).read_text()), path)["oneOf"] != payload:
            raise ValueError(f"{name}: embedded task contract differs from the canonical payload")
    digest = hashlib.sha256()
    for name in files:
        data = (SCHEMAS / name).read_bytes()
        schema = json.loads(data)
        if "/agent/v5/" not in schema.get("$id", ""):
            raise ValueError(f"{name}: non-V5 schema identifier")
        digest.update(data)
    expected = re.search(r'pub const SCHEMA_FINGERPRINT: &str =\s*"([0-9a-f]{64})"', LIB.read_text())
    if expected is None or expected.group(1) != digest.hexdigest():
        raise ValueError("schema fingerprint differs from the declared V5 artifact")


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
    print("Agent V5 manifest and schemas are complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
