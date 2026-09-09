#!/usr/bin/env python3
"""Optional fixture regeneration: Python + PyYAML 6.0.3; not a CI dependency."""
import hashlib
import json
from pathlib import Path
import urllib.request
import yaml

REV = "21cd5dda3dab39aa059f4d34914959736af7ee70"
URL = f"https://raw.githubusercontent.com/microsoft/winget-cli-restsource/{REV}/documentation/WinGet-1.0.0.yaml"
SHA256 = "53a861e5630c6e62a8cdcb957e5f75d2395a10395c60a425556b4f3d0f661377"

def main():
    raw = urllib.request.urlopen(URL, timeout=30).read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise RuntimeError("upstream schema identity mismatch")
    schemas = yaml.safe_load(raw)["components"]["schemas"]
    found = set()
    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                name = value["$ref"].split("/")[-1]
                if name not in found:
                    found.add(name)
                    visit(schemas[name])
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    def normalize(value):
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {key: normalize(item) for key, item in value.items() if key not in ("nullable", "description")}
        return {"anyOf": [result, {"type": "null"}]} if value.get("nullable") else result
    visit({"$ref": "#/components/schemas/ManifestSchema"})
    result = {"$schema": "http://json-schema.org/draft-07/schema#", "$ref": "#/components/schemas/ManifestSchema", "components": {"schemas": normalize({key: schemas[key] for key in sorted(found)})}}
    Path(__file__).with_name("publish-schema.json").write_text(json.dumps(result, indent=2) + "\n")

if __name__ == "__main__":
    main()
