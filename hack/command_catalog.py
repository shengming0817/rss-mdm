#!/usr/bin/env python3
"""Generate/check command admission catalogs only in an isolated migrated T2 database."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("catalog", "dependencies")

def capture(container, mode):
    directory = ROOT / "crates/app/src/commands"
    query = "BEGIN; SET LOCAL ROLE mdm_command_runtime; SET LOCAL search_path=pg_catalog;\n"
    query += "\n".join((directory / f"{name}.sql").read_text() + ";" for name in NAMES)
    query += "\nROLLBACK;"
    result = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input=query, text=True, capture_output=True, check=True)
    values = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if len(values) != len(NAMES):
        raise RuntimeError("command catalog query did not produce both contracts")
    outputs = {directory / f"{name}.json": json.dumps(value, indent=2, sort_keys=True) + "\n" for name, value in zip(NAMES, values, strict=True)}
    if mode == "check":
        mismatches = [path.name for path, content in outputs.items() if json.loads(path.read_text()) != json.loads(content)]
        if mismatches:
            raise RuntimeError("command catalog drift: " + ", ".join(mismatches))
    elif mode == "write":
        pending = []
        try:
            for path, content in outputs.items():
                with tempfile.NamedTemporaryFile(mode="w", dir=directory, prefix=f".{path.name}.", delete=False) as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                    pending.append((Path(output.name), path))
            for temporary, path in pending:
                os.replace(temporary, path)
        finally:
            for temporary, _ in pending:
                temporary.unlink(missing_ok=True)
    else:
        raise ValueError("unknown catalog mode")
    print(f"command catalog {mode}: both contracts match isolated migrations", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    args = parser.parse_args()
    import t2
    t2.main(catalog_mode="check" if args.check else "write")
