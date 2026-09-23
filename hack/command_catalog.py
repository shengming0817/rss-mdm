#!/usr/bin/env python3
"""Generate/check command admission catalogs only in an isolated migrated T2 database."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("catalog", "dependencies", "management")

def capture(container, mode):
    directory = ROOT / "crates/app/src/commands"
    query = "BEGIN; SET LOCAL ROLE mdm_command_runtime; SET LOCAL search_path=pg_catalog;\n"
    paths = {name: (directory / f"{name}.sql") if name != "management" else ROOT / "crates/app/src/management/catalog.sql" for name in NAMES}
    query += "\n".join(paths[name].read_text() + ";" for name in NAMES)
    query += "\nROLLBACK;"
    result = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input=query, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError("command catalog query failed: " + result.stderr)
    values = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if len(values) != len(NAMES):
        raise RuntimeError("command catalog query did not produce all contracts")
    outputs = {paths[name].with_suffix(".json"): json.dumps(value, indent=2, sort_keys=True) + "\n" for name, value in zip(NAMES, values, strict=True)}
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
    # Check actual runtime authority as well as capturing shape. Session identity matters.
    admission = (directory / 'admission.sql').read_text()
    probe = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input="SET SESSION AUTHORIZATION mdm_command_runtime; BEGIN;\n" + admission + ";\nROLLBACK;", text=True, capture_output=True, check=True)
    if probe.stdout.strip() != 't':
        import re
        prefix, predicates = admission.split('\nSELECT ', 1)
        terms = re.split(r'\n AND ', predicates.strip())
        diagnostics = prefix + '\nSELECT ' + ','.join('(' + term.rstrip(';') + ')' for term in terms) + ';'
        result = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input="SET SESSION AUTHORIZATION mdm_command_runtime; BEGIN;\n" + diagnostics + "\nROLLBACK;", text=True, capture_output=True, check=True)
        rejected = [terms[i][:200] for i, value in enumerate(result.stdout.strip().split('|')) if value != 't']
        raise RuntimeError('command runtime admission rejected: ' + repr(rejected))
    print(f"command catalog {mode}: all contracts match isolated migrations", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    args = parser.parse_args()
    import t2
    t2.main(catalog_mode="check" if args.check else "write")
