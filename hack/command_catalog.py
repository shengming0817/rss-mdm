#!/usr/bin/env python3
"""Generate/check command admission catalogs only in an isolated migrated T2 database."""
import argparse
import json
import os
from pathlib import Path
from t2_processes import subprocess
import tempfile
from build_run import lease_fds

ROOT = Path(__file__).resolve().parents[1]
CATALOGS = {'compliance': 'compliance-postgres/src/catalog', 'catalog': 'flow-service/src/execution/catalog', 'dependencies': 'flow-service/src/execution/dependencies', 'planning': 'flow-service/src/planning/catalog', 'assets': 'inventory-service/src/assets/catalog', 'automation': 'flow-service/src/automation/catalog', 'resources': 'flow-service/src/resource_catalog/catalog', 'publication': 'flow-service/src/software_publication/http_catalog', 'software': 'software-service/src/catalog/catalog', 'content': 'content-service/src/catalog', 'flow': 'flow-service/src/storage/catalog'}
NAMES = tuple(CATALOGS)

def capture(container, mode, database):
    directory = ROOT / "crates/flow-service/src/execution"
    query = "BEGIN; SET LOCAL ROLE mdm_command_runtime; SET LOCAL search_path=pg_catalog;\n"
    paths = {name: ROOT / "crates" / (relative + ".sql") for name, relative in CATALOGS.items()}
    query += "\n".join(paths[name].read_text() + ";" for name in NAMES)
    query += "\nROLLBACK;"
    result = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], input=query, text=True, capture_output=True, pass_fds=lease_fds())
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
    probe = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], input="SET SESSION AUTHORIZATION mdm_command_runtime; BEGIN;\n" + admission + ";\nROLLBACK;", text=True, capture_output=True, check=True, pass_fds=lease_fds())
    if probe.stdout.strip() != 't':
        import re
        prefix, predicates = admission.split('\nSELECT ', 1)
        terms = re.split(r'\n AND ', predicates.strip())
        diagnostics = prefix + '\nSELECT ' + ','.join('(' + term.rstrip(';') + ')' for term in terms) + ';'
        result = subprocess.run(["docker", "exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], input="SET SESSION AUTHORIZATION mdm_command_runtime; BEGIN;\n" + diagnostics + "\nROLLBACK;", text=True, capture_output=True, check=True, pass_fds=lease_fds())
        rejected = [terms[i][:200] for i, value in enumerate(result.stdout.strip().split('|')) if value != 't']
        raise RuntimeError('command runtime admission rejected: ' + repr(rejected))
    print(f"command catalog {mode}: all contracts match isolated migrations", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true',required=True)
    args=parser.parse_args()
    from build_run import require_lease
    require_lease(ROOT)
    from t2_registry import MODULES
    from t2_execution import Builds, Processes, Invocation
    from t2_fixtures import RunFixtures
    processes=Processes()
    try:
        with tempfile.TemporaryDirectory(prefix='mdm-catalog-') as temporary:
            output=Path(temporary)
            module=MODULES['catalog.contract']
            builds=Builds(output,processes)
            builds.prepare([module])
            with RunFixtures(builds,output,1) as fixtures:
                job=Invocation(module,None)
                fixtures.prepare([job])
                with fixtures.scenario(job,output/'scenario',dict(environment=fixtures.evidence(job))) as fixture:
                    capture(fixture.owner.container(),'write',fixture.database)
    finally:
        processes.close()
