"""Compile/list current Cargo tests and reject ignored tests without an execution owner.

ref: nextest nextest-runner/src/list/test_list.rs@75ddba7e911b44c5c0700dac0415d824403de9bd
Listing runs no test functions or business preparation.
"""
import json
from pathlib import Path
import subprocess

from build_run import lease_fds, require_lease
from ci_registry import ROOT
from verification_result import publish, require


def validate_listing(document, package):
    require(isinstance(document, dict) and isinstance(document.get('rust-suites'), dict),
            'invalid nextest discovery document')
    suites = [suite for suite in document['rust-suites'].values() if suite['package-name'] == package]
    require(bool(suites), 'missing target discovery: ' + package)
    from t2_registry import MODULES, PACKAGE, discover
    owned = list(MODULES) if package == PACKAGE else []
    # One discovery is the authority for both T1 and active ignored T2.
    if owned:
        discover(document, owned, package=package)
    for suite in suites:
        require(suite['status'] == 'listed', 'incomplete target discovery: ' + package)
        for name, case in suite['testcases'].items():
            from t2_registry import owners
            assigned = owners(package, suite.get('binary-name', ''), name)
            require(not case['ignored'] or len(assigned) == 1, 'ignored test has no execution owner: ' + package + '/' + name)


def check_ownership(packages, output):
    require_lease(ROOT)
    output = Path(output)
    require(not output.is_symlink(), 'ownership output cannot be a symlink')
    output.mkdir(parents=True, exist_ok=True)
    require(bool(packages), 'ownership selection cannot be empty')
    flags = [flag for package in packages for flag in ('-p', package)]
    result = subprocess.run(['cargo', 'nextest', 'list', '--locked', '--all-features',
                             *flags, '--message-format', 'json'], cwd=ROOT,
                            pass_fds=lease_fds(), capture_output=True, text=True, timeout=600)
    (output / 'listing.log').write_text(result.stderr)
    require(result.returncode == 0, 'target discovery failed')
    document = json.loads(result.stdout)
    publish(output / 'listing.json', document)
    for package in packages:
        validate_listing(document, package)
