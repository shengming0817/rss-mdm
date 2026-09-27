#!/usr/bin/env python3
"""Real local HTTPS/Git seams; ephemeral CA and a reviewed non-loopback address."""
import os
import ipaddress
import json
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from build_run import lease_fds, require_lease

ROOT = Path(__file__).resolve().parents[2]

EXPECTED = {
    "winget": {
        "actual_https_exact_protocol_and_credentials",
        "real_https_failures_do_not_look_successful",
        "total_timeout_and_cross_tenant_before_io",
        "chunked_body_is_bounded_without_content_length",
        "manifest_404_is_not_an_information_endpoint_failure",
        "total_budget_spans_information_and_manifest",
        "tls_rejects_untrusted_ca_and_wrong_hostname_before_credentials",
    },
    "brew-git": {
        "git_commit_cas_replay_and_fixed_snapshot",
        "externally_applied_commit_replay_and_repository_binding",
        "symlink_tree_and_symbolic_ref_are_rejected",
        "git_tree_modes_cannot_replace_a_directory_or_document",
        "git_failure_reports_safe_stage_without_raw_diagnostics",
        "conditional_removal_preserves_other_paths_and_old_commits",
    },
    "brew-recovery": {"git::recovery_tests::update_ref_response_loss_reconciles_the_actual_post_failure_head"},
}

def verify_tests(output, expected):
    actual = re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE)
    if (set(actual) != expected or len(actual) != len(expected)
            or f"test result: ok. {len(expected)} passed; 0 failed; 0 ignored;" not in output):
        raise RuntimeError("source T2 did not execute the exact required behaviors")

def run_tests(package, target, expected, env=None):
    result = subprocess.run(
        ["cargo", "test", "--locked", "-p", package, *target, "--", "--ignored", "--color=never"],
        pass_fds=lease_fds(), cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    print(result.stdout, flush=True)
    if result.returncode:
        raise RuntimeError("source T2 cargo test failed")
    verify_tests(result.stdout, expected)

def local_address():
    if os.environ.get("SOURCE_T2_ADDRESS"):
        candidates = [os.environ["SOURCE_T2_ADDRESS"]]
    elif sys.platform == "darwin":
        interfaces = subprocess.check_output(["/sbin/ifconfig"], text=True)
        candidates = re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)", interfaces)
    else:
        interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show"], text=True))
        candidates = [entry["local"] for interface in interfaces for entry in interface["addr_info"]]
    for address in candidates:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            continue
        # Bind before probing so no request is sent to an unrelated remote endpoint.
        try:
            with socket.socket() as listener:
                listener.bind((address, 0))
                listener.listen(1)
                listener.settimeout(0.25)
                with socket.create_connection(listener.getsockname(), timeout=0.25):
                    with listener.accept()[0]:
                        return address
        except OSError:
            continue
    raise RuntimeError("no reachable non-loopback local IPv4 address; set SOURCE_T2_ADDRESS")

def tls_environment(root, context):
    address=local_address()
    context.source_tls(root)
    return dict(os.environ,SOURCE_T2_TLS=str(root),SOURCE_T2_ADDRESS=address)

def main(context):
    require_lease(ROOT)
    failed = []
    with tempfile.TemporaryDirectory(prefix="mdm-source-tls-") as directory:
        try:
            env = tls_environment(Path(directory),context)
            run_tests("rss-mdm-winget-source", ["--test", "t2_http"], EXPECTED["winget"], env)
        except Exception as error:
            print(f"HTTPS fixture setup failed: {error}", file=sys.stderr)
            failed.append("t2_http")
        for name, target in [("brew-git", ["--test", "t2_git"]), ("brew-recovery", ["--lib"])]:
            try:
                run_tests("rss-mdm-brew-source", target, EXPECTED[name])
            except Exception as error:
                print(f"{name} failed: {error}", file=sys.stderr)
                failed.append(name)
    if failed:
        print("Failed source T2 targets: " + ", ".join(failed), file=sys.stderr)
    return int(bool(failed))
