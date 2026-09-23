#!/usr/bin/env python3
"""Actual million-device PostgreSQL acceptance. Synthetic identities are not device T3."""
import argparse
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/capacity"
CASES = {
    "static": ("rss-mdm-group-postgres", "capacity", "million_static_members_use_linear_storage_and_reject_one_more"),
    "dynamic": ("rss-mdm-group-postgres", "capacity", "million_dynamic_members_cover_zero_single_percent_and_full_changes"),
    "policy": ("rss-mdm-policy-postgres", "capacity", "million_targets_and_multiversion_history_remain_bounded"),
    "scope": ("rss-mdm-app", None, "management::tests::capacity::million_scope_pages_and_overflow_use_product_worker"),
}

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"hack/{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def output(args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def hardware():
    info = {"platform": platform.platform(), "architecture": platform.machine(), "cpu_count": os.cpu_count()}
    if sys.platform == "darwin":
        info.update(memory_bytes=int(output(["sysctl", "-n", "hw.memsize"])), model=output(["sysctl", "-n", "hw.model"]))
    info["docker"] = json.loads(output(["docker", "info", "--format", '{{json .}}']))
    info["docker"] = {key: info["docker"][key] for key in ("NCPU", "MemTotal", "Architecture", "OSType")}
    return info


def measure(name, head):
    package, target, test = CASES[name]
    owner = module("group-t2" if name in ("static", "dynamic") else "backend-t2")
    args = ["cargo", "test", "--locked", "-p", package, "--features", "integration"]
    args += ["--test", target] if target else ["--lib"]
    build = subprocess.run(args + ["--no-run", "--message-format=json"], cwd=ROOT, text=True, capture_output=True)
    (OUT / f"{name}-build.log").write_text(build.stdout + build.stderr)
    if build.returncode:
        raise RuntimeError(f"{name}: capacity build failed")
    binaries = [entry["executable"] for line in build.stdout.splitlines() if line.startswith("{")
                for entry in [json.loads(line)] if entry.get("reason") == "compiler-artifact" and entry.get("executable")]
    if len(binaries) != 1:
        raise RuntimeError(f"{name}: ambiguous capacity test binary")
    options = {"metrics": True}
    if name == "scope":
        options["app"] = True
    with owner.fixture(**options) as (env, sql):
        fixture_config = json.loads(Path(env["GROUP_PG_CONFIG" if name in ("static", "dynamic") else "BACKEND_PG_CONFIG"]).read_text())
        container = fixture_config["container"]
        settings = json.loads(sql("SELECT json_object_agg(name,setting||coalesce(unit,'')) FROM pg_settings WHERE name IN('server_version','shared_buffers','work_mem','maintenance_work_mem','max_connections','max_wal_size')"))
        before = int(sql("SELECT pg_database_size(current_database())"))
        sql("SELECT capacity_metrics.pg_stat_statements_reset()")
        stopped = threading.Event()
        samples = {"samples": 0, "max_open_transaction_seconds": 0.0, "lock_wait_samples": 0, "monitor_errors": [], "peak_database_container_memory_bytes": 0}

        def monitor():
            while not stopped.wait(1):
                try:
                    row = json.loads(sql("SELECT json_build_object('transaction',coalesce(max(extract(epoch FROM clock_timestamp()-xact_start)),0),'locks',count(*) FILTER(WHERE wait_event_type='Lock')) FROM pg_stat_activity WHERE datname=current_database() AND usename<>'postgres'"))
                    memory = int(subprocess.check_output(["docker", "exec", container, "cat", "/sys/fs/cgroup/memory.current"], text=True, timeout=5).strip())
                    samples["peak_database_container_memory_bytes"] = max(samples["peak_database_container_memory_bytes"], memory)
                    samples["samples"] += 1
                    samples["max_open_transaction_seconds"] = max(samples["max_open_transaction_seconds"], row["transaction"])
                    samples["lock_wait_samples"] += row["locks"]
                except Exception as error:
                    samples["monitor_errors"].append(type(error).__name__)

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        resource_file = OUT / f"{name}-resources.txt"
        timer = ["/usr/bin/time", "-l"] if sys.platform == "darwin" else ["/usr/bin/time", "-v"]
        started = time.monotonic()
        try:
            with resource_file.open("w") as resource, (OUT / f"{name}.log").open("w") as log:
                process = subprocess.Popen(timer + [binaries[0], test, "--exact", "--ignored", "--nocapture"], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=resource)
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    print(line, end="", flush=True)
                code = process.wait()
        finally:
            stopped.set()
            thread.join(timeout=35)
        elapsed = time.monotonic() - started
        resources = resource_file.read_text()
        rss = re.search(r"(\d+)\s+maximum resident set size", resources) if sys.platform == "darwin" else re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", resources)
        statistics = json.loads(sql("SELECT json_build_object('calls',coalesce(sum(calls),0),'total_exec_ms',coalesce(sum(total_exec_time),0),'max_statement_ms',coalesce(max(max_exec_time),0),'rows',coalesce(sum(rows),0),'wal_bytes',coalesce(sum(wal_bytes),0)) FROM capacity_metrics.pg_stat_statements WHERE userid<>(SELECT oid FROM pg_roles WHERE rolname='postgres')"))
        after = int(sql("SELECT pg_database_size(current_database())"))
        log = (OUT / f"{name}.log").read_text()
        passed = code == 0 and f"test {test} ... ok" in log and "test result: ok. 1 passed; 0 failed; 0 ignored;" in log
        passed = passed and rss is not None and samples["samples"] > 0 and not samples["monitor_errors"]
        result = {"head": head, "case": name, "passed": passed, "elapsed_seconds": elapsed, "peak_test_rss_bytes": int(rss[1]) * (1 if sys.platform == "darwin" else 1024) if rss else None,
                  "database_bytes_before": before, "database_bytes_after": after, "database_growth_bytes": after-before,
                  "postgresql": settings, "sql": statistics, "sampling": samples, "resources_file": resource_file.name,
                  "limits": "1,000,000 current devices; pages <=1,000 objects and 16 MiB; no fixed duration guarantee", "memory_note": "test RSS excludes PostgreSQL; container memory includes PostgreSQL and charged filesystem cache", "T3": "not run; synthetic device identities"}
        (OUT / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        return passed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=CASES, action="append")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    head = output(["/usr/bin/git", "rev-parse", "HEAD"])
    record = {"head": head, "hardware": hardware(), "cases": {}, "clean_at_start": not output(["/usr/bin/git", "status", "--porcelain"]), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    for name in args.case or CASES:
        print(f"capacity: {name}", flush=True)
        try:
            record["cases"][name] = "passed" if measure(name, head) else "failed"
        except Exception as error:
            record["cases"][name] = "failed"
            (OUT / f"{name}-error.txt").write_text(str(error) + "\n")
            print(f"capacity {name}: {error}", flush=True)
    record["same_head_at_end"] = head == output(["/usr/bin/git", "rev-parse", "HEAD"])
    (OUT / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    return int(not record["same_head_at_end"] or any(v != "passed" for v in record["cases"].values()))


if __name__ == "__main__":
    sys.exit(main())
