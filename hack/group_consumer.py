#!/usr/bin/env python3
"""Explicit Group public API consumer acceptance from a committed Git revision."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

import ci

ROOT = ci.ROOT
OUT = ROOT / "artifacts" / "group-consumer"
command = ci.command
noninteractive = ci.noninteractive
require = ci.require
workspace_pin = ci.workspace_pin

# Capability families include their subcrates (e.g. sqlx-postgres, hyper-util).
# Product/RSS owners are separately restricted to Group and its two value types.
GROUP_FORBIDDEN_DEPENDENCIES = {
    "http", "hyper", "reqwest", "ureq", "surf", "awc", "attohttpc", "isahc",
    "axum", "actix-web", "warp", "tide", "poem", "rocket", "salvo",
    "postgres", "tokio-postgres", "sqlx", "diesel", "sea-orm", "sea-query",
    "deadpool-postgres", "bb8-postgres",
}

def verify_group_consumer(data, group_source, pin):
    """Check resolved package identities and the actual production dependency edges."""
    packages = {p["id"]: p for p in data["packages"]}
    root = data["resolve"]["root"]
    require(data["workspace_members"] == [root], "consumer must be the sole workspace member")
    require(packages[root]["name"] == "group-consumer" and packages[root]["source"] is None, "invalid consumer root")
    value_types = {"rss-contract", "rss-request-context"}
    expected_rss = f"git+{pin[0]}?rev={pin[1]}#{pin[1]}"
    group_ids = []
    for key, package in packages.items():
        name, source = package["name"], package["source"]
        if key == root:
            continue
        if name == "rss-mdm-group":
            require(source == group_source, "Group source must equal the tested Git SHA")
            group_ids.append(key)
        elif name.startswith("rss-"):
            require(name in value_types and source == expected_rss, "unexpected RSS/product dependency or revision")
        else:
            require(source and source.startswith("registry+https://github.com/rust-lang/crates.io-index"), "unexpected path/source in consumer closure")
    require(len(group_ids) == 1, "exactly one Group package required")
    nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
    require(packages[group_ids[0]]["features"] == {} and nodes[group_ids[0]]["features"] == [], "Group feature surface changed; extend the consumer matrix explicitly")
    def dependencies(key):
        return {packages[d["pkg"]]["name"] for d in nodes[key]["deps"]}
    require(dependencies(root) == value_types | {"rss-mdm-group"}, "consumer must directly use only Group and its public value types")
    require(dependencies(group_ids[0]) == value_types, "Group must depend only on public tenant/time values")
    visited, todo = set(), [group_ids[0]]
    while todo:
        key = todo.pop()
        if key in visited:
            continue
        visited.add(key)
        name = packages[key]["name"]
        require(not any(name == banned or name.startswith(banned + "-") for banned in GROUP_FORBIDDEN_DEPENDENCIES),
                f"forbidden Group production dependency: {name}")
        for dep in nodes[key]["deps"]:
            # Include normal/build edges on every target; dependency tests are not production.
            if any(kind.get("kind") != "dev" for kind in dep.get("dep_kinds", [{"kind": None}])):
                todo.append(dep["pkg"])


def group_consumer(head):
    """One package consumed from committed Git source; fixture source stays in Group tests."""
    (OUT / "group-consumer.log").write_text(f"tested HEAD: {head}\n")
    status = command(["/usr/bin/git", "status", "--porcelain"])
    require(status.returncode == 0 and not status.stdout.strip(), "commit inputs before Group consumer proof")
    pin = workspace_pin(ROOT)
    url = ROOT.as_uri()
    with tempfile.TemporaryDirectory(prefix="mdm-group-consumer-", dir="/tmp") as directory:
        base = Path(directory).resolve()
        consumer = base / "consumer"
        (consumer / "tests").mkdir(parents=True)
        for parent in [consumer, *consumer.parents]:
            for name in ["config", "config.toml"]:
                require(not (parent / ".cargo" / name).exists(), "ancestor Cargo config leaks into consumer")
        # Own only credential transport configuration; do not inherit parent build/features.
        (consumer / ".cargo").mkdir()
        (consumer / ".cargo/config.toml").write_text("[net]\ngit-fetch-with-cli = true\n")
        for source, destination in [("crates/group/tests/consumer.rs", "tests/consumer.rs"), ("rust-toolchain.toml", "rust-toolchain.toml")]:
            result = command(["/usr/bin/git", "show", f"{head}:{source}"])
            require(result.returncode == 0, result.stdout)
            (consumer / destination).write_text(result.stdout)
        manifest = '[workspace]\n[package]\nname = "group-consumer"\nversion = "0.0.0"\nedition = "2024"\n[dependencies]\n'
        for name, source, rev in [("rss-mdm-group", url, head), ("rss-contract", *pin), ("rss-request-context", *pin)]:
            options = '' if name == 'rss-mdm-group' else ', default-features = false'
            manifest += f'{name} = {{ git = {json.dumps(source)}, rev = {json.dumps(rev)}{options} }}\n'
        (consumer / "Cargo.toml").write_text(manifest)
        env = {k:v for k,v in os.environ.items() if not k.startswith("CARGO_") and k not in ("CLIPPY_CONF_DIR", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")}
        env.update(CARGO_HOME=str(base / "cargo-home"), CARGO_TARGET_DIR=str(base / "target"))
        env["PATH"] = "/usr/bin:" + env.get("PATH", "")
        logs = [f"tested HEAD: {head}"]
        for args in [["cargo", "generate-lockfile"], ["cargo", "check", "--locked"], ["cargo", "test", "--locked"],
                     ["cargo", "metadata", "--locked", "--format-version", "1"], ["cargo", "tree", "--locked", "-e", "features"]]:
            result = subprocess.run(args, cwd=consumer, env=noninteractive(env), stdin=subprocess.DEVNULL, text=True, capture_output=True)
            logs.append("$ " + " ".join(args) + "\n" + result.stdout + result.stderr)
            (OUT / "group-consumer.log").write_text("\n".join(logs))
            require(result.returncode == 0, "Group consumer command failed; see group-consumer.log")
            if args[1] == "metadata":
                verify_group_consumer(json.loads(result.stdout), f"git+{url}?rev={head}#{head}", pin)
                (OUT / "group-metadata.json").write_text(result.stdout)
            if args[1] == "tree":
                (OUT / "group-tree.txt").write_text(result.stdout)
        lock = (consumer / "Cargo.lock").read_bytes()
        (OUT / "group-consumer.lock").write_bytes(lock)
        (OUT / "group-consumer.json").write_text(json.dumps({"head": head, "rssRevision": pin[1], "lockSha256": hashlib.sha256(lock).hexdigest(),
            "features": "Group defaults enabled; empty declared/resolved feature sets verified", "source": "local committed Git revision", "T3": "not run"}, indent=2) + "\n")



def main():
    if OUT.is_symlink():
        raise RuntimeError("group consumer output must not be a symlink")
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    head = command(["/usr/bin/git", "rev-parse", "HEAD"])
    require(head.returncode == 0, "cannot resolve tested HEAD")
    group_consumer(head.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
