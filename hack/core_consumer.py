#!/usr/bin/env python3
"""Run each pure core's public behavior suite as an isolated fixed-SHA Git consumer."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import ci

CORES = ("scope", "policy")
# Provider/runtime families cannot appear transitively in a pure decision core.
FORBIDDEN = ("sqlx", "postgres", "tokio", "hyper", "reqwest", "axum", "actix", "async-std", "surf", "ureq", "diesel")


def verify_closure(data, core, product_source, pin):
    url, rev = pin
    upstream = f"git+{url}?rev={rev}#{rev}"
    roots = set(data["workspace_members"])
    ci.require(len(roots) == 1, "consumer must have exactly one workspace member")
    found = set()
    for package in data["packages"]:
        name, source = package["name"], package["source"]
        if package["id"] in roots:
            ci.require(source is None, "consumer root must be local")
        elif name == core:
            ci.require(source == product_source, "core must use the tested Git SHA")
            found.add(name)
        elif name in ("rss-contract", "rss-request-context"):
            ci.require(source == upstream, "canonical RSS source differs")
            found.add(name)
        else:
            ci.require(not name.startswith("rss-"), f"unrelated RSS/product dependency: {name}")
            ci.require(not any(name == p or name.startswith(p + "-") for p in FORBIDDEN), f"provider/runtime in pure core: {name}")
            ci.require(source == "registry+https://github.com/rust-lang/crates.io-index", f"unexpected dependency source: {name}")
    ci.require(found == {core, "rss-contract", "rss-request-context"}, "missing tested core or canonical types")


def isolated_env(base):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CARGO_") and k not in ("CLIPPY_CONF_DIR", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")}
    env.update(CARGO_HOME=str(base / "cargo-home"), CARGO_TARGET_DIR=str(base / "target"))
    return ci.noninteractive(env)


def check_ancestors(root):
    for directory in (root, *root.parents):
        for name in ("config", "config.toml"):
            ci.require(not (directory / ".cargo" / name).exists(), f"unexpected ancestor Cargo configuration: {directory}")


def run_consumer(source, base, core, defaults, head, pin, out):
    name = f"{core}-{'default' if defaults else 'no-default'}"
    root = base / name
    root.mkdir()
    check_ancestors(root)
    (root / "tests").mkdir()
    shutil.copyfile(source / "rust-toolchain.toml", root / "rust-toolchain.toml")
    # The same public API behavior assertions run inside and outside the workspace.
    shutil.copyfile(source / "crates" / core / "tests/model.rs", root / "tests/model.rs")
    url, rev = pin
    product = f"rss-mdm-{core}"
    manifest = '\n'.join([
        '[package]', f'name = "{name}-consumer"', 'version = "0.0.0"', 'edition = "2024"',
        '[workspace]', '[dependencies]',
        f'{product} = {{ git = {json.dumps(source.as_uri())}, rev = "{head}", default-features = {str(defaults).lower()} }}',
        *[f'{p} = {{ git = {json.dumps(url)}, rev = "{rev}", default-features = false }}' for p in ("rss-contract", "rss-request-context")], '',
    ])
    (root / "Cargo.toml").write_text(manifest)
    shutil.copyfile(source / "Cargo.lock", root / "Cargo.lock")
    env = isolated_env(root)
    env["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true"
    log = out / f"{name}.log"
    log.write_text("")
    commands = []

    def run(args):
        result = subprocess.run(args, cwd=root, env=env, stdin=subprocess.DEVNULL, text=True, capture_output=True)
        with log.open("a") as stream:
            stream.write(json.dumps(args) + "\n" + result.stderr)
            if args[:2] != ["cargo", "metadata"]:
                stream.write(result.stdout)
        commands.append({"argv": args, "exitCode": result.returncode})
        ci.require(result.returncode == 0, f"{name}: command failed; see {log}")
        return result.stdout

    # Prepare a consumer-specific lock, seeded with the product's locked dependencies.
    run(["cargo", "metadata", "--format-version", "1"])
    lock = root / "Cargo.lock"
    lock_digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    data = json.loads(run(["cargo", "metadata", "--locked", "--format-version", "1"]))
    verify_closure(data, product, f"git+{source.as_uri()}?rev={head}#{head}", pin)
    (out / f"{name}-metadata.json").write_text(json.dumps(data))
    (out / f"{name}-tree.txt").write_text(run(["cargo", "tree", "--locked", "-e", "features"]))
    run(["cargo", "check", "--locked"])
    run(["cargo", "test", "--locked"])
    ci.require(hashlib.sha256(lock.read_bytes()).hexdigest() == lock_digest, "consumer lock changed during locked verification")
    shutil.copyfile(lock, out / f"{name}-Cargo.lock")
    return {"package": product, "defaultFeatures": defaults, "head": head, "rssRevision": rev,
            "lockSha256": lock_digest, "commands": commands, "status": "passed",
            "features": {p["id"]: p["features"] for p in data["resolve"]["nodes"]}}


def main():
    out = ci.OUT / "core-consumers"
    out.mkdir(parents=True, exist_ok=True)
    head = ci.command(["/usr/bin/git", "rev-parse", "HEAD"]).stdout.strip()
    ci.require(ci.command(["/usr/bin/git", "status", "--porcelain"]).stdout.strip() == "", "commit implementation before core consumer verification")
    results = []
    with tempfile.TemporaryDirectory(prefix="mdm-core-consumer-", dir="/tmp") as directory:
        base = Path(directory).resolve()
        source = base / "source"
        subprocess.run(["/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(ci.ROOT), str(source)], check=True, env=ci.noninteractive())
        subprocess.run(["/usr/bin/git", "-C", str(source), "checkout", "--quiet", "--detach", head], check=True, env=ci.noninteractive())
        pin = ci.workspace_pin(source)
        for core in CORES:
            for defaults in (True, False):
                try:
                    result = run_consumer(source, base, core, defaults, head, pin, out)
                except Exception as error:
                    result = {"package": f"rss-mdm-{core}", "defaultFeatures": defaults, "head": head, "status": "failed", "error": str(error)}
                results.append(result)
                print(json.dumps(result), flush=True)
    (out / "result.json").write_text(json.dumps(results, indent=2) + "\n")
    return int(any(r["status"] != "passed" for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
