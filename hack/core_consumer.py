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

CORES = ("scope", "policy", "software-release")
# Closed capability admission: names are reviewed here; exact versions/sources
# remain owned by the product Cargo.lock, not a second version inventory.
SUPPORT = frozenset({
    "bumpalo", "cfg-if", "futures-core", "futures-task", "futures-util", "js-sys",
    "once_cell", "pin-project-lite", "proc-macro2", "quote", "rustversion", "slab",
    "syn", "thiserror", "thiserror-impl", "unicode-ident", "uuid", "wasm-bindgen",
    "wasm-bindgen-macro", "wasm-bindgen-macro-support", "wasm-bindgen-shared",
})
HASH_SUPPORT = frozenset({
    "block-buffer", "cpufeatures", "crypto-common", "digest", "generic-array",
    "libc", "sha2", "typenum", "version_check",
})


def verify_closure(data, core, product_source, pin, locked_registry):
    url, rev = pin
    upstream = f"git+{url}?rev={rev}#{rev}"
    ci.require(core in {f"rss-mdm-{name}" for name in CORES}, "unknown pure core")
    allowed = SUPPORT | (HASH_SUPPORT if core in ("rss-mdm-policy", "rss-mdm-software-release") else frozenset())
    roots = set(data["workspace_members"])
    ci.require(len(roots) == 1, "consumer must have exactly one workspace member")
    root = next(iter(roots))
    packages = {p["id"]: p for p in data["packages"]}
    graph = data.get("resolve")
    ci.require(isinstance(graph, dict), "consumer dependency graph is missing")
    nodes = {n["id"]: n for n in graph["nodes"]}
    ci.require(graph["root"] == root and root in nodes, "consumer graph root differs")
    ci.require(set(nodes) == set(packages), "package list and graph differ")
    core_ids = {p["id"] for p in packages.values() if p["name"] == core}
    ci.require(len(core_ids) == 1, "consumer must resolve exactly one tested core")
    direct = nodes[root]["deps"]
    canonical_ids = {p["id"] for p in packages.values() if p["name"] in ("rss-contract", "rss-request-context")}
    ci.require(len(canonical_ids) == 2, "consumer requires the canonical value owners")
    ci.require(len(direct) == 3 and {d["pkg"] for d in direct} == core_ids | canonical_ids,
               "consumer must directly depend on one core and the canonical value owners")
    ci.require(all(d["dep_kinds"] and all(k["kind"] is None and k["target"] is None for k in d["dep_kinds"]) for d in direct), "consumer core edge must be an unconditional normal dependency")
    core_id = next(iter(core_ids))
    ci.require(not packages[core_id].get("features", {}) and not nodes[core_id].get("features", []),
               "pure core features changed: update consumption combinations explicitly")
    ci.require(all(not nodes[key].get("features", []) for key in canonical_ids),
               "canonical value owner features must remain disabled")
    # Cargo owns the resolved edges, including renamed and target dependencies.
    # Traverse normal/build edges: proc-macro/build support belongs to the proof.
    reached, pending = set(), list(core_ids)
    while pending:
        node = pending.pop()
        if node in reached:
            continue
        ci.require(node in nodes, "dependency graph has a missing node")
        reached.add(node)
        for dep in nodes[node]["deps"]:
            kinds = dep["dep_kinds"]
            ci.require(kinds and all(k["kind"] in (None, "build", "dev") for k in kinds), "unknown dependency kind")
            if any(k["kind"] != "dev" for k in kinds):
                pending.append(dep["pkg"])
    ci.require(root not in reached and reached == set(packages) - roots, "packages must belong to the tested core closure")
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
            ci.require(name in allowed, f"unapproved pure-core support dependency: {name}")
            ci.require(source == "registry+https://github.com/rust-lang/crates.io-index", f"unexpected dependency source: {name}")
            ci.require((name, package["version"], source) in locked_registry, f"dependency differs from product lock: {name}")
    ci.require(found == {core, "rss-contract", "rss-request-context"}, "missing tested core or canonical types")


def isolated_env(base):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CARGO_") and k not in ("CLIPPY_CONF_DIR", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN")}
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
    if core == "software-release":
        shutil.copyfile(source / "crates" / core / "tests/version.rs", root / "tests/version.rs")
    product = f"rss-mdm-{core}"
    manifest = '\n'.join([
        '[package]', f'name = "{name}-consumer"', 'version = "0.0.0"', 'edition = "2024"',
        '[workspace]', '[dependencies]',
        f'{product} = {{ git = {json.dumps(source.as_uri())}, rev = "{head}", default-features = {str(defaults).lower()} }}',
        *[f'{owner} = {{ git = {json.dumps(pin[0])}, rev = "{pin[1]}", default-features = false }}'
          for owner in ("rss-contract", "rss-request-context")],
        '',
    ])
    (root / "Cargo.toml").write_text(manifest)
    shutil.copyfile(source / "Cargo.lock", root / "Cargo.lock")
    env = isolated_env(root)
    env["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true"
    # Explicit pin also overrides ambient rustup directory overrides.
    env["RUSTUP_TOOLCHAIN"] = ci.tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
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

    toolchain = {"rustc": run(["rustc", "-Vv"]), "cargo": run(["cargo", "-V"])}
    # Prepare a consumer-specific lock, seeded with the product's locked dependencies.
    run(["cargo", "metadata", "--format-version", "1"])
    lock = root / "Cargo.lock"
    lock_digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    data = json.loads(run(["cargo", "metadata", "--locked", "--format-version", "1"]))
    locked_registry = {(p["name"], p["version"], p.get("source")) for p in ci.tomllib.loads((source / "Cargo.lock").read_text())["package"] if p.get("source", "").startswith("registry+")}
    verify_closure(data, product, f"git+{source.as_uri()}?rev={head}#{head}", pin, locked_registry)
    (out / f"{name}-metadata.json").write_text(json.dumps(data))
    (out / f"{name}-tree.txt").write_text(run(["cargo", "tree", "--locked", "-e", "features"]))
    run(["cargo", "check", "--locked"])
    run(["cargo", "test", "--locked"])
    ci.require(hashlib.sha256(lock.read_bytes()).hexdigest() == lock_digest, "consumer lock changed during locked verification")
    shutil.copyfile(lock, out / f"{name}-Cargo.lock")
    return {"package": product, "defaultFeatures": defaults, "head": head, "rssRevision": pin[1],
            "lockSha256": lock_digest, "commands": commands, "status": "passed", "toolchain": toolchain,
            "features": {p["id"]: p["features"] for p in data["resolve"]["nodes"]}}


def prepare_output(out):
    # This directory owns only regenerable artifacts from this gate.
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)


def main():
    out = ci.OUT / "core-consumers"
    prepare_output(out)
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
