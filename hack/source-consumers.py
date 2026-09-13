#!/usr/bin/env python3
"""Fixed-HEAD, one-product-package consumers outside both source workspaces."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "source-consumers"
PACKAGES = {"resource": "model.rs", "winget-source": "protocol.rs", "brew-source": "templates.rs"}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def verify_graph(data, product, product_source, rss_source):
    packages = {p["id"]: p for p in data["packages"]}
    product_nodes = [p for p in packages.values() if p["name"].startswith("rss-mdm-")]
    require(len(product_nodes) == 1 and product_nodes[0]["name"] == product, "consumer must contain exactly the selected product package")
    require(product_nodes[0]["source"] == product_source, "product source must be exact submitted Git HEAD")
    for package in packages.values():
        if package["name"].startswith("rss-") and package["name"] != product:
            require(package["source"] == rss_source, "RSS source identity mismatch")
    nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
    declared = product_nodes[0].get("features", {})
    selected = nodes[product_nodes[0]["id"]].get("features", [])
    require(not declared and not selected, "product features changed: update independent consumer matrix explicitly")
    pending = [product_nodes[0]["id"]]
    seen = set()
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        package = packages[key]
        name = package["name"]
        require("postgres" not in name and name not in ("sqlx", "sqlx-core", "sqlx-postgres"), "PG leaked into source core")
        if product == "rss-mdm-resource":
            require(name not in ("reqwest", "hyper", "tokio", "url"), "transport leaked into resource")
        if product == "rss-mdm-brew-source":
            require(name not in ("reqwest", "hyper", "hyper-util", "hyper-rustls"), "HTTP leaked into Brew")
        if name == "tokio":
            allowed = ({"default", "rt", "net", "time", "sync", "io-util", "bytes", "mio", "socket2", "libc", "windows-sys"}
                       if product == "rss-mdm-winget-source" else
                       {"process", "io-util", "time", "macros", "tokio-macros", "bytes", "mio", "libc", "signal-hook-registry", "windows-sys"})
            require(set(nodes[key].get("features", [])) <= allowed, "unexpected Tokio feature expansion")
        for dependency in nodes[key]["deps"]:
            if any(k["kind"] is None for k in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return sorted(packages[key]["name"] for key in seen)

def collect_consumers(run_one):
    """Setup failures and command failures have the same per-package boundary."""
    records = {}
    for name, test in PACKAGES.items():
        try:
            records[name] = run_one(name, test)
        except Exception as error:
            records[name] = {"status": "failed", "error": str(error)}
    return records


def run_consumer(name, test, checkout, base, env, sha, source_url, pin):
    package = "rss-mdm-" + name
    logs = []
    try:
        consumer = base / name
        (consumer / "tests").mkdir(parents=True)
        shutil.copy2(checkout / "rust-toolchain.toml", consumer / "rust-toolchain.toml")
        for parent in [consumer, *consumer.parents]:
            require(not any((parent / ".cargo" / filename).exists() for filename in ("config", "config.toml")), "unexpected ancestor Cargo configuration")
        (consumer / ".cargo").mkdir()
        (consumer / ".cargo/config.toml").write_text("[net]\ngit-fetch-with-cli = true\n")
        deps = [f'{package} = {{ git = "{source_url}", rev = "{sha}" }}']
        for owner in ["rss-request-context", *(["rss-contract"] if name != "winget-source" else [])]:
            deps.append(f'{owner} = {{ git = "{pin["git"]}", rev = "{pin["rev"]}", default-features = false }}')
        if name == "winget-source":
            deps.append('serde_json = "1"')
        (consumer / "Cargo.toml").write_text('[workspace]\n[package]\nname = "isolated-consumer"\nversion = "0.0.0"\nedition = "2024"\n[dependencies]\n' + "\n".join(deps) + "\n")
        shutil.copy2(checkout / "crates" / name / "tests" / test, consumer / "tests" / test)
        for extra in {"resource": ["restore.rs"], "winget-source": ["version.rs"]}.get(name, []):
            shutil.copy2(checkout / "crates" / name / "tests" / extra, consumer / "tests" / extra)
        fixtures = checkout / "crates" / name / "tests/fixtures"
        if fixtures.exists():
            shutil.copytree(fixtures, consumer / "tests/fixtures")
        local_env = dict(env, CARGO_TARGET_DIR=str(consumer / "target"))
        commands = [["cargo", "generate-lockfile"], ["cargo", "check", "--locked"], ["cargo", "test", "--locked"], ["cargo", "metadata", "--locked", "--format-version", "1"], ["cargo", "tree", "--locked", "-e", "features"]]
        for command in commands:
            print(f'{package}: {" ".join(command)}', flush=True)
            result = subprocess.run(command, cwd=consumer, env=local_env, stdin=subprocess.DEVNULL, text=True, capture_output=True)
            logs.append("$ " + " ".join(command) + "\n" + result.stdout + result.stderr)
            require(result.returncode == 0, f"{package}: command failed")
            if command[1] == "metadata":
                data = json.loads(result.stdout)
                closure = verify_graph(data, package, f"git+{source_url}?rev={sha}#{sha}", f'git+{pin["git"]}?rev={pin["rev"]}#{pin["rev"]}')
                (OUT / f"{name}-metadata.json").write_text(result.stdout)
                features = {n["id"]: n["features"] for n in data["resolve"]["nodes"]}
                declared = {p["name"]: p["features"] for p in data["packages"] if p["name"] == package}
            if command[1] == "tree":
                (OUT / f"{name}-tree.txt").write_text(result.stdout)
        lock = (consumer / "Cargo.lock").read_bytes()
        (OUT / f"{name}.lock").write_bytes(lock)
        return {"status": "passed", "lockSha256": hashlib.sha256(lock).hexdigest(), "normalClosure": closure, "selectedFeatures": features, "declaredProductFeatures": declared}
    except Exception as error:
        logs.append("ERROR: " + str(error))
        raise
    finally:
        (OUT / f"{name}.log").write_text("\n".join(logs))


def _main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Remove prior receipts before any fallible setup; no stale green result survives.
    for path in OUT.iterdir():
        if path.is_file():
            path.unlink()
    require(not subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT, text=True).strip(), "commit all proof inputs before consumer verification")
    sha = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_url = ROOT.as_uri()
    with tempfile.TemporaryDirectory(prefix="mdm-source-consumers-", dir="/tmp") as tmp:
        base = Path(tmp).resolve()
        checkout = base / "fixed-source"
        subprocess.run(["/usr/bin/git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(ROOT), str(checkout)], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(checkout), "checkout", "--quiet", "--detach", sha], check=True)
        pin = tomllib.loads((checkout / "Cargo.toml").read_text())["workspace"]["dependencies"]["rss-request-context"]
        env = {k: v for k, v in os.environ.items() if not k.startswith("CARGO_") and k not in ("RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CLIPPY_CONF_DIR")}
        env.update(CARGO_HOME=str(base / "cargo-home"), GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_ASKPASS="/usr/bin/false")
        records = collect_consumers(lambda name, test: run_consumer(name, test, checkout, base, env, sha, source_url, pin))
    result = {"head": sha, "rssRevision": pin["rev"], "consumers": records, "proof": "Git source consumption, not registry publication"}
    (OUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"head": sha, "consumers": {k: v["status"] for k, v in records.items()}}, indent=2))
    return int(any(r["status"] != "passed" for r in records.values()))

def main():
    try:
        return _main()
    except Exception as error:
        OUT.mkdir(parents=True, exist_ok=True)
        head = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True)
        sha = head.stdout.strip() if head.returncode == 0 else None
        result = {"head": sha, "status": "failed", "error": str(error),
                  "consumers": {name: {"status": "failed", "error": "shared setup failed"} for name in PACKAGES}}
        (OUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
