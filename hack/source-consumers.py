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
        for dependency in nodes[key]["deps"]:
            if any(k["kind"] is None for k in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return sorted(packages[key]["name"] for key in seen)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    require(not subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT, text=True).strip(), "commit all proof inputs before consumer verification")
    sha = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    shared = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["dependencies"]
    pin = shared["rss-request-context"]
    source_url = ROOT.as_uri()
    records = {}
    with tempfile.TemporaryDirectory(prefix="mdm-source-consumers-", dir="/tmp") as tmp:
        base = Path(tmp).resolve()
        env = {k: v for k, v in os.environ.items() if not k.startswith("CARGO_") and k not in ("RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CLIPPY_CONF_DIR")}
        env.update(CARGO_HOME=str(base / "cargo-home"), GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_ASKPASS="/usr/bin/false")
        for name, test in PACKAGES.items():
            package = "rss-mdm-" + name
            consumer = base / name
            (consumer / "tests").mkdir(parents=True)
            shutil.copy2(ROOT / "rust-toolchain.toml", consumer / "rust-toolchain.toml")
            for parent in [consumer, *consumer.parents]:
                require(not any((parent / ".cargo" / filename).exists() for filename in ("config", "config.toml")), "unexpected ancestor Cargo configuration")
            (consumer / ".cargo").mkdir()
            (consumer / ".cargo/config.toml").write_text("[net]\ngit-fetch-with-cli = true\n")
            deps = [f'{package} = {{ git = "{source_url}", rev = "{sha}" }}']
            # Public foreign types are consumed from their canonical owner, never re-exported.
            for owner in ["rss-request-context", *(["rss-contract"] if name != "winget-source" else [])]:
                deps.append(f'{owner} = {{ git = "{pin["git"]}", rev = "{pin["rev"]}", default-features = false }}')
            if name == "winget-source":
                deps.append('serde_json = "1"')
            (consumer / "Cargo.toml").write_text('[workspace]\n[package]\nname = "isolated-consumer"\nversion = "0.0.0"\nedition = "2024"\n[dependencies]\n' + "\n".join(deps) + "\n")
            shutil.copy2(ROOT / "crates" / name / "tests" / test, consumer / "tests" / test)
            fixtures = ROOT / "crates" / name / "tests/fixtures"
            if fixtures.exists():
                shutil.copytree(fixtures, consumer / "tests/fixtures")
            local_env = dict(env, CARGO_TARGET_DIR=str(consumer / "target"))
            commands = [["cargo", "generate-lockfile"], ["cargo", "check", "--locked"], ["cargo", "test", "--locked"], ["cargo", "metadata", "--locked", "--format-version", "1"], ["cargo", "tree", "--locked", "-e", "features"]]
            logs = []
            try:
                for command in commands:
                    print(f'{package}: {" ".join(command)}', flush=True)
                    result = subprocess.run(command, cwd=consumer, env=local_env, stdin=subprocess.DEVNULL, text=True, capture_output=True)
                    logs.append("$ " + " ".join(command) + "\n" + result.stdout + result.stderr)
                    require(result.returncode == 0, f"{package}: command failed")
                    if command[1] == "metadata":
                        data = json.loads(result.stdout)
                        closure = verify_graph(data, package, f"git+{source_url}?rev={sha}#{sha}", f'git+{pin["git"]}?rev={pin["rev"]}#{pin["rev"]}')
                        (OUT / f"{name}-metadata.json").write_text(result.stdout)
                lock = (consumer / "Cargo.lock").read_bytes()
                (OUT / f"{name}.lock").write_bytes(lock)
                records[name] = {"status": "passed", "lockSha256": hashlib.sha256(lock).hexdigest(), "normalClosure": closure, "features": "default (no optional product features)"}
            except Exception as error:
                records[name] = {"status": "failed", "error": str(error)}
            finally:
                (OUT / f"{name}.log").write_text("\n".join(logs))
    result = {"head": sha, "rssRevision": pin["rev"], "consumers": records, "proof": "Git source consumption, not registry publication"}
    (OUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return int(any(r["status"] != "passed" for r in records.values()))

if __name__ == "__main__":
    sys.exit(main())
