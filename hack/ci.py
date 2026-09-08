#!/usr/bin/env python3
"""Full local CI. Run all gates, then fail once with the complete failure list."""
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python >= 3.11 is required for local CI")

import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "local-ci"

LOCAL_PACKAGES = {
    "rss-mdm-inventory": "crates/inventory",
    "rss-mdm-inventory-postgres": "crates/inventory-postgres",
    "rss-mdm-examples": "crates/examples",
    "inventory-postgres-integration": "tests/inventory-postgres-integration",
}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def rss_pin(manifest, required=True):
    require('patch' not in manifest and 'replace' not in manifest, 'RSS patches/replacements are forbidden')
    pins = set()
    for owner in [manifest, manifest.get("workspace", {}), *manifest.get("target", {}).values()]:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for alias, dependency in owner.get(section, {}).items():
                name = dependency.get("package", alias) if isinstance(dependency, dict) else alias
                if name in LOCAL_PACKAGES:
                    require(dependency == {"path": LOCAL_PACKAGES[name]}, f"invalid local member source: {alias}")
                    continue
                if not name.startswith("rss-"):
                    continue
                require(isinstance(dependency, dict), f"RSS dependency {alias} must use git + rev")
                require(not any(k in dependency for k in ("path", "branch", "tag", "version", "workspace")), f"invalid RSS source: {alias}")
                url, rev = dependency.get("git"), dependency.get("rev")
                require(isinstance(url, str) and url.startswith("https://") and isinstance(rev, str) and re.fullmatch(r"[0-9a-f]{40}", rev), f"invalid RSS pin: {alias}")
                pins.add((url, rev))
    if not pins and not required:
        return None
    require(len(pins) == 1, "all direct RSS dependencies must share one git URL and full revision")
    return next(iter(pins))

def workspace_pin(root):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    pin = rss_pin(manifest)
    shared = manifest["workspace"]["dependencies"]
    for member in manifest["workspace"]["members"]:
        package = tomllib.loads((root / member / "Cargo.toml").read_text())
        require('patch' not in package and 'replace' not in package, 'RSS patches/replacements are forbidden')
        for owner in [package, *package.get("target", {}).values()]:
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                for alias, dep in list(owner.get(section, {}).items()):
                    if isinstance(dep, dict) and dep.get("workspace") is True:
                        require(alias in shared, f"unknown workspace dependency: {alias}")
                        require(not any(k in dep for k in ("path", "git", "rev", "branch", "tag", "version", "package")), f"invalid inherited source: {alias}")
                        owner[section][alias] = shared[alias]
        require(rss_pin(package, required=False) in (None, pin), f"RSS source differs in {member}")
    return pin

def noninteractive(env=None):
    value = dict(os.environ if env is None else env)
    value.pop("CLIPPY_CONF_DIR", None)
    value.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_ASKPASS="/usr/bin/false")
    return value

def command(args, cwd=ROOT, env=None):
    return subprocess.run(args, cwd=cwd, env=noninteractive(env), stdin=subprocess.DEVNULL, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def verify_metadata(data, root, mode, pin):
    url, rev = pin
    expected = f"git+{url}?rev={rev}#{rev}"
    for package in data["packages"]:
        if package["name"] in LOCAL_PACKAGES:
            require(package['source'] is None and Path(package['manifest_path']).resolve() == root / LOCAL_PACKAGES[package["name"]] / 'Cargo.toml', 'dependency isolation check failed')
        elif package["name"].startswith("rss-"):
            require(package['source'] == expected, (package['name'], package['source']))
        else:
            require(package['source'] and package['source'].startswith('registry+https://github.com/rust-lang/crates.io-index'), package['name'])
    require({p["name"] for p in data["packages"] if p["id"] in data["workspace_members"]} == set(LOCAL_PACKAGES), 'dependency isolation check failed')
    packages = {p["id"]: p["name"] for p in data["packages"]}
    features = {packages[n["id"]]: n["features"] for n in data["resolve"]["nodes"]}
    for name in ("rss-observation-postgres", "rss-projection-postgres"):
        require(("integration" in features[name]) == (mode == "integration"), f"unexpected {mode} features for {name}")
    return sorted(p["name"] for p in data["packages"] if p["name"].startswith("rss-") and p["name"] not in LOCAL_PACKAGES)

def isolate():
    # HEAD is the proof input; refuse an uncommitted tracked implementation.
    status = command(['/usr/bin/git', 'status', '--porcelain'])
    require(status.returncode == 0 and not status.stdout.strip(), 'commit all implementation inputs before final CI')
    with tempfile.TemporaryDirectory(prefix="mdm-isolated-", dir="/tmp") as directory:
        base = Path(directory).resolve()
        checkout = base / "checkout"
        result = command(["/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(checkout)])
        require(result.returncode == 0, result.stdout)
        for parent in [checkout, *checkout.parents]:
            for filename in ["config", "config.toml"]:
                path = parent / ".cargo" / filename
                require(not path.exists() or parent == checkout, f'ancestor Cargo config: {path}')
        env = {k:v for k,v in os.environ.items() if not k.startswith("CARGO_") and k not in ("CLIPPY_CONF_DIR", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")}
        env.update(CARGO_HOME=str(base / "cargo-home"), CARGO_TARGET_DIR=str(base / "target"))
        pin = workspace_pin(checkout)
        logs = []
        for extra in [[], ["--workspace", "--all-features"]]:
            args = ["cargo", "clippy", "--locked", "--all-targets", *extra, "--", "-D", "warnings"]
            result = command(args, checkout, env)
            logs.append(result.stdout)
            (OUT / "isolated-build.log").write_text("\n".join(logs))
            require(result.returncode == 0, 'isolated locked build failed; see isolated-build.log')
        for mode, extra in [("normal", []), ("integration", ["--all-features"])]:
            result = subprocess.run(["cargo","metadata","--locked","--format-version","1", *extra], cwd=checkout, env=noninteractive(env), stdin=subprocess.DEVNULL, text=True, capture_output=True)
            (OUT / f"metadata-{mode}.stderr.log").write_text(result.stderr)
            require(result.returncode == 0, result.stderr)
            data = json.loads(result.stdout)
            closure = verify_metadata(data, checkout, mode, pin)
            (OUT / f"metadata-{mode}.json").write_text(result.stdout)
            tree = command(["cargo","tree","--locked","-e","features", *extra], checkout, env)
            require(tree.returncode == 0, tree.stdout)
            (OUT / f"tree-{mode}.txt").write_text(tree.stdout)
            print(f"isolated {mode}: {', '.join(closure)}", flush=True)
        return "clean checkout, fresh Cargo home/target, both feature graphs passed"

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in ["isolation-error.txt", "result.json"]:
        (OUT / stale).unlink(missing_ok=True)
    head = command(["/usr/bin/git", "rev-parse", "HEAD"])
    require(head.returncode == 0, "cannot resolve tested HEAD")
    start_head = head.stdout.strip()
    gates = [
        ("script-tests",[sys.executable,"-O","-m","unittest","discover","-s","tests","-p","test_ci.py"]),
        ("fmt",["cargo","fmt","--all","--check"]),
        ("check",["cargo","check","--locked","--workspace","--all-targets"]),
        ("clippy",["cargo","clippy","--locked","--workspace","--all-targets","--all-features","--","-D","warnings"]),
        ("t1",["cargo","test","--locked","--workspace","--lib","--bins","--tests"]),
        ("api-boundary",["cargo","test","--locked","--workspace","--doc"]),
        ("t2",[sys.executable,"hack/t2.py"]),
    ]
    results = {}
    pin = None
    try:
        pin = workspace_pin(ROOT)
        results["pin"] = "passed"
    except Exception as error:
        (OUT / "pin.log").write_text(str(error))
        results["pin"] = "failed"
    for name,args in gates:
        print(f"local CI: {name}", flush=True)
        try:
            result = command(args)
            (OUT / f"{name}.log").write_text(result.stdout)
            results[name] = "passed" if result.returncode == 0 else "failed"
        except Exception as error:
            (OUT / f"{name}.log").write_text(str(error))
            results[name] = "failed"
        print(f"{name}: {results[name]}", flush=True)
    try:
        print("local CI: isolated Git consumer", flush=True)
        isolate()
        results["isolation"] = "passed"
    except Exception as error:
        (OUT / "isolation-error.txt").write_text(str(error))
        results["isolation"] = "failed"
    end_head = command(["/usr/bin/git", "rev-parse", "HEAD"])
    status = command(["/usr/bin/git", "status", "--porcelain"])
    results["identity"] = "passed" if end_head.returncode == 0 and end_head.stdout.strip() == start_head and status.returncode == 0 and not status.stdout.strip() else "failed"
    evidence = {"head":start_head, "rssRevision":pin[1] if pin else None,"rssGitUrl":pin[0] if pin else None,"cargoLockSha256":hashlib.sha256((ROOT/"Cargo.lock").read_bytes()).hexdigest(),"utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"gates":results,"remoteCI":False,"T3":"not run"}
    (OUT / "result.json").write_text(json.dumps(evidence,indent=2)+"\n")
    print(json.dumps(evidence, indent=2))
    return int(any(value != "passed" for value in results.values()))

if __name__ == "__main__": sys.exit(main())
