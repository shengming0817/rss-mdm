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
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "local-ci"

LOCAL_PACKAGES = {
    "rss-mdm-software-release": "crates/software-release",
    "rss-mdm-resource": "crates/resource",
    "rss-mdm-winget-source": "crates/winget-source",
    "rss-mdm-brew-source": "crates/brew-source",

    "rss-mdm-scope": "crates/scope",
    "rss-mdm-policy": "crates/policy",
    "rss-mdm-group": "crates/group",
    "rss-mdm-app": "crates/app",
    "rss-mdm-windows-mdm": "crates/windows-mdm",
    "rss-mdm-inventory": "crates/inventory",
    "rss-mdm-inventory-postgres": "crates/inventory-postgres",
    "rss-mdm-examples": "crates/examples",
    "inventory-postgres-integration": "tests/inventory-postgres-integration",
}

IDENTITY_PACKAGES = {"rss-identity-client", "rss-identity-contracts"}

def identity_dependency(dep):
    require(isinstance(dep, dict) and set(dep)=={'git','rev'}, 'invalid Identity dependency')
    url=urlsplit(dep['git'])
    require(url.scheme=='https' and url.hostname and not url.username and not url.password and not url.query and not url.fragment, 'invalid Identity Git URL')
    require(re.fullmatch(r'[0-9a-f]{40}',dep['rev']), 'invalid Identity revision')
    return dep['git'],dep['rev']

def identity_pin(manifest):
    deps=manifest['workspace']['dependencies']
    pairs={identity_dependency(deps[name]) for name in IDENTITY_PACKAGES}
    require(len(pairs)==1, 'Identity packages must share exact source')
    return next(iter(pairs))

def verify_policy(policy, manifest):
    require(policy['advisories']['ignore']==['RUSTSEC-2023-0071'], 'unapproved advisory exception')
    require(policy['advisories']['unused-ignored-advisory']=='deny', 'expired advisory exception must fail')
    require(policy['sources']['unknown-git']=='deny' and policy['sources']['unknown-registry']=='deny', 'unknown sources must fail')
    urls={rss_pin(manifest)[0],identity_pin(manifest)[0]}
    require(len(urls)==2 and set(policy['sources']['allow-git'])==urls, 'source permissions must match distinct reviewed repositories')

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
                if name in IDENTITY_PACKAGES:
                    identity_dependency(dependency)
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
    identity_pin(manifest)
    verify_policy(tomllib.loads((root / "deny.toml").read_text()),manifest)
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
        for owner in [package, *package.get("target", {}).values()]:
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                for alias, dep in owner.get(section, {}).items():
                    name = dep.get('package', alias) if isinstance(dep, dict) else alias
                    if name in IDENTITY_PACKAGES: require(dep == shared[name], 'Identity source mismatch')
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
        elif package["name"] in IDENTITY_PACKAGES:
            identity_url,revision = identity_pin(tomllib.loads((root / 'Cargo.toml').read_text()))
            require(package['source'] == f'git+{identity_url}?rev={revision}#{revision}', 'Identity source drift')
        elif package["name"].startswith("rss-"):
            require(package['source'] == expected, (package['name'], package['source']))
        else:
            require(package['source'] and package['source'].startswith('registry+https://github.com/rust-lang/crates.io-index'), package['name'])
    require({p["name"] for p in data["packages"] if p["id"] in data["workspace_members"]} == set(LOCAL_PACKAGES), 'dependency isolation check failed')
    packages = {p["id"]: p["name"] for p in data["packages"]}
    features = {packages[n["id"]]: n["features"] for n in data["resolve"]["nodes"]}
    for name in ("rss-observation-postgres", "rss-projection-postgres"):
        require(("integration" in features[name]) == (mode == "integration"), f"unexpected {mode} features for {name}")
    require({p['name'] for p in data['packages']} >= IDENTITY_PACKAGES, 'Identity SDK missing')
    nodes = {n['id']: n for n in data['resolve']['nodes']}
    app_id = next(p['id'] for p in data['packages'] if p['name'] == 'rss-mdm-app')
    visited, todo = set(), [app_id]
    while todo:
        ident = todo.pop()
        if ident in visited: continue
        visited.add(ident)
        for dep in nodes[ident]['deps']:
            if any(k.get('kind') != 'dev' for k in dep.get('dep_kinds', [{'kind':None}])): todo.append(dep['pkg'])
    require(not any(packages[p] == 'rss-mdm-examples' for p in visited), 'production application depends on fixtures')

    # Accepted public-verification path; no additional root or version is allowed.
    for name, version, parent in [('rsa','0.9.10','openidconnect'),('openidconnect','4.0.1','rss-mdm-app')]:
        found = [p for p in data['packages'] if p['name'] == name]
        require(len(found) == 1 and found[0]['version'] == version and found[0]['source'] == 'registry+https://github.com/rust-lang/crates.io-index', 'OIDC public-verification source drift')
        parents = {packages[n['id']] for n in data['resolve']['nodes'] if any(d['pkg'] == found[0]['id'] for d in n['deps'])}
        require(parents == {parent}, 'OIDC public-verification root drift')
    return sorted(p["name"] for p in data["packages"] if p["name"].startswith("rss-") and p["name"] not in LOCAL_PACKAGES and p["name"] not in IDENTITY_PACKAGES)

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
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in ["isolation-error.txt", "group-consumer-error.txt", "group-consumer.log", "group-consumer.json", "group-consumer.lock", "group-metadata.json", "group-tree.txt", "result.json"]:
        (OUT / stale).unlink(missing_ok=True)
    head = command(["/usr/bin/git", "rev-parse", "HEAD"])
    require(head.returncode == 0, "cannot resolve tested HEAD")
    start_head = head.stdout.strip()
    gates = [
        ("script-tests",[sys.executable,"-O","-m","unittest","discover","-s","tests","-p","test_*.py"]),
        ("fmt",["cargo","fmt","--all","--check"]),
        ("check",["cargo","check","--locked","--workspace","--all-targets"]),
        ("clippy",["cargo","clippy","--locked","--workspace","--all-targets","--all-features","--","-D","warnings"]),
        ("t1",["cargo","test","--locked","--workspace","--lib","--bins","--tests"]),
        ("api-boundary",["cargo","test","--locked","--workspace","--doc"]),
        ("core-consumers",[sys.executable,"hack/core_consumer.py"]),
        ("t2",[sys.executable,"hack/t2.py"]),
        ("source-t2",[sys.executable,"hack/source-t2.py"]),
        ("source-consumers",[sys.executable,"hack/source-consumers.py"]),

        ("identity-t2",[sys.executable,"hack/identity_t2.py"]),
        ("advisories",["cargo","deny","--locked","check","advisories","licenses","sources"]),
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
    try:
        print("local CI: Group public API consumer", flush=True)
        group_consumer(start_head)
        results["group-consumer"] = "passed"
    except Exception as error:
        (OUT / "group-consumer-error.txt").write_text(str(error))
        results["group-consumer"] = "failed"
    end_head = command(["/usr/bin/git", "rev-parse", "HEAD"])
    status = command(["/usr/bin/git", "status", "--porcelain"])
    results["identity"] = "passed" if end_head.returncode == 0 and end_head.stdout.strip() == start_head and status.returncode == 0 and not status.stdout.strip() else "failed"
    evidence = {"head":start_head, "rssRevision":pin[1] if pin else None,"rssGitUrl":pin[0] if pin else None,"cargoLockSha256":hashlib.sha256((ROOT/"Cargo.lock").read_bytes()).hexdigest(),"utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"gates":results,"remoteCI":False,"T3":"not run"}
    identity_url,identity_revision=identity_pin(tomllib.loads((ROOT/'Cargo.toml').read_text()))
    evidence.update(identityGitUrl=identity_url,identityRevision=identity_revision)
    candidate=ROOT/'fixtures/identity-candidate.json'
    evidence['identityCandidateManifestSha256']=hashlib.sha256(candidate.read_bytes()).hexdigest() if candidate.exists() else None
    (OUT / "result.json").write_text(json.dumps(evidence,indent=2)+"\n")
    print(json.dumps(evidence, indent=2))
    return int(any(value != "passed" for value in results.values()))

if __name__ == "__main__": sys.exit(main())
