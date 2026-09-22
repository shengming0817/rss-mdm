#!/usr/bin/env python3
"""Prove Agent wire consumption from fixed Git source and one packaged candidate archive."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "agent-wire-consumer"
PACKAGE = "rss-mdm-agent-wire"
VERSION = "1.0.0"

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def run(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, text=True, capture_output=True)
    require(result.returncode == 0, f"{' '.join(command)} failed:\n{result.stdout}{result.stderr}")
    return result

def consumer(base, dependency, expected_source, env):
    (base / "tests").mkdir(parents=True)
    (base / "Cargo.toml").write_text(f'''[package]
name = "agent-wire-independent-consumer"
version = "0.0.0"
edition = "2024"
[dependencies]
rss-mdm-agent-wire = {{ {dependency} }}
serde_json = "1"
uuid = {{ version = "1", features = ["v4"] }}
''')
    (base / "tests" / "contract.rs").write_text(r'''use rss_mdm_agent_wire::{Capability, RegistrationRequest, ReportBody, ReportRequest};
use serde_json::json;
use uuid::Uuid;

#[test]
fn independent_agent_consumes_exact_v1() {
    let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let registration: RegistrationRequest = serde_json::from_value(json!({
        "wireVersion":1,"operationId":Uuid::new_v4(),"enrollmentId":Uuid::new_v4(),
        "password":secret,"credential":secret,"capabilities":["inventory.basic.v1"]
    })).unwrap();
    assert_eq!(registration.capabilities(), &[Capability::InventoryBasicV1]);
    let report: ReportRequest = serde_json::from_value(json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":0,"observedAt":1,
        "body":{"kind":"snapshot","values":[]}
    })).unwrap();
    assert!(matches!(report.body(), ReportBody::Snapshot(_)));
}
''')
    logs = []
    metadata = None
    commands = [["cargo", "generate-lockfile"], ["cargo", "check", "--locked"], ["cargo", "test", "--locked"], ["cargo", "metadata", "--locked", "--format-version", "1"]]
    for command in commands:
        result = run(command, base, dict(env, CARGO_TARGET_DIR=str(base / "target")))
        logs.append("$ " + " ".join(command) + "\n" + result.stdout + result.stderr)
        if command[1] == "metadata":
            metadata = json.loads(result.stdout)
    package = next(p for p in metadata["packages"] if p["name"] == PACKAGE)
    require(package["version"] == VERSION, "consumer resolved an unexpected wire version")
    require(package["source"] == expected_source, "consumer resolved an unexpected source")
    closure = {p["name"] for p in metadata["packages"]}
    require(not ({name for name in closure if name.startswith("rss-mdm-")} - {PACKAGE}), "product implementation leaked into wire closure")
    return {"commands": commands, "closure": sorted(closure), "log": "\n".join(logs)}

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for path in OUT.iterdir():
        if path.is_file(): path.unlink()
    require(not subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT, text=True).strip(), "commit proof inputs before consumption")
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    clean_env = {k:v for k,v in os.environ.items() if not k.startswith("CARGO_") and k not in ("RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")}
    clean_env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_ASKPASS="/usr/bin/false")
    with tempfile.TemporaryDirectory(prefix="agent-wire-consumer-", dir="/tmp") as directory:
        base = Path(directory)
        source = base / "source"
        subprocess.run(["/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(source)], check=True, env=clean_env)
        subprocess.run(["/usr/bin/git", "-C", str(source), "checkout", "--quiet", "--detach", head], check=True, env=clean_env)
        package_env = dict(clean_env, CARGO_TARGET_DIR=str(base / "package-target"))
        packaged = run(["cargo", "package", "--locked", "-p", PACKAGE], source, package_env)
        archive = base / "package-target" / "package" / f"{PACKAGE}-{VERSION}.crate"
        require(archive.is_file(), "candidate archive missing")
        archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        unpacked = base / "candidate"
        unpacked.mkdir()
        with tarfile.open(archive, "r:gz") as package:
            package.extractall(unpacked, filter="data")
        git_source = f"git+{ROOT.as_uri()}?rev={head}#{head}"
        source_result = consumer(base / "git-consumer", f'git = "{ROOT.as_uri()}", rev = "{head}"', git_source, clean_env)
        candidate_path = unpacked / f"{PACKAGE}-{VERSION}"
        candidate_result = consumer(base / "candidate-consumer", f'path = "{candidate_path}"', None, clean_env)
        (OUT / "git.log").write_text(source_result.pop("log"))
        (OUT / "candidate.log").write_text(packaged.stdout + packaged.stderr + candidate_result.pop("log"))
    result = {"status":"passed","head":head,"package":PACKAGE,"version":VERSION,"archiveSha256":archive_sha,"source":source_result,"candidate":candidate_result}
    (OUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "result.json").write_text(json.dumps({"status":"failed","error":str(error)}, indent=2) + "\n")
        print(error, file=sys.stderr)
        raise SystemExit(1)
