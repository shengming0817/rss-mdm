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
VERSION = "2.0.0"
SCHEMAS = [
    "registration-request-v2.schema.json", "registration-receipt-v2.schema.json",
    "report-request-v2.schema.json", "report-ack-v2.schema.json",
    "report-status-v2.schema.json", "error-body-v2.schema.json",
    "task-claim-request-v2.schema.json", "task-event-request-v2.schema.json",
    "task-payload-v2.schema.json", "signed-task-v2.schema.json",
    "task-claim-response-v2.schema.json", "task-event-ack-v2.schema.json",
]

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
base64 = "0.22"
ring = "0.17"
''')
    (base / "tests" / "contract.rs").write_text(r'''use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::{Capability, ErrorBody, RegistrationReceipt, RegistrationRequest, ReportAck, ReportBody, ReportRequest, ReportStatus, SCHEMA_FINGERPRINT, SCHEMA_MANIFEST, Secret};
use serde_json::json;
use uuid::Uuid;

#[test]
fn independent_agent_consumes_exact_v2() {
    let secret = || Secret::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let registration = RegistrationRequest::new(
        Uuid::new_v4(), Uuid::new_v4(), secret(), secret(),
        vec![Capability::InventoryBasicV2,Capability::TaskExecuteV2]
    ).unwrap();
    assert_eq!(registration.capabilities(), &[Capability::InventoryBasicV2,Capability::TaskExecuteV2]);
    let inventory_only=RegistrationRequest::new(
        Uuid::new_v4(),Uuid::new_v4(),secret(),secret(),vec![Capability::InventoryBasicV2]
    ).unwrap();
    assert_eq!(inventory_only.capabilities(), &[Capability::InventoryBasicV2]);
    let report = ReportRequest::new(
        Uuid::new_v4(), 0, 1, ReportBody::Snapshot(vec![])
    ).unwrap();
    assert!(matches!(report.body(), ReportBody::Snapshot(_)));
    assert_eq!(serde_json::to_value(&registration).unwrap()["wireVersion"], 2);
    let operation = Uuid::new_v4();
    let registration_id = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let report_id = Uuid::new_v4();
    let _: RegistrationReceipt = serde_json::from_value(json!({
        "wireVersion":2,"operationId":operation,"deviceId":"device-1",
        "registrationId":registration_id,"generation":1,"source":"agent.builtin",
        "epoch":epoch,"capabilities":["inventory.basic.v2","task.execute.v2"]
    })).unwrap();
    let ack = json!({"wireVersion":2,"reportId":report_id,"receivedAt":1,"intake":"durable"});
    let _: ReportAck = serde_json::from_value(ack.clone()).unwrap();
    let _: ReportStatus = serde_json::from_value(json!({
        "ack":ack,"observation":"pending","projection":"pending"
    })).unwrap();
    let _: ErrorBody = serde_json::from_value(json!({"code":"operation_unknown"})).unwrap();
    assert!(SCHEMA_MANIFEST.contains("RegistrationReceipt"));
    assert_eq!(SCHEMA_FINGERPRINT.len(), 64);
    use rss_mdm_agent_wire::{ExecutionIdentity,ExecutorProfile,OutputQuality,SignedTask,TaskArchitecture,TaskClaimRequest,TaskClaimResponse,TaskContent,TaskEvent,TaskEventAck,TaskEventRequest,TaskResult,TaskDiagnostics,TaskFailure,TaskPayload,TaskPermit,TaskPlatform,TaskSpec,TaskVerification};
    let claim=TaskClaimRequest::new(Uuid::new_v4()).unwrap();
    assert_eq!(serde_json::to_value(claim).unwrap()["wireVersion"],2);
    let key_document=Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key=Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
    let tenant=Uuid::new_v4();
    let registration=Uuid::new_v4();
    let task=Uuid::new_v4();
    let attempt=Uuid::new_v4();
    let offer_spec=TaskSpec {
        wire_version:2,tenant_id:tenant,device_id:"device-1".into(),
        platform:TaskPlatform::Macos,architecture:TaskArchitecture::Aarch64,
        registration_id:registration,generation:1,task_id:task,attempt_id:attempt,
        permit:TaskPermit::Offer,expires_at:200,resource_digest:[1;32],
        content:TaskContent{length:3,sha256:[2;32]},profile:ExecutorProfile::PosixSh,
        run_as:ExecutionIdentity::System,arguments:vec!["literal".into()],
        environment:Default::default(),timeout_seconds:60,output_bytes:4096,max_rows:1,
    };
    let sign=|payload:TaskPayload| SignedTask {
        signature:base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.sign(&payload.signing_bytes("fixture").unwrap()).as_ref()),
        payload,key_id:"fixture".into(),
    };
    let signed_offer=sign(offer_spec.clone().try_into().unwrap());
    let response:TaskClaimResponse=serde_json::from_value(serde_json::to_value(TaskClaimResponse::new(Some(signed_offer),vec![]).unwrap()).unwrap()).unwrap();
    let offer=response.task().unwrap();
    let context=TaskVerification {
        key_id:"fixture",public_key:key.public_key().as_ref(),tenant_id:tenant,
        device_id:"device-1",platform:TaskPlatform::Macos,architecture:TaskArchitecture::Aarch64,
        registration_id:registration,generation:1,task_id:task,attempt_id:attempt,
        permit:TaskPermit::Offer,now:100,
    };
    assert_eq!(offer.verify(&context).unwrap().payload().task_id,task);
    let start_request=TaskEventRequest::new(Uuid::new_v4(),attempt,TaskEvent::Start).unwrap();
    assert_eq!(serde_json::to_value(start_request).unwrap()["event"]["kind"],"start");
    let mut start_spec:TaskSpec=offer.payload.clone().into();
    start_spec.permit=TaskPermit::Start;
    start_spec.expires_at=115;
    let signed_start=sign(start_spec.try_into().unwrap());
    let start_ack:TaskEventAck=serde_json::from_value(serde_json::to_value(TaskEventAck::new(Some(signed_start),false)).unwrap()).unwrap();
    let start=start_ack.permit().unwrap();
    assert!(start.verify(&TaskVerification{permit:TaskPermit::Start,now:100,..context}).is_ok());
    for quality in [OutputQuality::Complete,OutputQuality::Truncated] {
        let failure=if quality==OutputQuality::Truncated {Some(TaskFailure::OutputLimit)} else {None};
        let diagnostics=TaskDiagnostics::new("version=1.2.3".into(),String::new(),5,100,failure).unwrap();
        let result=TaskEventRequest::new(Uuid::new_v4(),attempt,TaskEvent::Result(
            TaskResult::new(Some(0),quality,json!({"version":"1.2.3"}),diagnostics).unwrap()
        )).unwrap();
        let encoded=serde_json::to_value(result).unwrap();
        assert_eq!(encoded["event"]["quality"],serde_json::to_value(quality).unwrap());
        assert_eq!(encoded["event"]["diagnostics"]["stdout"],"version=1.2.3");
        assert_eq!(encoded["event"]["diagnostics"]["durationMs"],5);
        assert_eq!(encoded["event"]["diagnostics"]["executedAt"],100);
        let decoded:TaskEventRequest=serde_json::from_value(encoded.clone()).unwrap();
        let TaskEvent::Result(evidence)=decoded.event() else {panic!("result lost")};
        assert_eq!(evidence.diagnostics().stdout(),"version=1.2.3");
        let mut legacy=encoded;
        legacy["event"].as_object_mut().unwrap().remove("diagnostics");
        assert!(serde_json::from_value::<TaskEventRequest>(legacy).is_err());
    }
    assert!(serde_json::from_value::<TaskClaimRequest>(json!({"wireVersion":1,"operationId":Uuid::new_v4()})).is_err());
    assert!(SCHEMA_MANIFEST.contains("SignedTask"));
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
    schema_fingerprint = hashlib.sha256(b"".join((ROOT / "crates" / "agent-wire" / "schema" / name).read_bytes() for name in SCHEMAS)).hexdigest()
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
    result = {"status":"passed","head":head,"package":PACKAGE,"version":VERSION,"schemaFingerprint":schema_fingerprint,"archiveSha256":archive_sha,"source":source_result,"candidate":candidate_result}
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
