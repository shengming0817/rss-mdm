#!/usr/bin/env python3
"""Build a Linux arm64 OCI candidate from clean, fixed product source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]

def run(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()

def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()

def oci_identity(path):
    with tarfile.open(path) as archive:
        def blob(digest):
            value = archive.extractfile("blobs/sha256/" + digest.removeprefix("sha256:")).read()
            if "sha256:" + hashlib.sha256(value).hexdigest() != digest:
                raise ValueError("OCI content digest mismatch")
            return json.loads(value)
        descriptors = json.load(archive.extractfile("index.json"))["manifests"]
        if len(descriptors) != 1:
            raise ValueError("expected one candidate platform")
        descriptor = descriptors[0]
        manifest = blob(descriptor["digest"])
        config = blob(manifest["config"]["digest"])
        if (config.get("os"), config.get("architecture"), config["config"].get("User")) != ("linux", "arm64", "10001:10001"):
            raise ValueError("candidate platform or user mismatch")
        return descriptor["digest"], config

def build(out, header):
    if out.exists():
        raise ValueError("candidate output must be new")
    if header.is_symlink() or not header.is_file() or header.stat().st_mode & 0o077:
        raise ValueError("Git authorization header must be a private regular file")
    if run(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT):
        raise ValueError("candidate requires clean submitted source")
    revision = run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT)
    providers = json.loads((ROOT / "deployment/providers.lock.json").read_text())
    if any("@sha256:" not in image for image in providers.values()):
        raise ValueError("build providers must be pinned")
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="mdm-candidate-") as temporary:
        context = Path(temporary)
        source = context / "source"
        source.mkdir()
        archive_path = context / "source.tar"
        with archive_path.open("wb") as archive:
            subprocess.run(["/usr/bin/git", "archive", revision], cwd=ROOT, stdout=archive, check=True)
        with tarfile.open(archive_path) as archive:
            archive.extractall(source, filter="data")
        shutil.copy(source / "deployment/Dockerfile", context / "Dockerfile")
        image = "rss-mdm/server:" + revision
        common = ["docker", "buildx", "build", "--platform", "linux/arm64", "--provenance=false",
                  "--secret", "id=azure_header,src=" + str(header),
                  "--build-arg", "RUST_IMAGE=" + providers["rust"],
                  "--build-arg", "RUNTIME_IMAGE=" + providers["runtime"],
                  "--build-arg", "MDM_REVISION=" + revision]
        output = out / "server.oci.tar"
        subprocess.run([*common, "--target", "server", "--tag", image, "--output",
                        "type=oci,dest=" + str(output), str(context)], check=True)
        digest, config = oci_identity(output)
        if config["config"].get("Labels", {}).get("org.opencontainers.image.revision") != revision:
            raise ValueError("compiled candidate revision mismatch")
        subprocess.run(["docker", "load", "--input", str(output)], check=True)
        migrations = json.loads(run(["docker", "run", "--rm", "--network", "none", "--platform",
                                     "linux/arm64", image, "--describe"]))
        version = run(["docker", "run", "--rm", "--network", "none", "--platform", "linux/arm64", image, "--version"])
        subprocess.run([*common, "--target", "evidence", "--output",
                        "type=local,dest=" + str(out / "evidence"), str(context)], check=True)
        metadata = json.loads((out / "evidence/metadata.json").read_text())
        inputs = [{"package": p["name"], "source": p["source"]} for p in metadata["packages"]
                  if p["name"].startswith("rss-") and p["source"]]
        manifest = {
            "format_version": 1, "repository": "https://dev.azure.com/shengming0923/rss/_git/rss-mdm",
            "revision": revision, "version": version, "platform": "linux/arm64",
            "cargo_lock_sha256": sha(source / "Cargo.lock"), "migrations": migrations,
            "image": image + "@" + digest,
            "archive": {"file": output.name, "sha256": sha(output), "manifest_digest": digest},
            "binary_sha256": sha(out / "evidence/rss-mdm"), "dependencies": inputs, "providers": providers,
            "toolchain": (out / "evidence/toolchain.txt").read_text(),
            "validation": {"embedded_description": True, "version": True}
        }
        if not manifest["toolchain"].startswith("rustc " + tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"] + " "):
            raise ValueError("compiler identity mismatch")
        if run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT) != revision or run(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT):
            raise ValueError("source changed during candidate build")
        (out / "candidate.json").write_text(json.dumps(manifest, indent=2) + "\n")
        shutil.copy(source / "fixtures/mdm-config.example.json", out / "mdm-config.example.json")
    print("candidate: " + str(out / "candidate.json"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--git-auth-header-file", type=Path, required=True)
    args = parser.parse_args()
    build(args.output.resolve(), args.git_auth_header_file.absolute())
