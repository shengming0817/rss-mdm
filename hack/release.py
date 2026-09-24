#!/usr/bin/env python3
"""Build a Docker-default-platform OCI candidate from the current working source."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import uuid

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
        if config.get("os") != "linux" or not config.get("architecture") or config["config"].get("User") != "10001:10001":
            raise ValueError("candidate platform or user mismatch")
        return descriptor["digest"], config

def platform(config):
    return "/".join(config[key] for key in ("os", "architecture", "variant") if config.get(key))

def immutable_image(reference):
    if not re.fullmatch(r'(?:[^\s]+@)?sha256:[0-9a-f]{64}',reference):
        raise ValueError("immutable image ID or repository digest required")
    return reference

def image_metadata(value):
    result={"id":value["Id"], "revision":(value["Config"].get("Labels") or {}).get("org.opencontainers.image.revision"),
            "os":value["Os"], "architecture":value["Architecture"]}
    if value.get('Variant'):result['variant']=value['Variant']
    return result

def snapshot_ui(reference, output):
    value=json.loads(run(['docker','image','inspect',immutable_image(reference)]))[0]
    metadata=image_metadata(value)
    if value['Config'].get('User')!='10001:10001':
        raise ValueError('UI runtime user mismatch')
    subprocess.run(['docker','image','save','--output',str(output),metadata['id']],check=True)
    metadata['archive']={'file':output.name,'sha256':sha(output)}
    return metadata

def build(out, header, web_image):
    if out.exists():
        raise ValueError("candidate output must be new")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mdm-candidate-", dir=out.parent) as temporary:
        staged = Path(temporary) / "candidate"
        build_staged(staged, header, web_image)
        staged.rename(out)
    print("candidate: " + str(out / "candidate.json"))

ROLE_NAMES = ("software-publication", "management", "identity", "commands")
DEPLOYMENT_FILES = ("mdm-config.example.json", "deployment/nginx.conf", *(
    f"deployment/{name}-roles.sql" for name in ROLE_NAMES))


def source_inputs(root, header=None):
    """Git index admits paths; bytes always come from the current working tree."""
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo", "fixtures", "deployment", *manifest["workspace"]["members"]]
    for path in paths:
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("build input outside repository")
    def names(*flags):
        result = subprocess.check_output(["/usr/bin/git", "ls-files", "-z", *flags, "--", *paths], cwd=root)
        return set(os.fsdecode(result).split("\0")) - {""}
    tracked = names("--cached")
    unknown = names("--others", "--exclude-standard")
    inputs = {}
    for name in sorted(tracked | unknown):
        source = root / name
        if (header is not None and source.resolve() == header.resolve()) or name in (".cargo/credentials", ".cargo/credentials.toml"):
            raise ValueError("credential file among build inputs; move it outside the source tree")
        if source.is_symlink() or any(parent.is_symlink() for parent in source.parents if parent != root and parent.is_relative_to(root)):
            raise ValueError("symlink build input")
        if name in unknown:
            raise ValueError("untracked build input; review and add intended source paths to the Git index")
        if not source.exists():
            continue
        if not source.is_file() or not source.resolve().is_relative_to(root.resolve()):
            raise ValueError("invalid build input")
        before = source.stat()
        digest = sha(source)
        after = source.stat()
        if before != after:
            raise ValueError("source changed during snapshot")
        inputs[name] = (digest, after.st_mode, after.st_mtime_ns, after.st_ctime_ns, after.st_ino)
    return inputs


def copy_source(root, destination, header=None):
    inputs = source_inputs(root, header)
    destination.mkdir(parents=True)
    for name, state in inputs.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, target)
        if sha(target) != state[0] or target.stat().st_mode != state[1]:
            raise ValueError("source changed during copy")
    if source_inputs(root, header) != inputs:
        raise ValueError("source changed during copy")
    # Record exactly the copied content and modes, independent of Git commit state.
    content = {name: state[:2] for name, state in inputs.items()}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def build_staged(out, header, web_image):
    if out.exists():
        raise ValueError("candidate output must be new")
    if header.is_symlink() or not header.is_file() or header.stat().st_mode & 0o077:
        raise ValueError("Git authorization header must be a private regular file")
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="mdm-candidate-") as temporary:
        context = Path(temporary)
        source = context / "source"
        inputs_sha256 = copy_source(ROOT, source, header)
        providers = json.loads((source / "deployment/providers.lock.json").read_text())
        if any("@sha256:" not in image for image in providers.values()):
            raise ValueError("build providers must be pinned")
        ui = snapshot_ui(web_image, out / "identity-ui.image.tar")
        shutil.copy(source / "deployment/Dockerfile", context / "Dockerfile")
        image = "rss-mdm/server:build-" + uuid.uuid4().hex
        output = out / "server.oci.tar"
        subprocess.run(["docker", "buildx", "build", "--provenance=false",
                        "--secret", "id=azure_header,src=" + str(header),
                        "--build-arg", "RUST_IMAGE=" + providers["rust"],
                        "--build-arg", "RUNTIME_IMAGE=" + providers["runtime"],
                        "--target", "server", "--tag", image, "--output",
                        "type=oci,dest=" + str(output), str(context)], check=True)
        digest, config = oci_identity(output)
        subprocess.run(["docker", "load", "--input", str(output)], check=True)
        migrations = json.loads(run(["docker", "run", "--rm", "--network", "none", image, "--describe"]))
        version = run(["docker", "run", "--rm", "--network", "none", image, "--version"])
        deployment = {}
        for name in DEPLOYMENT_FILES:
            original = (source / "fixtures/mdm-config.example.json" if name == "mdm-config.example.json"
                        else source / ("crates/app/schema/" + Path(name).name) if name.endswith("-roles.sql")
                        else source / name)
            target = out / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(original, target)
            deployment[name] = sha(target)
        build = out / "build"
        build.mkdir()
        for name in ("Cargo.lock", "rust-toolchain.toml"):
            shutil.copy(source / name, build / name)
        manifest = {
            "format_version": 3, "ui": ui,
            "source": {"inputs_sha256": inputs_sha256},
            "version": version, "platform": platform(config), "migrations": migrations,
            "image": image + "@" + digest,
            "archive": {"file": output.name, "sha256": sha(output), "manifest_digest": digest},
            "providers": providers, "deployment": deployment,
        }
        (out / "candidate.json").write_text(json.dumps(manifest, indent=2) + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--git-auth-header-file", type=Path, required=True)
    parser.add_argument("--web-image", required=True, help="immutable UI image ID or repository digest")
    args = parser.parse_args()
    build(args.output.resolve(), args.git_auth_header_file.absolute(), args.web_image)
