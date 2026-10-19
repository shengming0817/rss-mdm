//! Exact cold filesystem snapshots; no symlink traversal or overwrite of different restored bytes.
use super::{Error, Result, local::Journal, transfer::backup::file_digest};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    relative: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    digest: Option<String>,
    bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tree {
    source: PathBuf,
    nodes: Vec<Node>,
}
fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Input);
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        if std::fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::Input);
        }
    }
    Ok(())
}
fn relative(path: &Path) -> Result<()> {
    if path.components().count() > 32
        || !path.components().all(|p| matches!(p, Component::Normal(_)))
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}
fn copy(source: &Path, target: &Path) -> Result<()> {
    let expected = file_digest(source)?;
    if target.exists() {
        let actual = file_digest(target)?;
        if actual.sha256 != expected.sha256 || actual.bytes != expected.bytes {
            return Err(Error::Conflict);
        }
        return Ok(());
    }
    let stage = target.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)
        .map_err(|_| Error::Storage)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&stage)
        .map_err(|_| Error::Storage)?;
    let mut block = [0u8; 65536];
    loop {
        let n = input.read(&mut block).map_err(|_| Error::Storage)?;
        if n == 0 {
            break;
        }
        output.write_all(&block[..n]).map_err(|_| Error::Storage)?;
    }
    output.sync_all().map_err(|_| Error::Storage)?;
    drop(output);
    let actual = file_digest(&stage)?;
    if actual.sha256 != expected.sha256 || actual.bytes != expected.bytes {
        return Err(Error::Conflict);
    }
    std::fs::hard_link(&stage, target).map_err(|_| Error::Conflict)?;
    std::fs::remove_file(stage).map_err(|_| Error::Storage)?;
    std::fs::File::open(target.parent().ok_or(Error::Input)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::Storage)
}
pub(super) fn capture(journal: &Journal, name: &str, source: &Path) -> Result<()> {
    absolute(source)?;
    let archive = journal.path(name)?;
    if archive.starts_with(source) || source.starts_with(&archive) {
        return Err(Error::Input);
    }
    let manifest = format!("{name}.json");
    if let Some(tree) = journal.load::<Tree>(&manifest)? {
        if tree.source != source {
            return Err(Error::Conflict);
        }
        return verify(&archive, &tree);
    }
    std::fs::create_dir_all(&archive).map_err(|_| Error::Storage)?;
    std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| Error::Storage)?;
    let mut queue = vec![PathBuf::new()];
    let mut nodes = Vec::new();
    while let Some(path) = queue.pop() {
        relative(&path)?;
        let origin = source.join(&path);
        let metadata = std::fs::symlink_metadata(&origin).map_err(|_| Error::Storage)?;
        if !metadata.is_dir() {
            return Err(Error::Input);
        }
        let destination = archive.join(&path);
        std::fs::create_dir_all(&destination).map_err(|_| Error::Storage)?;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Storage)?;
        nodes.push(Node {
            relative: path.clone(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o777,
            digest: None,
            bytes: 0,
        });
        for entry in std::fs::read_dir(&origin).map_err(|_| Error::Storage)? {
            let entry = entry.map_err(|_| Error::Storage)?;
            if entry.file_name() == "install.lock" {
                continue;
            }
            let path = path.join(entry.file_name());
            relative(&path)?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| Error::Storage)?;
            if metadata.is_dir() {
                queue.push(path);
                continue;
            }
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(Error::Input);
            }
            copy(&entry.path(), &archive.join(&path))?;
            let digest = file_digest(&archive.join(&path))?;
            nodes.push(Node {
                relative: path,
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o777,
                digest: Some(digest.sha256),
                bytes: digest.bytes,
            });
            if nodes.len() + queue.len() > 1_000_000 {
                return Err(Error::Input);
            }
        }
    }
    nodes.sort_by(|a, b| a.relative.cmp(&b.relative));
    let tree = Tree {
        source: source.into(),
        nodes,
    };
    verify(&archive, &tree)?;
    journal.secret(
        &manifest,
        &serde_json::to_vec(&tree).map_err(|_| Error::Corrupt)?,
    )?;
    Ok(())
}
fn verify(archive: &Path, tree: &Tree) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for node in &tree.nodes {
        relative(&node.relative)?;
        if !seen.insert(&node.relative) {
            return Err(Error::Corrupt);
        }
        let path = archive.join(&node.relative);
        absolute(&path)?;
        if let Some(expected) = &node.digest {
            let actual = file_digest(&path)?;
            if &actual.sha256 != expected || actual.bytes != node.bytes {
                return Err(Error::Corrupt);
            }
        } else if !std::fs::symlink_metadata(path)
            .map_err(|_| Error::Storage)?
            .is_dir()
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}
pub(super) fn restore(journal: &Journal, name: &str) -> Result<()> {
    let tree: Tree = journal
        .load(&format!("{name}.json"))?
        .ok_or(Error::Corrupt)?;
    let archive = journal.path(name)?;
    verify(&archive, &tree)?;
    absolute(&tree.source)?;
    for node in &tree.nodes {
        let target = tree.source.join(&node.relative);
        absolute(&target)?;
        if node.digest.is_none() {
            match std::fs::symlink_metadata(&target) {
                Ok(meta)
                    if !meta.is_dir()
                        || meta.uid() != node.uid
                        || meta.gid() != node.gid
                        || meta.mode() & 0o777 != node.mode =>
                {
                    return Err(Error::Conflict);
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir_all(&target).map_err(|_| Error::Storage)?;
                    attributes(&target, node)?;
                }
                Err(_) => return Err(Error::Storage),
            }
        } else if target.exists() {
            let actual = file_digest(&target)?;
            let meta = std::fs::symlink_metadata(&target).map_err(|_| Error::Storage)?;
            if Some(&actual.sha256) != node.digest.as_ref()
                || actual.bytes != node.bytes
                || meta.uid() != node.uid
                || meta.gid() != node.gid
                || meta.mode() & 0o777 != node.mode
            {
                return Err(Error::Conflict);
            }
        } else {
            copy(&archive.join(&node.relative), &target)?;
            attributes(&target, node)?;
        }
    }
    Ok(())
}
fn attributes(path: &Path, node: &Node) -> Result<()> {
    std::os::unix::fs::chown(path, Some(node.uid), Some(node.gid)).map_err(|_| Error::Storage)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(node.mode))
        .map_err(|_| Error::Storage)
}

#[derive(Serialize, Deserialize)]
struct ExternalFile {
    source: PathBuf,
    node: Node,
}
pub(super) fn capture_inputs(journal: &Journal, values: &[serde_json::Value]) -> Result<()> {
    fn collect(
        value: &serde_json::Value,
        paths: &mut std::collections::BTreeSet<PathBuf>,
    ) -> Result<()> {
        match value {
            serde_json::Value::Object(object) => {
                for (name, value) in object {
                    if name.ends_with("_file") && value.is_string() {
                        paths.insert(PathBuf::from(value.as_str().ok_or(Error::Input)?));
                    } else if matches!(name.as_str(), "key_files" | "credential_keys") {
                        for value in value.as_object().ok_or(Error::Input)?.values() {
                            paths.insert(PathBuf::from(value.as_str().ok_or(Error::Input)?));
                        }
                    } else if matches!(
                        name.as_str(),
                        "historical_files" | "apple_material_roots" | "ca_files"
                    ) {
                        for value in value.as_array().ok_or(Error::Input)? {
                            paths.insert(PathBuf::from(value.as_str().ok_or(Error::Input)?));
                        }
                    } else {
                        collect(value, paths)?;
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect(value, paths)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    if let Some(saved) = journal.load::<Vec<ExternalFile>>("inputs.json")? {
        for file in &saved {
            verify_external(journal, file)?;
        }
        return Ok(());
    }
    let mut paths = std::collections::BTreeSet::new();
    for value in values {
        collect(value, &mut paths)?;
    }
    let mut files = Vec::new();
    for (index, source) in paths.into_iter().enumerate() {
        absolute(&source)?;
        let metadata = std::fs::symlink_metadata(&source).map_err(|_| Error::Storage)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(Error::Input);
        }
        let name = format!("material-{index}");
        let path = journal.path(&name)?;
        copy(&source, &path)?;
        let digest = file_digest(&path)?;
        files.push(ExternalFile {
            source,
            node: Node {
                relative: name.into(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o777,
                digest: Some(digest.sha256),
                bytes: digest.bytes,
            },
        });
    }
    journal.secret(
        "inputs.json",
        &serde_json::to_vec(&files).map_err(|_| Error::Corrupt)?,
    )?;
    Ok(())
}
fn verify_external(journal: &Journal, file: &ExternalFile) -> Result<()> {
    relative(&file.node.relative)?;
    let actual = file_digest(&journal.path(file.node.relative.to_str().ok_or(Error::Corrupt)?)?)?;
    if file.node.digest.as_ref() != Some(&actual.sha256) || file.node.bytes != actual.bytes {
        return Err(Error::Corrupt);
    }
    Ok(())
}
pub(super) fn restore_inputs(journal: &Journal) -> Result<()> {
    let files: Vec<ExternalFile> = journal.load("inputs.json")?.ok_or(Error::Corrupt)?;
    for file in files {
        verify_external(journal, &file)?;
        absolute(&file.source)?;
        let source = journal.path(file.node.relative.to_str().ok_or(Error::Corrupt)?)?;
        if file.source.exists() {
            let actual = file_digest(&file.source)?;
            if Some(&actual.sha256) != file.node.digest.as_ref() || actual.bytes != file.node.bytes
            {
                return Err(Error::Conflict);
            }
        } else {
            let parent = file.source.parent().ok_or(Error::Input)?;
            if !parent.is_dir() {
                return Err(Error::Input);
            }
            copy(&source, &file.source)?;
            attributes(&file.source, &file.node)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_preserves_empty_and_pending_files_and_refuses_changed_restore() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let source = root.join("original");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("empty"), b"").unwrap();
        std::fs::write(source.join("device.pending"), b"original pending payload").unwrap();
        let journal = Journal::open(&root.join("archive")).unwrap();
        capture(&journal, "tree", &source).unwrap();
        assert!(
            journal
                .path("tree")
                .unwrap()
                .join("device.pending")
                .exists()
        );
        std::fs::write(source.join("device.pending"), b"conflicting bytes").unwrap();
        assert!(matches!(restore(&journal, "tree"), Err(Error::Conflict)));
        std::fs::remove_dir_all(&source).unwrap();
        restore(&journal, "tree").unwrap();
        assert_eq!(
            std::fs::read(source.join("device.pending")).unwrap(),
            b"original pending payload"
        );
        assert!(std::fs::read(source.join("empty")).unwrap().is_empty());
        restore(&journal, "tree").unwrap();
    }
    #[test]
    fn snapshot_refuses_symlink_and_preserves_imported_materials() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(root.join("secret"), b"original key").unwrap();
        std::os::unix::fs::symlink(root.join("secret"), source.join("link")).unwrap();
        let journal = Journal::open(&root.join("archive")).unwrap();
        assert!(capture(&journal, "tree", &source).is_err());
        capture_inputs(
            &journal,
            &[serde_json::json!({"key_files":{"original":root.join("secret")}})],
        )
        .unwrap();
        std::fs::remove_file(root.join("secret")).unwrap();
        restore_inputs(&journal).unwrap();
        assert_eq!(std::fs::read(root.join("secret")).unwrap(), b"original key");
    }
}
