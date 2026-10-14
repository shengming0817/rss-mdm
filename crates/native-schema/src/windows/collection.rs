//! Fixed Learn supplement for the Win32 inventory CSP omitted from DDFv2Feb2026.
//! ref: https://learn.microsoft.com/en-us/windows/client-management/mdm/win32appinventory-csp
use super::ddf::{Applicability, Node};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
#[derive(Deserialize)]
struct Source {
    url: String,
    sha256: String,
    file: String,
}
pub fn supplement(root: &Path, nodes: &mut Vec<Node>) -> Result<(), Box<dyn std::error::Error>> {
    let root = root.join("schema/collection");
    let sources: Vec<Source> = serde_json::from_slice(&fs::read(root.join("source.json"))?)?;
    if sources.len() != 2 {
        return Err("invalid collection sources".into());
    }
    let source = &sources[0];
    if sources.len() != 2
        || source.file != "win32appinventory.md"
        || source.url
            != "https://learn.microsoft.com/en-us/windows/client-management/mdm/win32appinventory-csp?accept=text/markdown"
        || format!("{:x}", Sha256::digest(fs::read(root.join(&source.file))?)) != source.sha256
    {
        return Err("invalid fixed Win32 source".into());
    }
    // Learn declares Windows 10/11 and editions, but no servicing/build minimum.
    // This encodes that OS family, not a tested earliest-build support claim.
    let support = Applicability {
        builds: vec![[10, 0, 0, 0]],
        editions: Some(
            ["0x30", "0x31", "0x4", "0x1B", "0x79", "0x7A", "0xBC"]
                .map(str::to_owned)
                .to_vec(),
        ),
    };
    let base = "./Device/Vendor/MSFT/Win32AppInventory";
    for (suffix, format) in [
        ("", "node"),
        ("/Win32InstalledProgram", "node"),
        ("/Win32InstalledProgram/*", "node"),
        ("/Win32InstalledProgram/*/Name", "chr"),
        ("/Win32InstalledProgram/*/Publisher", "chr"),
        ("/Win32InstalledProgram/*/Version", "chr"),
        ("/Win32InstalledProgram/*/Language", "chr"),
        ("/Win32InstalledProgram/*/RegKey", "chr"),
        ("/Win32InstalledProgram/*/Source", "chr"),
        ("/Win32InstalledProgram/*/MsiProductCode", "chr"),
        ("/Win32InstalledProgram/*/MsiPackageCode", "chr"),
    ] {
        nodes.push(Node {
            path: format!("{base}{suffix}"),
            format: format.into(),
            access: vec!["Get".into()],
            applicability: support.clone(),
            source: format!("Learn:{}", source.sha256),
            constraints: Vec::new(),
            atomic: false,
            deprecated: None,
            mime: String::new(),
            lifetime: if suffix.contains('*') {
                "Dynamic"
            } else {
                "Permanent"
            }
            .into(),
            occurrence: "ZeroOrMore".into(),
            case: None,
        });
    }
    let source = &sources[1];
    if source.file != "update.md"
        || source.url
            != "https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp?accept=text/markdown"
        || format!("{:x}", Sha256::digest(fs::read(root.join(&source.file))?)) != source.sha256
    {
        return Err("invalid fixed Update source".into());
    }
    let mut suffixes = vec![
        ("".to_owned(), "node", 10240),
        ("/LastSuccessfulScanTime".into(), "chr", 10240),
    ];
    for (name, columns) in [
        ("InstalledUpdates", vec![]),
        ("InstallableUpdates", vec![("Type", "int")]),
        ("FailedUpdates", vec![("HResult", "int"), ("State", "int")]),
        ("PendingRebootUpdates", vec![("InstalledTime", "chr")]),
    ] {
        suffixes.push((format!("/{name}"), "node", 10240));
        suffixes.push((format!("/{name}/*"), "node", 10240));
        suffixes.push((format!("/{name}/*/RevisionNumber"), "int", 15063));
        for (column, format) in columns {
            suffixes.push((format!("/{name}/*/{column}"), format, 10240));
        }
    }
    for (suffix, format, build) in suffixes {
        nodes.push(Node {
            path: format!("./Vendor/MSFT/Update{suffix}"),
            format: format.into(),
            access: vec!["Get".into()],
            applicability: Applicability {
                builds: vec![[10, 0, build, 0]],
                editions: Some(
                    [
                        "0x30", "0x31", "0x4", "0x1B", "0x79", "0x7A", "0x65", "0x62", "0xCA",
                        "0xCB", "0xBC",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            },
            source: format!("Learn:{}", source.sha256),
            constraints: Vec::new(),
            atomic: false,
            deprecated: None,
            mime: String::new(),
            lifetime: if suffix.contains('*') {
                "Dynamic"
            } else {
                "Permanent"
            }
            .into(),
            occurrence: "ZeroOrMore".into(),
            case: None,
        });
    }
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    if nodes.windows(2).any(|n| n[0].path == n[1].path) {
        return Err("duplicate Win32 schema identity".into());
    }
    Ok(())
}
