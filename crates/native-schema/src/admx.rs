//! Extract schema inputs without installing or executing the Microsoft MSI package.
//! ref: msi 0.10 src/internal/package.rs; cab 0.6 src/cabinet.rs.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::Path,
};

#[derive(Deserialize, Serialize)]
struct Installer {
    version: String,
    url: String,
    sha256: String,
    file: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
}

#[derive(Serialize)]
struct Extracted {
    installer: Installer,
    files: BTreeMap<String, String>,
    licenses: Vec<String>,
}

fn object(
    output: &Path,
    bytes: &[u8],
    extension: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let name = format!("{:x}.{extension}", Sha256::digest(bytes));
    fs::write(output.join("objects").join(&name), bytes)?;
    Ok(name)
}

pub fn import(manifest: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let installers: Vec<Installer> = serde_json::from_slice(&fs::read(manifest)?)?;
    fs::create_dir_all(output.join("objects"))?;
    let mut extracted = Vec::new();
    for installer in installers {
        if Path::new(&installer.file).components().count() != 1 {
            return Err("installer file must be relative to its manifest".into());
        }
        let bytes = fs::read(
            manifest
                .parent()
                .ok_or("manifest directory")?
                .join(&installer.file),
        )?;
        if format!("{:x}", Sha256::digest(&bytes)) != installer.sha256 {
            return Err("official installer digest mismatch".into());
        }
        let mut package = msi::Package::open(Cursor::new(bytes))?;
        let mut requested = BTreeMap::new();
        for row in package.select_rows(msi::Select::table("File"))? {
            let name = row["FileName"].as_str().ok_or("MSI file name")?;
            let name = name.split('|').next_back().ok_or("MSI long name")?;
            if name.ends_with(".admx")
                && (installer.include.is_empty()
                    || installer
                        .include
                        .iter()
                        .any(|selected| selected.eq_ignore_ascii_case(name)))
            {
                let id = row["File"].as_str().ok_or("MSI file identity")?;
                requested.insert(id.to_owned(), name.to_owned());
            }
        }
        let cabinets = package
            .select_rows(msi::Select::table("Media"))?
            .filter_map(|row| row["Cabinet"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        let mut files = BTreeMap::new();
        for name in cabinets {
            let name = name
                .strip_prefix('#')
                .ok_or("external cabinet is not a frozen input")?;
            let mut bytes = Vec::new();
            package.read_stream(name)?.read_to_end(&mut bytes)?;
            let mut cabinet = cab::Cabinet::new(Cursor::new(bytes))?;
            let names = cabinet
                .folder_entries()
                .flat_map(|folder| folder.file_entries().map(|file| file.name().to_owned()))
                .collect::<Vec<_>>();
            for id in names {
                if let Some(name) = requested.remove(&id) {
                    let mut bytes = Vec::new();
                    cabinet
                        .read_file(&id)?
                        .take(16 * 1024 * 1024 + 1)
                        .read_to_end(&mut bytes)?;
                    if bytes.len() > 16 * 1024 * 1024 {
                        return Err("ADMX source exceeds size bound".into());
                    }
                    if files
                        .insert(name, object(output, &bytes, "admx")?)
                        .is_some()
                    {
                        return Err("duplicate ADMX name".into());
                    }
                }
            }
        }
        if files.is_empty() || !requested.is_empty() {
            return Err("MSI ADMX extraction is incomplete".into());
        }
        let mut licenses = Vec::new();
        if package.has_table("Control") {
            for row in package.select_rows(msi::Select::table("Control"))? {
                if row["Type"].as_str() == Some("ScrollableText")
                    && let Some(text) = row["Text"].as_str()
                {
                    licenses.push(object(output, text.as_bytes(), "rtf")?);
                }
            }
        }
        if licenses.is_empty() {
            return Err("installer license source was not extracted".into());
        }
        println!(
            "{}: extracted {} ADMX templates and {} license text(s)",
            installer.version,
            files.len(),
            licenses.len()
        );
        extracted.push(Extracted {
            installer,
            files,
            licenses,
        });
    }
    fs::write(
        output.join("sources.json"),
        serde_json::to_string_pretty(&extracted)? + "\n",
    )?;
    Ok(())
}
