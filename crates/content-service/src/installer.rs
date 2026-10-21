//! Bounded native installer observation; never executes packages or assesses OS signature trust.
//! ref: mdsteele/rust-msi src/internal/summary.rs; CasualX/pelite src/resources/version_info.rs;
//! Dil4rd/dpp xara/src/toc.rs (declared decompression extents).
use super::*;
use quick_xml::{Reader, events::Event};
use rss_mdm_resource::{Architecture, SoftwareFormat};
use rss_mdm_software_service::management::content::InstallerFacts;
use std::collections::BTreeSet;
const METADATA: u64 = 1_048_576;
fn invalid() -> Error {
    Error::Malformed
}
fn check(clock: &dyn Clock, deadline: Deadline) -> Result<(), Error> {
    if clock.now() >= deadline.instant() {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
pub(super) fn inspect(
    file: &mut File,
    name: &str,
    config: &Config,
    clock: &dyn Clock,
    deadline: Deadline,
) -> Result<InstallerFacts, Error> {
    check(clock, deadline)?;
    file.rewind().map_err(|_| invalid())?;
    let suffix = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let facts = match suffix.as_str() {
        "exe" => exe(file)?,
        "msi" => msi(file)?,
        "msix" => super::native::inspect_msix(file, config, clock, deadline)?,
        "pkg" => pkg(file, config, clock, deadline)?,
        _ => return Err(invalid()),
    };
    if facts
        .version
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    check(clock, deadline)?;
    Ok(facts)
}
fn exe(file: &mut File) -> Result<InstallerFacts, Error> {
    // PE resources are observations. A bootstrap executable's CPU does not prove its payload CPU.
    let mut bytes = Vec::new();
    file.take(16 * METADATA)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let pe = pelite::PeFile::from_bytes(&bytes).map_err(|_| invalid())?;
    if pe.file_header().Characteristics & 0x2002 != 2 {
        return Err(invalid());
    }
    if !matches!(pe.file_header().Machine, 0x14c | 0x8664 | 0xaa64) {
        return Err(invalid());
    }
    let version = pe
        .resources()
        .ok()
        .and_then(|resources| resources.version_info().ok())
        .and_then(|info| {
            info.translation()
                .iter()
                .find_map(|lang| info.value(*lang, "ProductVersion"))
        });
    Ok(InstallerFacts {
        format: SoftwareFormat::Exe,
        version,
        architectures: vec![],
        bundle_id: None,
    })
}
// MSI table stream names use the encoding defined by rust-msi's internal/streamname.rs.
const STRING_POOL: &str = "\u{4840}\u{3f3f}\u{4577}\u{446c}\u{3e6a}\u{44b2}\u{482f}";
const STRING_DATA: &str = "\u{4840}\u{3f3f}\u{4577}\u{446c}\u{3b6a}\u{45e4}\u{4824}";
fn msi_budget(file: &mut File) -> Result<(), Error> {
    let mut compound = cfb::CompoundFile::open(&mut *file).map_err(|_| invalid())?;
    let mut total = 0u64;
    let mut count = 0usize;
    for entry in compound.walk().filter(|entry| entry.is_stream()) {
        // Tables and summary properties are parsed eagerly by Package::open; embedded cabinets
        // are payload and are never decoded here.
        if entry.name().starts_with(['\u{4840}', '\u{5}']) {
            total = total.checked_add(entry.len()).ok_or_else(invalid)?;
            count += 1;
            if total > METADATA || count > 4096 {
                return Err(invalid());
            }
        }
    }
    let mut summary = Vec::new();
    compound
        .open_stream("\u{5}SummaryInformation")
        .map_err(|_| invalid())?
        .take(METADATA + 1)
        .read_to_end(&mut summary)
        .map_err(|_| invalid())?;
    summary_budget(&summary)?;
    let data_length = compound.entry(STRING_DATA).map_err(|_| invalid())?.len();
    let mut pool = Vec::new();
    compound
        .open_stream(STRING_POOL)
        .map_err(|_| invalid())?
        .take(METADATA + 1)
        .read_to_end(&mut pool)
        .map_err(|_| invalid())?;
    if pool.len() < 4 || pool.len() as u64 > METADATA {
        return Err(invalid());
    }
    let mut at = 4;
    let mut strings = 0;
    let mut declared = 0u64;
    while at < pool.len() {
        let entry = pool.get(at..at + 4).ok_or_else(invalid)?;
        let short = u16::from_le_bytes([entry[0], entry[1]]);
        let refs = u16::from_le_bytes([entry[2], entry[3]]);
        at += 4;
        let length = if short == 0 && refs > 0 {
            let bytes = pool.get(at..at + 4).ok_or_else(invalid)?;
            at += 4;
            u32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?)
        } else {
            u32::from(short)
        };
        declared = declared
            .checked_add(u64::from(length))
            .ok_or_else(invalid)?;
        strings += 1;
        if declared > data_length || declared > METADATA || strings > 4096 {
            return Err(invalid());
        }
    }
    drop(compound);
    file.rewind().map_err(|_| invalid())
}
// The property reader also allocates LPSTR capacity from the declared length before reading.
fn summary_budget(bytes: &[u8]) -> Result<(), Error> {
    let number = |at: usize| -> Result<usize, Error> {
        let value = bytes
            .get(at..at.checked_add(4).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        Ok(u32::from_le_bytes(value.try_into().map_err(|_| invalid())?) as usize)
    };
    let section = number(44)?;
    let count = number(section.checked_add(4).ok_or_else(invalid)?)?;
    if count > 4096 {
        return Err(invalid());
    }
    let mut strings = 0usize;
    for i in 0..count {
        let offset = number(section.checked_add(12 + i * 8).ok_or_else(invalid)?)?;
        let start = section.checked_add(offset).ok_or_else(invalid)?;
        if number(start)? == 30 {
            let length = number(start.checked_add(4).ok_or_else(invalid)?)?;
            strings = strings.checked_add(length).ok_or_else(invalid)?;
            if strings as u64 > METADATA
                || start
                    .checked_add(8)
                    .and_then(|v| v.checked_add(length))
                    .is_none_or(|end| end > bytes.len())
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn msi(file: &mut File) -> Result<InstallerFacts, Error> {
    msi_budget(file)?;
    let mut package = msi::Package::open(file).map_err(|_| invalid())?;
    if package.package_type() != msi::PackageType::Installer {
        return Err(invalid());
    }
    let architectures = match package.summary_info().arch() {
        Some("x64" | "AMD64") => vec![Architecture::X86_64],
        Some("Arm64" | "arm64") => vec![Architecture::Aarch64],
        None | Some("") => vec![],
        _ => return Err(invalid()),
    };
    let mut version = None;
    if package.get_table("Property").is_some() {
        let rows = package
            .select_rows(msi::Select::table("Property"))
            .map_err(|_| invalid())?;
        for (i, row) in rows.enumerate() {
            if i >= 4096 {
                return Err(invalid());
            }
            if row["Property"].as_str() == Some("ProductVersion") {
                if version.is_some() {
                    return Err(invalid());
                }
                version = row["Value"].as_str().map(str::to_owned);
            }
        }
    }
    Ok(InstallerFacts {
        format: SoftwareFormat::Msi,
        version,
        architectures,
        bundle_id: None,
    })
}
fn pkg(
    file: &mut File,
    config: &Config,
    clock: &dyn Clock,
    deadline: Deadline,
) -> Result<InstallerFacts, Error> {
    let length = file.metadata().map_err(|_| invalid())?.len();
    let header = xara::header::parse_header(&mut *file).map_err(|_| invalid())?;
    if header.header_size < 28
        || header.version != 1
        || header.toc_compressed_len > METADATA
        || header.toc_uncompressed_len > METADATA
        || u64::from(header.header_size)
            .checked_add(header.toc_compressed_len)
            .is_none_or(|n| n > length)
        || header.toc_uncompressed_len
            > header
                .toc_compressed_len
                .max(1)
                .saturating_mul(config.max_expansion_ratio)
    {
        return Err(invalid());
    }
    file.rewind().map_err(|_| invalid())?;
    let mut archive = xara::XarArchive::open(file).map_err(|_| invalid())?;
    if archive.files().len() > config.max_bundle_entries {
        return Err(invalid());
    }
    let heap = u64::from(header.header_size) + header.toc_compressed_len;
    let mut names = BTreeSet::new();
    let mut infos = Vec::new();
    for entry in archive.files() {
        check(clock, deadline)?;
        if !names.insert(entry.path.to_lowercase()) {
            return Err(invalid());
        }
        if let Some(data) = &entry.data {
            if heap
                .checked_add(data.offset)
                .and_then(|n| n.checked_add(data.length))
                .is_none_or(|n| n > length)
            {
                return Err(invalid());
            }
            if entry.name == "PackageInfo" || entry.name == "Distribution" {
                if data.size > METADATA
                    || data.length > METADATA
                    || data.size
                        > data
                            .length
                            .max(1)
                            .saturating_mul(config.max_expansion_ratio)
                {
                    return Err(invalid());
                }
                infos.push(entry.clone());
            }
        }
    }
    if infos.is_empty() {
        return Err(invalid());
    }
    let mut versions = BTreeSet::new();
    let mut bundles = BTreeSet::new();
    let mut architectures = BTreeSet::new();
    let mut total = 0usize;
    for info in infos {
        check(clock, deadline)?;
        let bytes = archive.read_file(&info).map_err(|_| invalid())?;
        total = total.checked_add(bytes.len()).ok_or_else(invalid)?;
        if total as u64 > METADATA {
            return Err(invalid());
        }
        let mut reader = Reader::from_reader(bytes.as_slice());
        let mut depth = 0u32;
        let mut root_seen = false;
        loop {
            let event = reader.read_event().map_err(|_| invalid())?;
            match &event {
                Event::Start(element) | Event::Empty(element) => {
                    if depth > 32 {
                        return Err(invalid());
                    }
                    let tag = element.name();
                    if depth == 0 {
                        let expected = if info.name == "PackageInfo" {
                            "pkg-info"
                        } else {
                            "installer-gui-script"
                        };
                        if root_seen || tag.as_ref() != expected {
                            return Err(invalid());
                        }
                        root_seen = true;
                    }
                    for attr in element.attributes().with_checks(true) {
                        let attr = attr.map_err(|_| invalid())?;
                        let value = attr
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map_err(|_| invalid())?;
                        if value.len() > 4096 {
                            return Err(invalid());
                        }
                        match (tag.as_ref(), attr.key.as_ref()) {
                            ("pkg-info", "version") if !value.is_empty() => {
                                versions.insert(value.into_owned());
                            }
                            ("bundle", "id") => {
                                bundles.insert(value.into_owned());
                            }
                            (_, "hostArchitectures") => {
                                for arch in value.split(',') {
                                    match arch.trim() {
                                        "x86_64" => {
                                            architectures.insert(Architecture::X86_64);
                                        }
                                        "arm64" => {
                                            architectures.insert(Architecture::Aarch64);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Event::DocType(_) | Event::GeneralRef(_) => return Err(invalid()),
                Event::Eof => {
                    if !root_seen || depth != 0 {
                        return Err(invalid());
                    }
                    break;
                }
                _ => {}
            }
            match event {
                Event::Start(_) => {
                    depth = depth.checked_add(1).ok_or_else(invalid)?;
                    if depth > 32 {
                        return Err(invalid());
                    }
                }
                Event::End(_) => depth = depth.checked_sub(1).ok_or_else(invalid)?,
                _ => {}
            }
        }
    }
    Ok(InstallerFacts {
        format: SoftwareFormat::Pkg,
        version: if versions.len() == 1 {
            versions.pop_first()
        } else {
            None
        },
        architectures: architectures.into_iter().collect(),
        bundle_id: if bundles.len() == 1 {
            bundles.pop_first()
        } else {
            None
        },
    })
}
