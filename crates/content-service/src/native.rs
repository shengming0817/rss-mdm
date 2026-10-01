//! Native container identity checks. Signature/trust assessment remains a declared OS requirement.
//! ref: microsoft/msix-packaging src/msix/common/AppxManifestObject.cpp
use super::*;
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use rss_mdm_resource::{MsixArchitecture, MsixContainer, MsixIdentity, MsixSoftware};
use std::{collections::BTreeMap, io::Write};

fn invalid() -> Error {
    Error::Malformed
}
fn check_time(timer: &dyn Clock, deadline: Deadline) -> Result<(), Error> {
    if timer.now() >= deadline.instant() {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn archive<'a>(
    file: &'a mut File,
    config: &Config,
) -> Result<zip::ZipArchive<&'a mut File>, Error> {
    let (count, _) = super::bundle::directory(file, config)?;
    let mut archive = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        file,
    )
    .map_err(|_| invalid())?;
    if archive.len() as u64 != count || archive.has_overlapping_files().map_err(|_| invalid())? {
        return Err(invalid());
    }
    let mut expanded = 0u64;
    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i).map_err(|_| invalid())?;
        if entry.encrypted()
            || !entry.is_file()
            || entry
                .unix_mode()
                .is_some_and(|m| !matches!(m & 0o170000, 0 | 0o100000))
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return Err(invalid());
        }
        expanded = expanded.checked_add(entry.size()).ok_or_else(invalid)?;
        if expanded > config.max_bundle_bytes
            || entry.size()
                > entry
                    .compressed_size()
                    .max(1)
                    .saturating_mul(config.max_expansion_ratio)
        {
            return Err(invalid());
        }
    }
    Ok(archive)
}
#[derive(Default)]
struct Facts {
    identities: Vec<BTreeMap<String, String>>,
    dependencies: Vec<BTreeMap<String, String>>,
    families: Vec<BTreeMap<String, String>>,
    members: Vec<BTreeMap<String, String>>,
}
const PACKAGE_NS: &str = "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
const BUNDLE_NS: &str = "http://schemas.microsoft.com/appx/2013/bundle";
fn attributes(
    reader: &NsReader<&[u8]>,
    e: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut map = BTreeMap::new();
    for attribute in e.attributes().with_checks(true) {
        let a = attribute.map_err(|_| invalid())?;
        let key = a.key.as_ref();
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        if !matches!(
            reader.resolver().resolve_attribute(a.key).0,
            ResolveResult::Unbound
        ) {
            return Err(invalid());
        }
        let value = a
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|_| invalid())?
            .into_owned();
        if key.len() > 255 || value.len() > 4096 || map.insert(key.to_owned(), value).is_some() {
            return Err(invalid());
        }
    }
    Ok(map)
}
fn facts(xml: &[u8]) -> Result<Facts, Error> {
    if xml.len() > 1_048_576 {
        return Err(invalid());
    }
    let mut reader = NsReader::from_reader(xml);
    let mut out = Facts::default();
    let mut stack = Vec::<(String, String)>::new();
    let mut root_seen = false;
    let mut root_closed = false;
    loop {
        let event = reader.read_event().map_err(|_| invalid())?;
        let is_start = matches!(event, Event::Start(_));
        match event {
            Event::Start(e) | Event::Empty(e) => {
                let (namespace, name) = reader.resolver().resolve_element(e.name());
                let ns = match namespace {
                    ResolveResult::Bound(ns) => ns.as_ref().to_owned(),
                    ResolveResult::Unbound => String::new(),
                    ResolveResult::Unknown(_) => return Err(invalid()),
                };
                let name = name.as_ref().to_owned();
                if stack.is_empty() {
                    if root_seen
                        || root_closed
                        || !matches!(
                            (ns.as_str(), name.as_str()),
                            (PACKAGE_NS, "Package") | (BUNDLE_NS, "Bundle")
                        )
                    {
                        return Err(invalid());
                    }
                    root_seen = true;
                }
                if stack.len() >= 32 {
                    return Err(invalid());
                }
                collect(&reader, &e, &ns, &name, &stack, &mut out)?;
                if is_start {
                    stack.push((ns, name));
                } else if stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::End(e) => {
                let (namespace, name) = reader.resolver().resolve_element(e.name());
                let ns = match namespace {
                    ResolveResult::Bound(ns) => ns.as_ref().to_owned(),
                    _ => return Err(invalid()),
                };
                if stack.pop() != Some((ns, name.as_ref().to_owned())) {
                    return Err(invalid());
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::DocType(_) | Event::PI(_) => return Err(invalid()),
            Event::Text(text) if stack.is_empty() => {
                if !text.as_ref().bytes().all(|b| b.is_ascii_whitespace()) {
                    return Err(invalid());
                }
            }
            Event::Eof => break,
            _ => (),
        }
    }
    if !root_seen
        || !root_closed
        || !stack.is_empty()
        || out.identities.len() != 1
        || out.dependencies.len() > 32
        || out.members.len() > 128
        || out.families.len() > 8
    {
        return Err(invalid());
    }
    let mut members = std::collections::BTreeSet::new();
    if out.members.iter().any(|m| {
        m.get("FileName")
            .is_none_or(|name| !members.insert(name.to_lowercase()))
    }) {
        return Err(invalid());
    }
    Ok(out)
}
fn collect(
    reader: &NsReader<&[u8]>,
    e: &quick_xml::events::BytesStart<'_>,
    ns: &str,
    name: &str,
    parents: &[(String, String)],
    out: &mut Facts,
) -> Result<(), Error> {
    let path = |namespace: &str, names: &[&str]| {
        parents.len() == names.len()
            && parents
                .iter()
                .zip(names)
                .all(|((ns, name), expected)| ns == namespace && name == expected)
    };
    let target = match name {
        "Identity"
            if (ns == PACKAGE_NS && path(PACKAGE_NS, &["Package"]))
                || (ns == BUNDLE_NS && path(BUNDLE_NS, &["Bundle"])) =>
        {
            Some(&mut out.identities)
        }
        "PackageDependency"
            if ns == PACKAGE_NS && path(PACKAGE_NS, &["Package", "Dependencies"]) =>
        {
            Some(&mut out.dependencies)
        }
        "TargetDeviceFamily"
            if ns == PACKAGE_NS && path(PACKAGE_NS, &["Package", "Dependencies"]) =>
        {
            Some(&mut out.families)
        }
        "Package" if ns == BUNDLE_NS && path(BUNDLE_NS, &["Bundle", "Packages"]) => {
            Some(&mut out.members)
        }
        "Package" if ns == PACKAGE_NS && parents.is_empty() => None,
        "Identity" | "PackageDependency" | "TargetDeviceFamily" | "Package" => {
            return Err(invalid());
        }
        _ => None,
    };
    if let Some(target) = target {
        target.push(attributes(reader, e)?);
    }
    Ok(())
}
fn version(value: &str) -> Result<[u16; 4], Error> {
    let values = value
        .split('.')
        .map(|v| v.parse::<u16>().map_err(|_| invalid()))
        .collect::<Result<Vec<_>, _>>()?;
    values.try_into().map_err(|_| invalid())
}
fn field<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Error> {
    values.get(key).map(String::as_str).ok_or_else(invalid)
}
fn match_identity(
    values: &BTreeMap<String, String>,
    expected: &MsixIdentity,
    bundle: bool,
) -> Result<(), Error> {
    if field(values, "Name")? != expected.name
        || field(values, "Publisher")? != expected.publisher
        || version(field(values, "Version")?)? != expected.version
    {
        return Err(invalid());
    }
    if !bundle {
        let architecture = match values
            .get("ProcessorArchitecture")
            .map(String::as_str)
            .unwrap_or("neutral")
        {
            "x64" => MsixArchitecture::X86_64,
            "arm64" => MsixArchitecture::Aarch64,
            "neutral" => MsixArchitecture::Neutral,
            _ => return Err(invalid()),
        };
        if architecture != expected.architecture
            || values.get("ResourceId").map(String::as_str).unwrap_or("") != expected.resource_id
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn read_xml(
    archive: &mut zip::ZipArchive<&mut File>,
    path: &str,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<Facts, Error> {
    check_time(timer, deadline)?;
    let mut entry = archive.by_name(path).map_err(|_| invalid())?;
    if entry.size() > 1_048_576 {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut bytes).map_err(|_| invalid())?;
    check_time(timer, deadline)?;
    facts(&bytes)
}
fn package(
    file: &mut File,
    identity: &MsixIdentity,
    expected: &MsixSoftware,
    config: &Config,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<(), Error> {
    let mut archive = archive(file, config)?;
    let f = read_xml(&mut archive, "AppxManifest.xml", timer, deadline)?;
    match_identity(&f.identities[0], identity, false)?;
    if f.dependencies.len() != expected.dependencies.len() {
        return Err(invalid());
    }
    for d in &f.dependencies {
        let min = version(field(d, "MinVersion")?)?;
        if !expected.dependencies.iter().any(|i| {
            i.name == field(d, "Name").unwrap_or("")
                && i.publisher == field(d, "Publisher").unwrap_or("")
                && i.version >= min
        }) {
            return Err(invalid());
        }
    }
    if f.families.is_empty()
        || f.families.iter().any(|f| {
            version(field(f, "MinVersion").unwrap_or("")).ok() != Some(expected.minimum_os)
                || !matches!(
                    field(f, "Name"),
                    Ok("Windows.Desktop" | "Windows.Universal")
                )
        })
    {
        return Err(invalid());
    }
    Ok(())
}
/// Verify the actual MSIX identity/member/dependency material, without executing or validating OS trust.
pub(super) fn msix(
    file: &mut File,
    expected: &MsixSoftware,
    config: &Config,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<(), Error> {
    check_time(timer, deadline)?;
    let MsixContainer::Bundle { members, .. } = &expected.container else {
        return package(file, &expected.identity, expected, config, timer, deadline);
    };
    let mut archive = archive(file, config)?;
    let f = read_xml(
        &mut archive,
        "AppxMetadata/AppxBundleManifest.xml",
        timer,
        deadline,
    )?;
    match_identity(&f.identities[0], &expected.identity, true)?;
    let total = members
        .iter()
        .try_fold(0u64, |sum, m| sum.checked_add(m.length))
        .ok_or_else(invalid)?;
    if total > config.max_temporary_bytes || total > config.max_bundle_bytes {
        return Err(invalid());
    }
    for member in members {
        check_time(timer, deadline)?;
        let header = f
            .members
            .iter()
            .find(|p| p.get("FileName") == Some(&member.path))
            .ok_or_else(invalid)?;
        let architecture = match member.identity.architecture {
            MsixArchitecture::X86_64 => "x64",
            MsixArchitecture::Aarch64 => "arm64",
            MsixArchitecture::Neutral => "neutral",
        };
        let kind = if member.identity.resource_id.is_empty() {
            "application"
        } else {
            "resource"
        };
        if field(header, "Type")? != kind
            || field(header, "Architecture")? != architecture
            || version(field(header, "Version")?)? != member.identity.version
            || header.get("ResourceId").map(String::as_str).unwrap_or("")
                != member.identity.resource_id
            || field(header, "Size")?
                .parse::<u64>()
                .map_err(|_| invalid())?
                != member.length
        {
            return Err(invalid());
        }
        let mut input = archive.by_name(&member.path).map_err(|_| invalid())?;
        if input.size() != member.length {
            return Err(invalid());
        }
        let mut spool = tempfile::tempfile().map_err(|_| storage())?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut length = 0u64;
        loop {
            check_time(timer, deadline)?;
            let n = input.read(&mut buffer).map_err(|_| invalid())?;
            if n == 0 {
                break;
            }
            length = length.checked_add(n as u64).ok_or_else(invalid)?;
            if length > member.length {
                return Err(invalid());
            }
            hasher.update(&buffer[..n]);
            spool.write_all(&buffer[..n]).map_err(|_| storage())?;
        }
        if length != member.length || <[u8; 32]>::from(hasher.finalize()) != member.sha256 {
            return Err(invalid());
        }
        drop(input);
        spool.seek(SeekFrom::Start(0)).map_err(|_| storage())?;
        package(
            &mut spool,
            &member.identity,
            expected,
            config,
            timer,
            deadline,
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_names_require_the_real_namespace_and_parent() {
        for xml in [
            "<Package><Identity Name=\"Acme\"/></Package>",
            "<Package xmlns=\"urn:forged\"><Identity Name=\"Acme\"/></Package>",
            "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Properties><Identity Name=\"Acme\"/></Properties></Package>",
        ] {
            assert!(facts(xml.as_bytes()).is_err(), "accepted {xml}");
        }
    }
}
