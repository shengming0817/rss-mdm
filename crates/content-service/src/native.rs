//! Native container identity checks. Signature/trust assessment remains a declared OS requirement.
//! ref: microsoft/msix-packaging src/msix/common/AppxManifestObject.cpp
use super::*;
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use std::collections::BTreeMap;

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
    let archive = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        file,
    )
    .map_err(|_| invalid())?;
    if archive.len() as u64 != count {
        return Err(invalid());
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
pub(super) fn read_xml_bytes(
    reader: &mut impl Read,
    length: u64,
    timer: &dyn Clock,
    deadline: Deadline,
    bytes: &mut Vec<u8>,
) -> Result<(), Error> {
    if length > 1_048_576 || !bytes.is_empty() {
        return Err(invalid());
    }
    let mut buffer = [0; 8192];
    loop {
        check_time(timer, deadline)?;
        let count = buffer.len().min(length as usize - bytes.len() + 1);
        let n = reader.read(&mut buffer[..count]).map_err(|_| invalid())?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > length as usize {
            return Err(invalid());
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    check_time(timer, deadline)?;
    if bytes.len() != length as usize {
        return Err(invalid());
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
    if !super::bundle::regular_entry(&entry) {
        return Err(invalid());
    }
    if !entry.is_file() || entry.size() > 1_048_576 {
        return Err(invalid());
    }
    let length = entry.size();
    let mut bytes = Vec::with_capacity(length as usize);
    read_xml_bytes(&mut entry, length, timer, deadline, &mut bytes)?;
    facts(&bytes)
}
/// Discover the same namespace-checked MSIX identity used by publication verification.
pub(super) fn inspect_msix(
    file: &mut File,
    config: &Config,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<rss_mdm_software_service::management::content::InstallerFacts, Error> {
    let mut archive = archive(file, config)?;
    let path = if archive.index_for_name("AppxManifest.xml").is_some() {
        "AppxManifest.xml"
    } else {
        "AppxMetadata/AppxBundleManifest.xml"
    };
    {
        let entry = archive.by_name(path).map_err(|_| invalid())?;
        if entry.size()
            > entry
                .compressed_size()
                .max(1)
                .saturating_mul(config.max_expansion_ratio)
        {
            return Err(invalid());
        }
    }
    let facts = read_xml(&mut archive, path, timer, deadline)?;
    let identity = &facts.identities[0];
    let version = field(identity, "Version")?;
    self::version(version)?;
    let architectures = match identity
        .get("ProcessorArchitecture")
        .map(String::as_str)
        .unwrap_or("neutral")
    {
        "x64" => vec![rss_mdm_resource::Architecture::X86_64],
        "arm64" => vec![rss_mdm_resource::Architecture::Aarch64],
        "neutral" => vec![],
        _ => return Err(invalid()),
    };
    // Publisher is package identity; its presence is not signature verification.
    if field(identity, "Name")?.is_empty() || field(identity, "Publisher")?.is_empty() {
        return Err(invalid());
    }
    Ok(
        rss_mdm_software_service::management::content::InstallerFacts {
            format: rss_mdm_resource::SoftwareFormat::Msix,
            version: Some(version.into()),
            architectures,
            bundle_id: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_names_require_the_real_namespace_and_parent() {
        let valid = r#"<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Acme" Publisher="CN=Acme" Version="1.0.0.0"/></Package>"#;
        assert!(facts(valid.as_bytes()).is_ok());
        for xml in [
            valid.replace(r#" xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10""#, ""),
            valid.replace("http://schemas.microsoft.com/appx/manifest/foundation/windows10", "urn:forged"),
            valid.replace("<Identity", "<Properties><Identity").replace("/></Package>", "/></Properties></Package>"),
        ] {
            assert!(facts(xml.as_bytes()).is_err(), "accepted {xml}");
        }
    }
}
