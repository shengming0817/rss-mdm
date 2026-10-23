//! Narrow, bounded XAR metadata reader. Payloads and scripts are never decompressed.
//! ref: apple-oss-distributions/xar xar/lib/{archive.c,xml.c,zxar.c};
//! flate2 bufread::{ZlibDecoder,GzDecoder} (bounded streams and consumed extents).
use super::*;
use std::io::Cursor;

pub(super) struct Metadata {
    pub name: String,
    pub bytes: Vec<u8>,
}
#[derive(Default)]
struct Entry {
    parent: Option<usize>,
    name: Option<String>,
    kind: Option<String>,
    offset: Option<u64>,
    length: Option<u64>,
    size: Option<u64>,
    encoding: Option<String>,
    data: bool,
}
struct Element {
    name: String,
    text: String,
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn toc(xml: &[u8], limit: usize) -> Result<Vec<Entry>, Error> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut elements = Vec::<Element>::new();
    let mut files = Vec::<usize>::new();
    let mut entries = Vec::<Entry>::new();
    let mut root = false;
    loop {
        match reader.read_event().map_err(|_| invalid())? {
            Event::Start(e) => {
                if elements.len() >= 32 {
                    return Err(invalid());
                }
                let name = e.name().as_ref().to_owned();
                if elements.is_empty() {
                    if root || name != "xar" {
                        return Err(invalid());
                    }
                    root = true;
                }
                if name == "file" {
                    if elements
                        .last()
                        .is_none_or(|p| !matches!(p.name.as_str(), "toc" | "file"))
                        || entries.len() >= limit
                    {
                        return Err(invalid());
                    }
                    let parent = files.last().copied();
                    files.push(entries.len());
                    entries.push(Entry {
                        parent,
                        ..Default::default()
                    });
                }
                if let Some(&i) = files.last() {
                    let direct = elements.last().is_some_and(|p| p.name == "file");
                    if direct && name == "data" {
                        if entries[i].data {
                            return Err(invalid());
                        }
                        entries[i].data = true;
                    }
                    if name == "encoding"
                        && elements.last().is_some_and(|p| p.name == "data")
                        && elements
                            .iter()
                            .rev()
                            .nth(1)
                            .is_some_and(|p| p.name == "file")
                    {
                        let mut style = None;
                        for a in e.attributes().with_checks(true) {
                            let a = a.map_err(|_| invalid())?;
                            if a.key.as_ref() == "style" {
                                once(
                                    &mut style,
                                    a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                        .map_err(|_| invalid())?
                                        .into_owned(),
                                )?;
                            }
                        }
                        once(&mut entries[i].encoding, style.ok_or_else(invalid)?)?;
                    }
                }
                elements.push(Element {
                    name,
                    text: String::new(),
                });
            }
            Event::Text(text) => {
                if let Some(e) = elements.last_mut() {
                    e.text.push_str(&text.xml10_content());
                } else if !text.trim().is_empty() {
                    return Err(invalid());
                }
            }
            Event::CData(text) => elements
                .last_mut()
                .ok_or_else(invalid)?
                .text
                .push_str(&text.xml10_content()),
            Event::GeneralRef(reference) => {
                let escaped = format!("&{};", reference.as_ref());
                let text = quick_xml::escape::unescape(&escaped).map_err(|_| invalid())?;
                elements
                    .last_mut()
                    .ok_or_else(invalid)?
                    .text
                    .push_str(&text);
            }
            Event::End(_) => {
                let e = elements.pop().ok_or_else(invalid)?;
                let direct_data = elements.last().is_some_and(|p| p.name == "data")
                    && elements
                        .iter()
                        .rev()
                        .nth(1)
                        .is_some_and(|p| p.name == "file");
                if let Some(&i) = files.last() {
                    match (elements.last().map(|p| p.name.as_str()), e.name.as_str()) {
                        (Some("file"), "name") => {
                            if e.text.is_empty()
                                || e.text.len() > 8192
                                || e.text.contains(['/', '\\'])
                                || matches!(e.text.as_str(), "." | "..")
                                || e.text.chars().any(char::is_control)
                            {
                                return Err(invalid());
                            }
                            // Apple pkgbuild emits two identical decoded names for one entry.
                            if entries[i].name.as_ref().is_some_and(|old| old != &e.text) {
                                return Err(invalid());
                            }
                            entries[i].name = Some(e.text);
                        }
                        (Some("file"), "type") => once(&mut entries[i].kind, e.text)?,
                        (Some("data"), "offset") if direct_data => once(
                            &mut entries[i].offset,
                            e.text.parse().map_err(|_| invalid())?,
                        )?,
                        (Some("data"), "length") if direct_data => once(
                            &mut entries[i].length,
                            e.text.parse().map_err(|_| invalid())?,
                        )?,
                        (Some("data"), "size") if direct_data => {
                            once(&mut entries[i].size, e.text.parse().map_err(|_| invalid())?)?
                        }
                        (_, "file") => {
                            files.pop();
                        }
                        _ => {}
                    }
                }
            }
            Event::DocType(_) => return Err(invalid()),
            Event::Eof => {
                if !root || !elements.is_empty() || !files.is_empty() {
                    return Err(invalid());
                }
                return Ok(entries);
            }
            _ => {}
        }
    }
}
fn inflate(bytes: &[u8], size: u64, gzip: bool) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    if gzip {
        let mut decoder = flate2::bufread::GzDecoder::new(Cursor::new(bytes));
        (&mut decoder)
            .take(METADATA + 1)
            .read_to_end(&mut output)
            .map_err(|_| invalid())?;
        if decoder.into_inner().position() != bytes.len() as u64 {
            return Err(invalid());
        }
    } else {
        let mut decoder = flate2::bufread::ZlibDecoder::new(Cursor::new(bytes));
        (&mut decoder)
            .take(METADATA + 1)
            .read_to_end(&mut output)
            .map_err(|_| invalid())?;
        if decoder.total_in() != bytes.len() as u64 {
            return Err(invalid());
        }
    }
    if output.len() as u64 != size || size > METADATA {
        return Err(invalid());
    }
    Ok(output)
}

pub(super) fn read(
    file: &mut File,
    config: &Config,
    clock: &dyn Clock,
    deadline: Deadline,
) -> Result<Vec<Metadata>, Error> {
    file.rewind().map_err(|_| invalid())?;
    let mut header = [0u8; 28];
    file.read_exact(&mut header).map_err(|_| invalid())?;
    let header_size = u64::from(u16::from_be_bytes(
        header[4..6].try_into().map_err(|_| invalid())?,
    ));
    let compressed = u64::from_be_bytes(header[8..16].try_into().map_err(|_| invalid())?);
    let size = u64::from_be_bytes(header[16..24].try_into().map_err(|_| invalid())?);
    let length = file.metadata().map_err(|_| invalid())?.len();
    let heap = header_size.checked_add(compressed).ok_or_else(invalid)?;
    if &header[..4] != b"xar!"
        || header[6..8] != 1u16.to_be_bytes()
        || header_size < 28
        || heap > length
        || compressed == 0
        || compressed > METADATA
        || size > METADATA
        || size > compressed.saturating_mul(config.max_expansion_ratio)
        || u32::from_be_bytes(header[24..28].try_into().map_err(|_| invalid())?) > 4
    {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(header_size))
        .map_err(|_| invalid())?;
    let mut bytes = vec![0; compressed as usize];
    file.read_exact(&mut bytes).map_err(|_| invalid())?;
    let xml = inflate(&bytes, size, false)?;
    let entries = toc(&xml, config.max_bundle_entries)?;
    let mut paths = Vec::<String>::new();
    let mut unique = BTreeSet::new();
    let mut path_bytes = 0usize;
    let mut result = Vec::new();
    let mut total = 0u64;
    for entry in entries {
        check(clock, deadline)?;
        let name = entry.name.ok_or_else(invalid)?;
        let path = match entry.parent {
            Some(i) => format!("{}/{}", paths.get(i).ok_or_else(invalid)?, name),
            None => name.clone(),
        };
        path_bytes = path_bytes.checked_add(path.len()).ok_or_else(invalid)?;
        if path_bytes > METADATA as usize || !unique.insert(path.to_lowercase()) {
            return Err(invalid());
        }
        paths.push(path);
        if !entry.data {
            continue;
        }
        let offset = entry.offset.ok_or_else(invalid)?;
        let stored = entry.length.ok_or_else(invalid)?;
        let size = entry.size.ok_or_else(invalid)?;
        let start = heap.checked_add(offset).ok_or_else(invalid)?;
        if start.checked_add(stored).is_none_or(|end| end > length) {
            return Err(invalid());
        }
        if !matches!(name.as_str(), "PackageInfo" | "Distribution") {
            continue;
        }
        if entry.kind.as_deref() != Some("file")
            || stored > METADATA
            || size > METADATA
            || size > stored.max(1).saturating_mul(config.max_expansion_ratio)
        {
            return Err(invalid());
        }
        total = total.checked_add(size).ok_or_else(invalid)?;
        if total > METADATA {
            return Err(invalid());
        }
        file.seek(SeekFrom::Start(start)).map_err(|_| invalid())?;
        let mut bytes = vec![0; stored as usize];
        file.read_exact(&mut bytes).map_err(|_| invalid())?;
        let bytes = match entry.encoding.as_deref() {
            Some("application/octet-stream") if stored == size => bytes,
            Some("application/x-gzip") => inflate(&bytes, size, bytes.starts_with(&[0x1f, 0x8b]))?,
            _ => return Err(invalid()),
        };
        result.push(Metadata { name, bytes });
    }
    if result.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apple_duplicate_names_are_equal_after_decoding_and_paths_remain_bounded() {
        let xml=b"<xar><toc><file><name>Package&#73;nfo</name><name>PackageInfo</name></file></toc></xar>";
        assert_eq!(toc(xml, 1).unwrap()[0].name.as_deref(), Some("PackageInfo"));
        assert!(toc(xml, 0).is_err());
        assert!(
            toc(
                b"<xar><toc><file><name>PackageInfo</name><name>Payload</name></file></toc></xar>",
                1
            )
            .is_err()
        );
        assert!(
            toc(
                b"<!DOCTYPE xar [<!ENTITY x 'PackageInfo'>]><xar><toc/></xar>",
                1
            )
            .is_err()
        );
        assert!(
            toc(
                format!(
                    "<xar><toc>{}{}</toc></xar>",
                    "<file><name>x</name>".repeat(40),
                    "</file>".repeat(40)
                )
                .as_bytes(),
                100
            )
            .is_err()
        );
    }
}
