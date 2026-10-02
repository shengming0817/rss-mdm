//! Offline XML source reader. DTD declarations are never fetched or expanded.
use quick_xml::{Reader, XmlVersion, events::Event};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct Element {
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub text: String,
    pub children: Vec<Element>,
}
impl Element {
    pub fn child(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|n| local(&n.name) == name)
    }
    pub fn children(&self, name: &str) -> impl Iterator<Item = &Self> {
        self.children.iter().filter(move |n| local(&n.name) == name)
    }
    pub fn value(&self, name: &str) -> Option<&str> {
        self.child(name).map(|n| n.text.trim())
    }
}
pub fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

pub fn parse(bytes: &[u8]) -> Result<Element, Box<dyn std::error::Error>> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("XML source exceeds byte budget".into());
    }
    let decoded;
    let bytes = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let mut words = Vec::new();
        let little = bytes[0] == 0xff;
        if !bytes.len().is_multiple_of(2) {
            return Err("truncated UTF-16 source".into());
        }
        for part in bytes[2..].chunks_exact(2) {
            words.push(if little {
                u16::from_le_bytes([part[0], part[1]])
            } else {
                u16::from_be_bytes([part[0], part[1]])
            });
        }
        decoded = String::from_utf16(&words)?;
        decoded.as_bytes()
    } else {
        bytes
    };
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut root = None;
    let mut count = 0;
    loop {
        match reader.read_event()? {
            Event::Start(start) | Event::Empty(start) => {
                count += 1;
                if count > 250_000 || stack.len() > 128 {
                    return Err("XML source exceeds structure budget".into());
                }
                let mut element = Element {
                    name: start.name().as_ref().into(),
                    ..Element::default()
                };
                for attr in start.attributes() {
                    let attr = attr?;
                    let name = attr.key.as_ref().to_owned();
                    let value = attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned();
                    if element.attributes.insert(name, value).is_some() {
                        return Err("duplicate XML attribute".into());
                    }
                }
                // expand_empty_elements ensures all elements have a matching end event.
                stack.push(element);
            }
            Event::End(_) => {
                let element = stack.pop().ok_or("unbalanced XML source")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(element);
                } else if root.replace(element).is_some() {
                    return Err("multiple XML roots".into());
                }
            }
            Event::Text(text) => {
                let text = text.xml_content(XmlVersion::Implicit1_0);
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&text);
                } else if !text.trim().is_empty() {
                    return Err("text outside source root".into());
                }
            }
            Event::CData(text) => stack
                .last_mut()
                .ok_or("CDATA outside source root")?
                .text
                .push_str(&text.xml_content(XmlVersion::Implicit1_0)),
            Event::GeneralRef(reference) => {
                let reference = reference.as_ref();
                let escaped = format!("&{reference};");
                let text = quick_xml::escape::unescape(&escaped)?;
                stack
                    .last_mut()
                    .ok_or("reference outside source root")?
                    .text
                    .push_str(&text);
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::DocType(_) | Event::PI(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err("unterminated XML source".into());
    }
    root.ok_or_else(|| "XML source has no root".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_entities_decode_without_external_resolution() {
        let doc=parse(br#"<!DOCTYPE tree SYSTEM "https://invalid.test/no-fetch"><tree><name>&lt;dynamic&gt;</name><empty/></tree>"#).unwrap();
        assert_eq!(doc.value("name"), Some("<dynamic>"));
        assert!(doc.child("empty").is_some());
        assert!(parse(br#"<!DOCTYPE tree [<!ENTITY external SYSTEM "file:///tmp/no-read">]><tree>&external;</tree>"#).is_err());
    }
    #[test]
    fn admx_utf16_and_namespaced_properties_are_read() {
        let text = "<p:tree><p:name>設定</p:name></p:tree>";
        let bytes = [
            vec![0xff, 0xfe],
            text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ]
        .concat();
        let doc = parse(&bytes).unwrap();
        assert_eq!(doc.value("name"), Some("設定"));
    }
}
