use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
/// Independent XML event comparison against checked-in wire fixtures; does not
/// invoke the codec's parser, field validation, or encoder to build expectations.
pub fn canonical(bytes: &[u8]) -> Vec<String> {
    let mut r = NsReader::from_reader(bytes);
    r.config_mut().expand_empty_elements = true;
    let mut out = Vec::new();
    let ns = |n: ResolveResult<'_>| match n {
        ResolveResult::Bound(n) => n.0.to_owned(),
        ResolveResult::Unbound => String::new(),
        _ => panic!("unbound fixture prefix"),
    };
    loop {
        match r.read_event().unwrap() {
            Event::Start(e) => {
                let (n, k) = r.resolver().resolve_element(e.name());
                let mut attrs = Vec::new();
                for a in e.attributes() {
                    let a = a.unwrap();
                    if a.key.0 == "xmlns" || a.key.0.starts_with("xmlns:") {
                        continue;
                    }
                    let (n, k) = r.resolver().resolve_attribute(a.key);
                    attrs.push(format!(
                        "{}:{}={}",
                        ns(n),
                        k.into_inner(),
                        a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .unwrap()
                    ));
                }
                attrs.sort();
                out.push(format!("+{}:{}{:?}", ns(n), k.into_inner(), attrs));
            }
            Event::End(e) => {
                let (n, k) = r.resolver().resolve_element(e.name());
                out.push(format!("-{}:{}", ns(n), k.into_inner()));
            }
            Event::Text(t) => {
                if !t.trim().is_empty() {
                    out.push(format!("={}", t.xml10_content()));
                }
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) => {}
            _ => panic!("fixture event not supported"),
        }
    }
    out
}
