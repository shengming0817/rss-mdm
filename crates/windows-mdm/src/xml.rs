//! Private streaming protocol cursor and bounded writer; no XML tree is built.
use crate::{CodecError as E, CodecLimits, Result, bound, text};
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
    name::{NamespaceError, ResolveResult},
    reader::NsReader,
};
use std::{collections::BTreeSet, io::Write};
pub(crate) const XML: &str = "http://www.w3.org/XML/1998/namespace";
pub(crate) const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
pub(crate) fn legal_char(c: char) -> bool {
    matches!(c, '\t'|'\n'|'\r'|'\u{20}'..='\u{d7ff}'|'\u{e000}'..='\u{fffd}'|'\u{10000}'..='\u{10ffff}')
}
// quick-xml's event reader does not validate QName lexical syntax.
// XML 1.0 fifth edition NameStartChar/NameChar; colon separates at most two NCNames.
fn qname(value: &str) -> Result<()> {
    fn first(c: char) -> bool {
        matches!(c, 'A'..='Z'|'a'..='z'|'_'|'\u{c0}'..='\u{d6}'|'\u{d8}'..='\u{f6}'|'\u{f8}'..='\u{2ff}'|'\u{370}'..='\u{37d}'|'\u{37f}'..='\u{1fff}'|'\u{200c}'..='\u{200d}'|'\u{2070}'..='\u{218f}'|'\u{2c00}'..='\u{2fef}'|'\u{3001}'..='\u{d7ff}'|'\u{f900}'..='\u{fdcf}'|'\u{fdf0}'..='\u{fffd}'|'\u{10000}'..='\u{effff}')
    }
    if value.split(':').count() > 2 {
        return Err(E::MalformedXml);
    }
    for part in value.split(':') {
        let mut chars = part.chars();
        if !chars.next().is_some_and(first)||!chars.all(|c|first(c)||matches!(c,'-'|'.'|'0'..='9'|'\u{b7}'|'\u{300}'..='\u{36f}'|'\u{203f}'..='\u{2040}')) {return Err(E::MalformedXml);}
    }
    Ok(())
}
fn map_error(e: quick_xml::Error) -> E {
    match e {
        quick_xml::Error::Escape(quick_xml::escape::EscapeError::UnrecognizedEntity(..)) => {
            E::ForbiddenXml
        }
        quick_xml::Error::Namespace(
            NamespaceError::TooManyBindings(_) | NamespaceError::TooDeeplyNested(_),
        ) => E::LimitExceeded,
        _ => E::MalformedXml,
    }
}
fn namespace(ns: ResolveResult<'_>) -> Result<String> {
    match ns {
        ResolveResult::Bound(n) => {
            let attribute = quick_xml::events::attributes::Attribute {
                key: quick_xml::name::QName("xmlns"),
                value: std::borrow::Cow::Borrowed(n.0),
            };
            Ok(attribute
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(map_error)?
                .into_owned())
        }
        ResolveResult::Unbound => Ok(String::new()),
        _ => Err(E::WrongNamespace),
    }
}
#[derive(Clone)]
pub(crate) struct Attr {
    pub ns: String,
    pub name: String,
    pub value: String,
}
#[derive(Clone)]
pub(crate) struct Start {
    pub ns: String,
    pub name: String,
    pub attrs: Vec<Attr>,
}
impl Start {
    pub fn attrs(&self, allowed: &[(&str, &str)]) -> Result<()> {
        if self
            .attrs
            .iter()
            .any(|a| !allowed.contains(&(a.ns.as_str(), a.name.as_str())))
        {
            return Err(E::Unsupported);
        }
        Ok(())
    }
    pub fn attr(&self, ns: &str, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.ns == ns && a.name == name)
            .map(|a| a.value.as_str())
    }
}
enum Token {
    Start(Start),
    End(String, String),
    Text(String),
    Eof,
}
struct Budget {
    events: usize,
    elements: usize,
    depth: usize,
    attrs: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            events: 0,
            elements: 0,
            depth: 0,
            attrs: 0,
        }
    }
    fn event(&mut self, l: &CodecLimits) -> Result<()> {
        self.events = self.events.checked_add(1).ok_or(E::LimitExceeded)?;
        bound(self.events, l.events)
    }
    fn start(&mut self, attrs: usize, l: &CodecLimits) -> Result<()> {
        self.elements = self.elements.checked_add(1).ok_or(E::LimitExceeded)?;
        self.depth = self.depth.checked_add(1).ok_or(E::LimitExceeded)?;
        self.attrs = self.attrs.checked_add(attrs).ok_or(E::LimitExceeded)?;
        bound(self.elements, l.elements)?;
        bound(self.depth, l.depth)?;
        bound(attrs, l.attributes_per_element)?;
        bound(self.attrs, l.attributes)
    }
}
pub(crate) struct Input<'a> {
    reader: NsReader<&'a [u8]>,
    look: Option<Token>,
    budget: Budget,
    pub limits: &'a CodecLimits,
    started: bool,
    declaration: bool,
    pub commands: usize,
    pub items: usize,
}
impl<'a> Input<'a> {
    pub fn new(bytes: &'a [u8], max: usize, limits: &'a CodecLimits) -> Result<Self> {
        bound(bytes.len(), max)?;
        let value = std::str::from_utf8(bytes).map_err(|_| E::Unsupported)?;
        if !value.chars().all(legal_char) {
            return Err(E::MalformedXml);
        }
        let mut reader = NsReader::from_reader(bytes);
        reader.config_mut().enable_all_checks(true);
        reader.config_mut().expand_empty_elements = true;
        reader
            .resolver_mut()
            .set_max_namespace_bindings(limits.namespace_bindings);
        Ok(Self {
            reader,
            look: None,
            budget: Budget::new(),
            limits,
            started: false,
            declaration: false,
            commands: 0,
            items: 0,
        })
    }
    fn read(&mut self) -> Result<Token> {
        if let Some(t) = self.look.take() {
            return Ok(t);
        }
        loop {
            self.budget.event(self.limits)?;
            let event = self.reader.read_event().map_err(map_error)?;
            return match event {
                Event::Start(e) => {
                    qname(e.name().0)?;
                    self.started = true;
                    let (ns, name) = self.reader.resolver().resolve_element(e.name());
                    let ns = namespace(ns)?;
                    let name = name.into_inner().to_string();
                    let mut attrs = Vec::new();
                    let mut seen = BTreeSet::new();
                    let mut count = 0;
                    for a in e.attributes() {
                        let a = a.map_err(|_| E::MalformedXml)?;
                        qname(a.key.0)?;
                        count += 1;
                        bound(count, self.limits.attributes_per_element)?;
                        bound(
                            self.budget
                                .attrs
                                .checked_add(count)
                                .ok_or(E::LimitExceeded)?,
                            self.limits.attributes,
                        )?;
                        // Raw spelling is bounded by the entire input. Attribute budget
                        // measures the normalized value, just as the writer does.
                        let value = a
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map_err(map_error)?
                            .into_owned();
                        text(&value, self.limits.field_bytes, true)?;
                        if a.key.0 == "xmlns" || a.key.0.starts_with("xmlns:") {
                            if value == "http://www.w3.org/2000/xmlns/"
                                || (value == XML && a.key.0 != "xmlns:xml")
                                || (a.key.0.starts_with("xmlns:") && value.is_empty())
                            {
                                return Err(E::WrongNamespace);
                            }
                            continue;
                        }
                        let (ns, name) = self.reader.resolver().resolve_attribute(a.key);
                        let ns = namespace(ns)?;
                        let name = name.into_inner().to_string();
                        if !seen.insert((ns.clone(), name.clone())) {
                            return Err(E::Duplicate);
                        }
                        attrs.push(Attr { ns, name, value });
                    }
                    self.budget.start(count, self.limits)?;
                    Ok(Token::Start(Start { ns, name, attrs }))
                }
                Event::End(e) => {
                    self.budget.depth = self.budget.depth.checked_sub(1).ok_or(E::MalformedXml)?;
                    let (ns, name) = self.reader.resolver().resolve_element(e.name());
                    Ok(Token::End(namespace(ns)?, name.into_inner().to_string()))
                }
                Event::Text(e) => {
                    if self.budget.depth == 0 {
                        self.started = true;
                    }
                    Ok(Token::Text(e.xml10_content().into_owned()))
                }
                Event::CData(e) => {
                    if self.budget.depth == 0 {
                        return Err(E::MalformedXml);
                    }
                    Ok(Token::Text(e.xml10_content().into_owned()))
                }
                Event::GeneralRef(e) => {
                    if self.budget.depth == 0 {
                        return Err(E::MalformedXml);
                    }
                    let s = if let Some(c) = e.resolve_char_ref().map_err(map_error)? {
                        if !legal_char(c) {
                            return Err(E::MalformedXml);
                        }
                        c.to_string()
                    } else {
                        match &*e {
                            "amp" => "&",
                            "lt" => "<",
                            "gt" => ">",
                            "apos" => "'",
                            "quot" => "\"",
                            _ => return Err(E::ForbiddenXml),
                        }
                        .to_string()
                    };
                    Ok(Token::Text(s))
                }
                Event::Decl(e) => {
                    if self.started || self.declaration {
                        return Err(E::MalformedXml);
                    }
                    self.declaration = true;
                    let declaration = BytesStart::from_content(e.as_ref(), 3);
                    let mut position = 0;
                    for a in declaration.attributes() {
                        let a = a.map_err(|_| E::MalformedXml)?;
                        bound(a.value.len(), self.limits.field_bytes)?;
                        match (position, a.key.0, a.value.as_ref()) {
                            (0, "version", "1.0") => position = 1,
                            (1, "encoding", v) if v.eq_ignore_ascii_case("utf-8") => position = 2,
                            (1 | 2, "standalone", "yes" | "no") => position = 3,
                            _ => return Err(E::MalformedXml),
                        }
                    }
                    if position == 0 {
                        return Err(E::MalformedXml);
                    }
                    continue;
                }
                Event::Comment(_) => {
                    self.started = true;
                    continue;
                }
                Event::Eof => Ok(Token::Eof),
                Event::DocType(_) | Event::PI(_) => Err(E::ForbiddenXml),
                _ => Err(E::MalformedXml),
            };
        }
    }
    fn significant(&mut self) -> Result<Token> {
        loop {
            let t = self.read()?;
            if matches!(&t,Token::Text(s) if s.chars().all(|c| matches!(c,' '| '\n'|'\r'|'\t'))) {
                continue;
            }
            return Ok(t);
        }
    }
    pub fn is(&mut self, ns: &str, name: &str) -> Result<bool> {
        let t = self.significant()?;
        let yes = matches!(&t,Token::Start(s) if s.ns==ns && s.name==name);
        self.look = Some(t);
        Ok(yes)
    }
    pub fn start(&mut self, ns: &str, name: &str) -> Result<Start> {
        match self.significant()? {
            Token::Start(s) if s.ns == ns && s.name == name => Ok(s),
            Token::Start(s) if s.name == name => Err(E::WrongNamespace),
            _ => Err(E::Structure),
        }
    }
    pub fn open(&mut self, ns: &str, name: &str) -> Result<()> {
        self.start(ns, name)?.attrs(&[])
    }
    pub fn end(&mut self, ns: &str, name: &str) -> Result<()> {
        match self.significant()? {
            Token::End(n, k) if n == ns && k == name => Ok(()),
            _ => Err(E::Structure),
        }
    }
    pub fn content(&mut self, ns: &str, name: &str, max: usize, empty: bool) -> Result<String> {
        let mut s = String::new();
        loop {
            match self.read()? {
                Token::Text(t) => {
                    bound(s.len().checked_add(t.len()).ok_or(E::LimitExceeded)?, max)?;
                    s.push_str(&t);
                }
                Token::End(n, k) if n == ns && k == name => {
                    text(&s, max, empty)?;
                    return Ok(s);
                }
                _ => return Err(E::Structure),
            }
        }
    }
    pub fn scalar(&mut self, ns: &str, name: &str, max: usize, empty: bool) -> Result<String> {
        self.open(ns, name)?;
        self.content(ns, name, max, empty)
    }
    pub fn qname_scalar(&mut self, ns: &str, name: &str) -> Result<(String, String)> {
        let value = self.scalar(ns, name, self.limits.uri_bytes, false)?;
        qname(&value)?;
        let (ns, local) = self
            .reader
            .resolver()
            .resolve_element(quick_xml::name::QName(&value));
        Ok((namespace(ns)?, local.into_inner().to_string()))
    }
    pub fn optional(&mut self, ns: &str, name: &str, max: usize) -> Result<Option<String>> {
        if self.is(ns, name)? {
            Ok(Some(self.scalar(ns, name, max, false)?))
        } else {
            Ok(None)
        }
    }
    pub fn finish(&mut self) -> Result<()> {
        if matches!(self.significant()?, Token::Eof) && self.budget.depth == 0 {
            Ok(())
        } else {
            Err(E::Structure)
        }
    }
    pub fn command(&mut self) -> Result<()> {
        self.commands += 1;
        bound(self.commands, self.limits.commands)
    }
    pub fn item(&mut self) -> Result<()> {
        self.items += 1;
        bound(self.items, self.limits.items)
    }
}
struct Sink {
    bytes: Vec<u8>,
    max: usize,
}
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > self.max.saturating_sub(self.bytes.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) struct Output<'a> {
    writer: Writer<Sink>,
    limits: &'a CodecLimits,
    budget: Budget,
    bindings: Vec<usize>,
    active: usize,
    pub commands: usize,
    pub items: usize,
}
impl<'a> Output<'a> {
    pub fn new(max: usize, limits: &'a CodecLimits) -> Self {
        Self {
            writer: Writer::new(Sink {
                bytes: Vec::new(),
                max,
            }),
            limits,
            budget: Budget::new(),
            bindings: Vec::new(),
            active: 0,
            commands: 0,
            items: 0,
        }
    }
    pub fn start(&mut self, name: &str, attrs: &[(&str, &str)]) -> Result<()> {
        self.budget.event(self.limits)?;
        self.budget.start(attrs.len(), self.limits)?;
        let n = attrs
            .iter()
            .filter(|(k, _)| *k == "xmlns" || k.starts_with("xmlns:"))
            .count();
        self.active += n;
        bound(self.active, self.limits.namespace_bindings)?;
        self.bindings.push(n);
        let mut e = BytesStart::new(name);
        for (k, v) in attrs {
            text(v, self.limits.field_bytes, true)?;
            e.push_attribute((*k, *v));
        }
        self.writer
            .write_event(Event::Start(e))
            .map_err(|_| E::LimitExceeded)
    }
    pub fn end(&mut self, name: &str) -> Result<()> {
        self.budget.event(self.limits)?;
        self.budget.depth = self.budget.depth.checked_sub(1).ok_or(E::Structure)?;
        self.active -= self.bindings.pop().ok_or(E::Structure)?;
        self.writer
            .write_event(Event::End(BytesEnd::new(name)))
            .map_err(|_| E::LimitExceeded)
    }
    pub fn scalar(&mut self, name: &str, value: &str, max: usize, empty: bool) -> Result<()> {
        text(value, max, empty)?;
        self.start(name, &[])?;
        self.content(value, max)?;
        self.end(name)
    }
    pub fn content(&mut self, value: &str, max: usize) -> Result<()> {
        text(value, max, true)?;
        if !value.is_empty() {
            // The reader emits one event per reference and one per intervening text run.
            let mut run = false;
            for c in value.chars() {
                if matches!(c, '&' | '<' | '>' | '\"' | '\'' | '\r') {
                    self.budget.event(self.limits)?;
                    run = false;
                } else if !run {
                    self.budget.event(self.limits)?;
                    run = true;
                }
            }
            self.writer
                .write_event(Event::Text(BytesText::new(value)))
                .map_err(|_| E::LimitExceeded)?;
        }
        Ok(())
    }
    pub fn empty(&mut self, name: &str) -> Result<()> {
        self.start(name, &[])?;
        self.end(name)
    }
    pub fn finish(mut self) -> Result<Vec<u8>> {
        self.budget.event(self.limits)?;
        if self.budget.depth != 0 {
            return Err(E::Structure);
        }
        Ok(self.writer.into_inner().bytes)
    }
    pub fn command(&mut self) -> Result<()> {
        self.commands += 1;
        bound(self.commands, self.limits.commands)
    }
    pub fn item(&mut self) -> Result<()> {
        self.items += 1;
        bound(self.items, self.limits.items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Exercise the private event cursor without introducing a production tree/parser API.
    fn consume(bytes: &[u8], l: &CodecLimits) -> Result<()> {
        let mut p = Input::new(bytes, bytes.len(), l)?;
        loop {
            if matches!(p.read()?, Token::Eof) {
                return Ok(());
            }
        }
    }
    #[test]
    fn structural_budgets_at_limit_and_one_over() {
        let default = CodecLimits::default();
        let cases: Vec<(Vec<u8>, CodecLimits, CodecLimits)> = vec![
            (
                b"<r><a/></r>".to_vec(),
                CodecLimits {
                    depth: 2,
                    ..default.clone()
                },
                CodecLimits {
                    depth: 1,
                    ..default.clone()
                },
            ),
            (
                b"<r><a/></r>".to_vec(),
                CodecLimits {
                    elements: 2,
                    ..default.clone()
                },
                CodecLimits {
                    elements: 1,
                    ..default.clone()
                },
            ),
            (
                b"<r/>".to_vec(),
                CodecLimits {
                    events: 3,
                    ..default.clone()
                },
                CodecLimits {
                    events: 2,
                    ..default.clone()
                },
            ),
            (
                b"<r a='1' b='2'/>".to_vec(),
                CodecLimits {
                    attributes_per_element: 2,
                    ..default.clone()
                },
                CodecLimits {
                    attributes_per_element: 1,
                    ..default.clone()
                },
            ),
            (
                b"<r a='1'><a b='2'/></r>".to_vec(),
                CodecLimits {
                    attributes: 2,
                    ..default.clone()
                },
                CodecLimits {
                    attributes: 1,
                    ..default.clone()
                },
            ),
            (
                b"<r xmlns:a='a' xmlns:b='b'/>".to_vec(),
                CodecLimits {
                    namespace_bindings: 2,
                    ..default.clone()
                },
                CodecLimits {
                    namespace_bindings: 1,
                    ..default.clone()
                },
            ),
            (
                b"<r a='12'/>".to_vec(),
                CodecLimits {
                    field_bytes: 2,
                    ..default.clone()
                },
                CodecLimits {
                    field_bytes: 1,
                    ..default.clone()
                },
            ),
        ];
        for (xml, yes, no) in cases {
            consume(&xml, &yes).unwrap();
            assert_eq!(consume(&xml, &no), Err(E::LimitExceeded), "{xml:?}");
        }
        let deep = format!("{}{}", "<r>".repeat(33), "</r>".repeat(33));
        assert_eq!(consume(deep.as_bytes(), &default), Err(E::LimitExceeded));
    }
    #[test]
    fn writer_enforces_structure_namespaces_and_escaped_event_budget() {
        let default = CodecLimits::default();
        let write = |l: &CodecLimits| -> Result<Vec<u8>> {
            let mut w = Output::new(1024, l);
            w.start("r", &[("xmlns:a", "a"), ("xmlns:b", "b")])?;
            w.content("&x&", l.field_bytes)?;
            w.end("r")?;
            w.finish()
        };
        let yes = CodecLimits {
            depth: 1,
            elements: 1,
            events: 6,
            namespace_bindings: 2,
            attributes_per_element: 2,
            attributes: 2,
            ..default.clone()
        };
        let wire = write(&yes).unwrap();
        consume(&wire, &yes).unwrap();
        for no in [
            CodecLimits {
                depth: 0,
                ..yes.clone()
            },
            CodecLimits {
                elements: 0,
                ..yes.clone()
            },
            CodecLimits {
                events: 5,
                ..yes.clone()
            },
            CodecLimits {
                namespace_bindings: 1,
                ..yes.clone()
            },
            CodecLimits {
                attributes_per_element: 1,
                ..yes.clone()
            },
            CodecLimits {
                attributes: 1,
                ..yes.clone()
            },
        ] {
            assert_eq!(write(&no), Err(E::LimitExceeded));
        }
    }
    #[test]
    fn entities_duplicate_expanded_attributes_and_illegal_characters() {
        let l = CodecLimits::default();
        for xml in [
            "<!DOCTYPE r [<!ENTITY x 'x'>]><r>&x;</r>",
            "<r>&unknown;</r>",
            "<r>&#x1;</r>",
            "<r a='1' a='2'/>",
            "<r xmlns:a='urn:x' xmlns:b='urn:x' a:k='1' b:k='2'/>",
            "<z:r/>",
            "<r a='&#x1;'/>",
        ] {
            assert!(consume(xml.as_bytes(), &l).is_err(), "{xml}");
        }
        consume(b"<r>&amp;&#65;&#x41;&lt;&gt;&apos;&quot;</r>", &l).unwrap();
    }
}
