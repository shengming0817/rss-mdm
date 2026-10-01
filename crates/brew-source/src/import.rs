//! Complete finite Ruby-DSL parsing. No Ruby process, partial regex extraction or unknown hook.
//! ref: Homebrew/brew Library/Homebrew/cask/dsl.rb@7cce6eac8d897b0b8440e16f33dbcb21770da7cf
use crate::*;
use std::collections::{BTreeMap, BTreeSet};

/// Finite native material, separate from subsequent enterprise Recipe generation.
#[derive(Clone, Debug)]
pub enum TapPayload {
    /// Precisely selected Cask and app/PKG behavior.
    Cask {
        /// Approved-origin archive/image coordinates.
        artifact: Artifact,
        /// Exact selected payload, including declared removal receipts.
        install: CaskArtifact,
    },
    /// Original source material and one precisely selected prebuilt bottle.
    Bottle {
        /// Source evidence; not authorized for building.
        source: Artifact,
        /// Complete selected bottle.
        bottle: Artifact,
        /// Exact platform tag.
        tag: BottleTag,
        /// Exact declared cellar relocation policy.
        cellar: String,
        /// Formula revision.
        revision: u32,
        /// Bottle rebuild.
        rebuild: u32,
        /// Declared prebuilt executable.
        executable: String,
    },
}
/// Metadata parsed from a fixed file; it neither publishes nor approves the result.
#[derive(Clone, Debug)]
pub struct TapImport {
    key: PackageKey,
    version: String,
    name: String,
    description: String,
    homepage: String,
    payload: TapPayload,
    dependencies: Vec<PackageKey>,
}
impl TapImport {
    /// Consume the complete bounded Cask/Formula file and reject unsupported executable semantics.
    pub fn parse(
        key: &PackageKey,
        release: &str,
        tag: BottleTag,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        if bytes.len() > MAX_DOCUMENT {
            return Err(Error::BudgetExceeded);
        }
        if release.eq_ignore_ascii_case("latest") {
            return Err(Error::Unsupported);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidInput)?;
        let lines = text.lines().map(lex).collect::<Result<Vec<_>, _>>()?;
        let mut parser = Parser { lines, position: 0 };
        let nodes = parser.nodes(0, false)?;
        if nodes.len() != 1 {
            return Err(Error::Unsupported);
        }
        let root = &nodes[0];
        validate(root)?;
        let body = selected(&root.children, tag);
        let declarations = declarations(&body)?;
        let actual = literal(required(&declarations, "version")?)?;
        if actual != release {
            return Err(Error::IdentityMismatch);
        }
        let name = if root.name == "cask" {
            literal(required(&declarations, "name")?)?
        } else {
            key.name.clone()
        };
        check_header(root, key)?;
        let description = literal(required(&declarations, "desc")?)?;
        let homepage = literal(required(&declarations, "homepage")?)?;
        Artifact::new(&homepage, [0; 32])?;
        let payload = if root.name == "cask" {
            cask(&declarations, release)?
        } else {
            bottle(key, &declarations, tag, release)?
        };
        let dependencies = dependencies(key, &body, tag)?;
        Ok(Self {
            key: key.clone(),
            version: release.into(),
            name,
            description,
            homepage,
            payload,
            dependencies,
        })
    }
    /// Exact original package coordinate.
    pub fn key(&self) -> &PackageKey {
        &self.key
    }
    /// Exact original version, not inferred from mutable URLs.
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Display name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Description.
    pub fn description(&self) -> &str {
        &self.description
    }
    /// Credential-free homepage.
    pub fn homepage(&self) -> &str {
        &self.homepage
    }
    /// Selected complete native material.
    pub fn payload(&self) -> &TapPayload {
        &self.payload
    }
    /// Qualified prerequisites; enterprise exact versions must be mapped separately.
    pub fn dependencies(&self) -> &[PackageKey] {
        &self.dependencies
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Text(String),
    Number(u32),
    Colon,
    Comma,
    Left,
    Right,
    Less,
}
fn lex(line: &str) -> Result<Vec<Token>, Error> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '#' {
            break;
        }
        let value = match c {
            ':' => Token::Colon,
            ',' => Token::Comma,
            '[' => Token::Left,
            ']' => Token::Right,
            '<' => Token::Less,
            '"' | '\'' => Token::Text(quoted(&mut chars, c)?),
            c if c.is_ascii_alphabetic() || c == '_' || c.is_ascii_digit() => {
                let mut word = c.to_string();
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
                {
                    word.push(chars.next().ok_or(Error::InvalidInput)?);
                }
                if word.bytes().all(|b| b.is_ascii_digit()) {
                    Token::Number(word.parse().map_err(|_| Error::InvalidInput)?)
                } else {
                    Token::Word(word)
                }
            }
            _ => return Err(Error::Unsupported),
        };
        out.push(value);
        if out.len() > 128 {
            return Err(Error::BudgetExceeded);
        }
    }
    Ok(out)
}
fn quoted(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    quote: char,
) -> Result<String, Error> {
    let mut value = String::new();
    while let Some(c) = chars.next() {
        if c == quote {
            return Ok(value);
        }
        if c == '\\' {
            let escaped = chars.next().ok_or(Error::InvalidInput)?;
            if !matches!(escaped, '\\' | '"' | '\'' | '#') {
                return Err(Error::Unsupported);
            }
            value.push(escaped);
        } else {
            value.push(c);
        }
        if value.len() > 4096 || c.is_control() {
            return Err(Error::BudgetExceeded);
        }
    }
    Err(Error::InvalidInput)
}
#[derive(Clone, Debug)]
enum Argument {
    Text(String),
    Number(u32),
    Symbol(String),
    Named(String, Box<Argument>),
    List(Vec<Argument>),
}
#[derive(Clone, Debug)]
struct Node {
    name: String,
    args: Vec<Argument>,
    children: Vec<Node>,
}
struct Parser {
    lines: Vec<Vec<Token>>,
    position: usize,
}
impl Parser {
    fn nodes(&mut self, depth: usize, nested: bool) -> Result<Vec<Node>, Error> {
        if depth > 8 {
            return Err(Error::BudgetExceeded);
        }
        let mut nodes = Vec::new();
        while self.position < self.lines.len() {
            let tokens = self.lines[self.position].clone();
            self.position += 1;
            if tokens.is_empty() {
                continue;
            }
            if tokens == [Token::Word("end".into())] {
                return if nested {
                    Ok(nodes)
                } else {
                    Err(Error::Unsupported)
                };
            }
            let mut node = statement(&tokens)?;
            let block = matches!(
                node.name.as_str(),
                "cask" | "class" | "install" | "bottle" | "on_arm" | "on_intel"
            );
            if block {
                node.children = self.nodes(depth + 1, true)?;
            }
            nodes.push(node);
            if nodes.len() > 256 {
                return Err(Error::BudgetExceeded);
            }
        }
        if nested {
            return Err(Error::InvalidInput);
        }
        Ok(nodes)
    }
}
fn statement(tokens: &[Token]) -> Result<Node, Error> {
    let Some(Token::Word(name)) = tokens.first() else {
        return Err(Error::Unsupported);
    };
    if name == "class" {
        let [_, Token::Word(class), Token::Less, Token::Word(parent)] = tokens else {
            return Err(Error::Unsupported);
        };
        if parent != "Formula" {
            return Err(Error::Unsupported);
        }
        return Ok(Node {
            name: name.clone(),
            args: vec![Argument::Text(class.clone())],
            children: vec![],
        });
    }
    if name == "def" {
        if tokens != [Token::Word("def".into()), Token::Word("install".into())] {
            return Err(Error::Unsupported);
        }
        return Ok(Node {
            name: "install".into(),
            args: vec![],
            children: vec![],
        });
    }
    let block = tokens.last() == Some(&Token::Word("do".into()));
    if matches!(name.as_str(), "cask" | "bottle" | "on_arm" | "on_intel") != block {
        return Err(Error::Unsupported);
    }
    let values = &tokens[1..tokens.len() - usize::from(block)];
    Ok(Node {
        name: name.clone(),
        args: args(values)?,
        children: vec![],
    })
}
fn args(tokens: &[Token]) -> Result<Vec<Argument>, Error> {
    let mut output = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == Token::Comma {
            i += 1;
            continue;
        }
        output.push(argument(tokens, &mut i)?);
    }
    Ok(output)
}
fn argument(tokens: &[Token], i: &mut usize) -> Result<Argument, Error> {
    let token = tokens.get(*i).ok_or(Error::InvalidInput)?;
    *i += 1;
    match token {
        Token::Text(value) => Ok(Argument::Text(value.clone())),
        Token::Number(value) => Ok(Argument::Number(*value)),
        Token::Colon => {
            let Some(Token::Word(name)) = tokens.get(*i) else {
                return Err(Error::Unsupported);
            };
            *i += 1;
            Ok(Argument::Symbol(name.clone()))
        }
        Token::Word(name) if tokens.get(*i) == Some(&Token::Colon) => {
            *i += 1;
            Ok(Argument::Named(
                name.clone(),
                Box::new(argument(tokens, i)?),
            ))
        }
        Token::Left => {
            let mut values = Vec::new();
            while tokens.get(*i) != Some(&Token::Right) {
                if tokens.get(*i) == Some(&Token::Comma) {
                    *i += 1;
                } else {
                    values.push(argument(tokens, i)?);
                }
                if values.len() > 32 {
                    return Err(Error::BudgetExceeded);
                }
            }
            *i += 1;
            Ok(Argument::List(values))
        }
        _ => Err(Error::Unsupported),
    }
}
fn validate(root: &Node) -> Result<(), Error> {
    if !matches!(root.name.as_str(), "class" | "cask") {
        return Err(Error::Unsupported);
    }
    validate_nodes(&root.children)
}
fn validate_nodes(nodes: &[Node]) -> Result<(), Error> {
    for node in nodes {
        match node.name.as_str() {
            "version" | "sha256" | "url" | "name" | "desc" | "homepage" | "license" | "app"
            | "pkg" | "uninstall" | "depends_on" | "revision" => {
                if !node.children.is_empty() {
                    return Err(Error::Unsupported);
                }
            }
            "on_arm" | "on_intel" => {
                if !node.args.is_empty() {
                    return Err(Error::Unsupported);
                }
                validate_nodes(&node.children)?;
            }
            "bottle" => {
                for n in &node.children {
                    if !matches!(n.name.as_str(), "root_url" | "sha256" | "rebuild")
                        || !n.children.is_empty()
                    {
                        return Err(Error::Unsupported);
                    }
                }
            }
            "install" => {
                if node.children.len() != 1
                    || node.children[0].name != "bin.install"
                    || !node.children[0].children.is_empty()
                {
                    return Err(Error::Unsupported);
                }
            }
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(())
}
fn selected(nodes: &[Node], tag: BottleTag) -> Vec<&Node> {
    let mut out = Vec::new();
    for node in nodes {
        match node.name.as_str() {
            "on_arm" if tag == BottleTag::Arm64Sonoma => out.extend(selected(&node.children, tag)),
            "on_intel" if tag == BottleTag::Sonoma => out.extend(selected(&node.children, tag)),
            "on_arm" | "on_intel" => {}
            _ => out.push(node),
        }
    }
    out
}
fn declarations<'a>(nodes: &[&'a Node]) -> Result<BTreeMap<&'a str, &'a Node>, Error> {
    let mut out = BTreeMap::new();
    for n in nodes {
        if n.name != "depends_on" && out.insert(n.name.as_str(), *n).is_some() {
            return Err(Error::Duplicate);
        }
    }
    Ok(out)
}
fn required<'a>(values: &BTreeMap<&str, &'a Node>, name: &str) -> Result<&'a Node, Error> {
    values.get(name).copied().ok_or(Error::Unsupported)
}
fn literal(node: &Node) -> Result<String, Error> {
    match node.args.as_slice() {
        [Argument::Text(value)] => Ok(value.clone()),
        _ => Err(Error::Unsupported),
    }
}
fn expanded(node: &Node, version: &str) -> Result<String, Error> {
    let value = literal(node)?.replace("#{version}", version);
    if value.contains("#{") {
        return Err(Error::Unsupported);
    }
    Ok(value)
}
fn digest(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::DigestMismatch);
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Error::DigestMismatch)?;
    }
    Ok(out)
}
fn check_header(root: &Node, key: &PackageKey) -> Result<(), Error> {
    let expected = if root.name == "cask" {
        key.name.clone()
    } else {
        key.name
            .split('-')
            .map(|part| {
                let mut c = part.chars();
                c.next()
                    .map(|x| x.to_ascii_uppercase().to_string() + c.as_str())
                    .unwrap_or_default()
            })
            .collect()
    };
    if literal(root)? != expected {
        return Err(Error::IdentityMismatch);
    }
    Ok(())
}
fn cask(values: &BTreeMap<&str, &Node>, version: &str) -> Result<TapPayload, Error> {
    let artifact = Artifact::new(
        &expanded(required(values, "url")?, version)?,
        digest(&literal(required(values, "sha256")?)?)?,
    )?;
    let install = match (values.get("app"), values.get("pkg")) {
        (Some(app), None) => CaskArtifact::App(literal(app)?),
        (None, Some(pkg)) => CaskArtifact::Pkg {
            path: literal(pkg)?,
            receipts: receipts(required(values, "uninstall")?)?,
        },
        _ => return Err(Error::Unsupported),
    };
    // Reuse the existing path/receipt restrictions without generating or executing Ruby.
    match &install {
        CaskArtifact::App(path) => {
            if path.contains('/') || !path.ends_with(".app") {
                return Err(Error::PathDenied);
            }
        }
        CaskArtifact::Pkg { path, receipts } => {
            if path.contains('/') || !path.ends_with(".pkg") || receipts.is_empty() {
                return Err(Error::PathDenied);
            }
        }
    }
    Ok(TapPayload::Cask { artifact, install })
}
fn receipts(node: &Node) -> Result<Vec<String>, Error> {
    let [Argument::Named(key, value)] = node.args.as_slice() else {
        return Err(Error::Unsupported);
    };
    if key != "pkgutil" {
        return Err(Error::Unsupported);
    }
    let values = match value.as_ref() {
        Argument::Text(v) => vec![v.clone()],
        Argument::List(values) => values
            .iter()
            .map(|v| match v {
                Argument::Text(v) => Ok(v.clone()),
                _ => Err(Error::Unsupported),
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(Error::Unsupported),
    };
    if values.is_empty()
        || values.iter().any(|v| {
            !v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(Error::Unsupported);
    }
    Ok(values)
}
fn number(values: &BTreeMap<&str, &Node>, key: &str) -> Result<u32, Error> {
    match values.get(key) {
        None => Ok(0),
        Some(node) => match node.args.as_slice() {
            [Argument::Number(n)] => Ok(*n),
            _ => Err(Error::Unsupported),
        },
    }
}
fn bottle(
    key: &PackageKey,
    values: &BTreeMap<&str, &Node>,
    tag: BottleTag,
    version: &str,
) -> Result<TapPayload, Error> {
    let source = Artifact::new(
        &expanded(required(values, "url")?, version)?,
        digest(&literal(required(values, "sha256")?)?)?,
    )?;
    let group = required(values, "bottle")?;
    let nodes: Vec<_> = group.children.iter().collect();
    let headers = declarations(&nodes)?;
    let root = expanded(required(&headers, "root_url")?, version)?;
    let (cellar, sha) = bottle_checksum(required(&headers, "sha256")?, tag)?;
    let install = required(values, "install")?;
    let executable = literal(&install.children[0])?;
    token(&executable)?;
    let revision = number(values, "revision")?;
    let rebuild = number(&headers, "rebuild")?;
    let revised = if revision == 0 {
        version.to_owned()
    } else {
        format!("{version}_{revision}")
    };
    let suffix = if rebuild == 0 {
        String::new()
    } else {
        format!(".{rebuild}")
    };
    let url = format!(
        "{}/{}--{}.{}.bottle{}.tar.gz",
        root.trim_end_matches('/'),
        key.name,
        revised,
        tag.as_str(),
        suffix
    );
    let bottle = Artifact::new(&url, sha)?;
    Ok(TapPayload::Bottle {
        source,
        bottle,
        tag,
        cellar,
        revision,
        rebuild,
        executable,
    })
}
fn bottle_checksum(node: &Node, tag: BottleTag) -> Result<(String, [u8; 32]), Error> {
    let mut cellar = None;
    let mut selected = None;
    let mut keys = BTreeSet::new();
    for arg in &node.args {
        let Argument::Named(key, value) = arg else {
            return Err(Error::Unsupported);
        };
        if !keys.insert(key) {
            return Err(Error::Duplicate);
        }
        match (key.as_str(), value.as_ref()) {
            ("cellar", Argument::Symbol(v))
                if matches!(v.as_str(), "any" | "any_skip_relocation") =>
            {
                cellar = Some(v.clone())
            }
            ("arm64_sonoma" | "sonoma", Argument::Text(v)) => {
                let sha = digest(v)?;
                if key == tag.as_str() {
                    selected = Some(sha);
                }
            }
            _ => return Err(Error::Unsupported),
        }
    }
    Ok((
        cellar.ok_or(Error::Unsupported)?,
        selected.ok_or(Error::NotFound)?,
    ))
}
fn dependencies(
    key: &PackageKey,
    nodes: &[&Node],
    tag: BottleTag,
) -> Result<Vec<PackageKey>, Error> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for node in nodes.iter().filter(|n| n.name == "depends_on") {
        if let [Argument::Named(name, value)] = node.args.as_slice() {
            if name == "arch"
                && let Argument::Symbol(arch) = value.as_ref()
            {
                let expected = match tag {
                    BottleTag::Arm64Sonoma => "arm64",
                    BottleTag::Sonoma => "x86_64",
                };
                if arch != expected {
                    return Err(Error::Unsupported);
                }
                continue;
            }
            return Err(Error::Unsupported);
        }
        let value = literal(node)?;
        let parts: Vec<_> = value.split('/').collect();
        let [owner, tap, name] = parts.as_slice() else {
            return Err(Error::Unsupported);
        };
        if !seen.insert(value.clone()) {
            return Err(Error::Duplicate);
        }
        result.push(PackageKey::new(
            key.tenant,
            &format!("{owner}/{tap}"),
            name,
        )?);
    }
    if result.len() > 32 {
        return Err(Error::BudgetExceeded);
    }
    Ok(result)
}
