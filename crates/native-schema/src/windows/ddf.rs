//! Compile native DDF identities and inherited applicability, without interpreting prose as schema.
use crate::xml::{Element, local};
use std::collections::BTreeSet;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Applicability {
    pub builds: Vec<[u32; 4]>,
    pub editions: Option<Vec<String>>,
}
#[derive(Debug)]
pub struct Node {
    pub path: String,
    pub format: String,
    pub access: Vec<String>,
    pub applicability: Applicability,
    pub source: String,
    pub constraints: Vec<Constraint>,
    pub atomic: bool,
    pub deprecated: Option<String>,
    pub mime: String,
    pub lifetime: String,
    pub occurrence: String,
    pub case: Option<String>,
}
#[derive(Debug)]
pub struct Constraint {
    pub kind: String,
    pub values: Vec<String>,
    pub delimiter: Option<String>,
    pub admx: Option<(String, String)>,
}

pub fn compile(sources: &[(String, Element)]) -> Result<Vec<Node>, String> {
    let mut nodes = Vec::new();
    for (name, document) in sources {
        for node in document.children("Node") {
            visit(node, "", &Applicability::default(), name, &mut nodes)?;
        }
    }
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    if nodes.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err("duplicate native DDF identity".into());
    }
    Ok(nodes)
}

fn applicability(p: &Element, parent: &Applicability) -> Result<Applicability, String> {
    let mut result = parent.clone();
    if let Some(a) = p.child("Applicability") {
        if let Some(builds) = a.value("OsBuildVersion") {
            result.builds = builds
                .split(',')
                .map(|raw| {
                    let parts = raw
                        .trim()
                        .split('.')
                        .map(str::parse::<u32>)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| "invalid DDF build")?;
                    if !(3..=4).contains(&parts.len()) {
                        return Err("invalid DDF build components");
                    }
                    Ok([
                        parts[0],
                        parts[1],
                        parts[2],
                        parts.get(3).copied().unwrap_or(0),
                    ])
                })
                .collect::<Result<_, _>>()?;
        }
        if let Some(editions) = a.value("EditionAllowList") {
            result.editions = Some(
                editions
                    .split(';')
                    .filter(|s| !s.is_empty())
                    .map(|raw| {
                        let raw = raw.trim();
                        u32::from_str_radix(
                            raw.strip_prefix("0x")
                                .ok_or("invalid DDF edition prefix")?
                                .trim_end_matches('*'),
                            16,
                        )
                        .map_err(|_| "invalid DDF edition")?;
                        Ok::<_, &str>(raw.to_owned())
                    })
                    .collect::<Result<_, _>>()?,
            );
        }
    }
    Ok(result)
}

fn visit(
    e: &Element,
    parent: &str,
    support: &Applicability,
    source: &str,
    nodes: &mut Vec<Node>,
) -> Result<(), String> {
    let name = e.value("NodeName").ok_or("DDF node name missing")?;
    if name.contains('/') || name == "*" {
        return Err("invalid DDF node segment".into());
    }
    let path = format!(
        "{}/{}",
        e.value("Path").unwrap_or(parent),
        if name.is_empty() { "*" } else { name }
    );
    if !path.starts_with("./") {
        return Err("DDF path missing root".into());
    }
    let p = e.child("DFProperties").ok_or("DDF properties missing")?;
    let support = applicability(p, support)?;
    let format = p
        .child("DFFormat")
        .and_then(|e| e.children.first())
        .map(|e| local(&e.name))
        .ok_or("DDF format missing")?;
    if !matches!(
        format,
        "chr" | "int" | "bool" | "b64" | "bin" | "xml" | "node" | "null" | "time"
    ) {
        return Err(format!("unknown DDF format: {format}"));
    }
    let access = p
        .child("AccessType")
        .ok_or("DDF access missing")?
        .children
        .iter()
        .map(|c| local(&c.name).to_owned())
        .collect::<Vec<_>>();
    if access
        .iter()
        .any(|s| !matches!(s.as_str(), "Get" | "Add" | "Replace" | "Delete" | "Exec"))
    {
        return Err("unknown DDF access operation".into());
    }
    if access.iter().collect::<BTreeSet<_>>().len() != access.len() {
        return Err("duplicate DDF access operation".into());
    }
    let constraints = p
        .children("AllowedValues")
        .map(constraint)
        .collect::<Result<Vec<_>, _>>()?;
    nodes.push(Node {
        path: path.clone(),
        format: format.into(),
        access,
        applicability: support.clone(),
        source: source.into(),
        constraints,
        atomic: p.child("AtomicRequired").is_some(),
        deprecated: p.child("Deprecated").map(|d| {
            d.attributes
                .get("OsBuildDeprecated")
                .cloned()
                .unwrap_or_default()
        }),
        mime: p
            .child("DFType")
            .and_then(|d| d.value("MIME"))
            .unwrap_or("")
            .into(),
        lifetime: p
            .child("Scope")
            .and_then(|d| d.children.first())
            .map(|d| local(&d.name))
            .unwrap_or("")
            .into(),
        occurrence: p
            .child("Occurrence")
            .and_then(|d| d.children.first())
            .map(|d| local(&d.name))
            .unwrap_or("")
            .into(),
        case: p
            .child("CaseSense")
            .and_then(|d| d.children.first())
            .map(|d| local(&d.name).to_owned()),
    });
    for child in e.children("Node") {
        visit(child, &path, &support, source, nodes)?;
    }
    Ok(())
}

fn constraint(e: &Element) -> Result<Constraint, String> {
    let kind = e
        .attributes
        .get("ValueType")
        .ok_or("DDF constraint kind missing")?
        .clone();
    if !matches!(
        kind.as_str(),
        "None" | "ENUM" | "Range" | "RegEx" | "Flag" | "ADMX" | "XSD" | "SDDL" | "JSON"
    ) {
        return Err(format!("unknown DDF constraint: {kind}"));
    }
    let values = if matches!(kind.as_str(), "ENUM" | "Flag") {
        e.children("Enum")
            .map(|e| {
                e.value("Value")
                    .ok_or("DDF enum value missing")
                    .map(str::to_owned)
            })
            .collect::<Result<_, _>>()?
    } else {
        e.children("Value")
            .map(|e| e.text.trim().to_owned())
            .collect()
    };
    let delimiter = e
        .child("List")
        .and_then(|e| e.attributes.get("Delimiter"))
        .cloned();
    let admx = e
        .child("AdmxBacked")
        .map(|a| {
            Ok::<_, String>((
                a.attributes
                    .get("File")
                    .ok_or("DDF ADMX file missing")?
                    .to_ascii_lowercase(),
                a.attributes
                    .get("Name")
                    .ok_or("DDF ADMX name missing")?
                    .clone(),
            ))
        })
        .transpose()?;
    Ok(Constraint {
        kind,
        values,
        delimiter,
        admx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dynamic_identity_and_partial_applicability_inherit_independently() {
        let xml = br#"<MgmtTree><Node><NodeName>Sample</NodeName><Path>./User/Vendor/MSFT</Path><DFProperties><AccessType><Get/></AccessType><DFFormat><node/></DFFormat><Applicability><OsBuildVersion>10.0.26100, 10.0.22621.5126</OsBuildVersion><EditionAllowList>0x30;0x4;</EditionAllowList></Applicability></DFProperties><Node><NodeName></NodeName><DFProperties><AccessType><Add/><Delete/></AccessType><DFFormat><chr/></DFFormat><Applicability><OsBuildVersion>10.0.26100.6725</OsBuildVersion></Applicability><AllowedValues ValueType="ENUM"><Enum><Value>one</Value></Enum></AllowedValues></DFProperties></Node></Node></MgmtTree>"#;
        let nodes = compile(&[("sample.xml".into(), crate::xml::parse(xml).unwrap())]).unwrap();
        assert_eq!(nodes[1].path, "./User/Vendor/MSFT/Sample/*");
        assert_eq!(
            nodes[0].applicability.builds,
            [[10, 0, 26100, 0], [10, 0, 22621, 5126]]
        );
        assert_eq!(nodes[1].applicability.builds, [[10, 0, 26100, 6725]]);
        assert_eq!(
            nodes[1].applicability.editions,
            Some(vec!["0x30".into(), "0x4".into()])
        );
        assert_eq!(nodes[1].constraints[0].values, ["one"]);
    }
}
