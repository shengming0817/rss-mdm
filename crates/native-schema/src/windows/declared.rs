//! Node-specific source corrections, consumed only from fixed structured facts.
use super::{ddf::Node, learn};
use std::{fmt::Write, path::Path};
pub fn leaf(path: &str) -> bool {
    path == "./Device/Vendor/MSFT/DeclaredConfiguration/ManagementServiceConfiguration/RefreshInterval"
        || path.contains("/DeclaredConfiguration/Host/")
            && [
                "/Complete/Documents/*/Document",
                "/Complete/Results/*/Document",
                "/Inventory/Documents/*/Document",
                "/Inventory/Results/*/Document",
            ]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}
pub fn emit(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let facts = learn::facts(root)?;
    let mut out = String::from("\npub(super) static DECLARED_SCENARIOS: &[(&str,&str)] = &[\n");
    for (name, source) in facts.scenarios {
        writeln!(out, "({name:?},{source:?}),")?;
    }
    out.push_str("];\n");
    Ok(out)
}
pub fn supplement(nodes: &mut Vec<Node>) -> Result<(), String> {
    let parent = nodes
        .iter()
        .find(|n| n.path == "./Device/Vendor/MSFT/DeclaredConfiguration")
        .ok_or("missing DeclaredConfiguration DDF parent")?;
    let applicability = parent.applicability.clone();
    let path =
        "./Device/Vendor/MSFT/DeclaredConfiguration/ManagementServiceConfiguration/RefreshInterval";
    if !nodes.iter().any(|n| n.path == path) {
        nodes.push(Node {
            path: path.into(),
            format: "int".into(),
            access: vec!["Get".into(), "Replace".into(), "Delete".into()],
            applicability,
            source: "Learn:c189fd88d7d2b0eae46c76ef22af81d33963fd165e6590984d386f14f5dc4319".into(),
            constraints: Vec::new(),
            atomic: false,
            deprecated: None,
            mime: "text/plain".into(),
            lifetime: "Permanent".into(),
            occurrence: "ZeroOrOne".into(),
            case: None,
        });
    }
    // The official resource-access protocol explicitly uses User Document/Results leaves.
    // Do not copy the rest of the Device-only DDF subtree into the User tree.
    let additions = nodes
        .iter()
        .filter(|n| leaf(&n.path) && n.path.starts_with("./Device/") && n.path.contains("/Host/"))
        .map(|n| Node {
            path: n.path.replacen("./Device/", "./User/", 1),
            format: n.format.clone(),
            access: n.access.clone(),
            applicability: n.applicability.clone(),
            source: n.source.clone(),
            constraints: Vec::new(),
            atomic: n.atomic,
            deprecated: n.deprecated.clone(),
            mime: n.mime.clone(),
            lifetime: n.lifetime.clone(),
            occurrence: n.occurrence.clone(),
            case: n.case.clone(),
        })
        .collect::<Vec<_>>();
    nodes.extend(additions);
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    if nodes.windows(2).any(|p| p[0].path == p[1].path) {
        return Err("duplicate corrected node".into());
    }
    Ok(())
}
