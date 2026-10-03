//! Read native URI applicability tables from the fixed official Learn documents.
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone, Debug, Deserialize)]
pub struct Support {
    pub builds: Vec<[u32; 4]>,
    pub preview_only: bool,
    pub source: String,
}

#[derive(Deserialize)]
pub(super) struct Facts {
    pub sources: BTreeMap<String, String>,
    pub nodes: BTreeMap<String, Support>,
    pub scenarios: Vec<(String, String)>,
    pub declared_certificate_builds: Vec<[u32; 4]>,
}

pub fn facts(root: &Path) -> Result<Facts, Box<dyn std::error::Error>> {
    let facts: Facts = serde_json::from_slice(&fs::read(root.join("schema/learn-facts.json"))?)?;
    let hashes = facts
        .sources
        .values()
        .collect::<std::collections::BTreeSet<_>>();
    if facts.nodes.is_empty()
        || facts.sources.iter().any(|(url, hash)| {
            !url.starts_with("https://learn.microsoft.com/")
                || hash.len() != 64
                || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        })
        || facts
            .nodes
            .values()
            .any(|node| !hashes.contains(&node.source))
    {
        return Err("invalid fixed Learn facts or source references".into());
    }
    if facts.scenarios.is_empty() || facts.scenarios.iter().any(|(_, source)| !hashes.contains(source)) || facts.declared_certificate_builds.is_empty() { return Err("invalid declared source facts".into()); }
    Ok(facts)
}

pub fn read(root: &Path) -> Result<BTreeMap<String, Support>, Box<dyn std::error::Error>> { Ok(facts(root)?.nodes) }

#[cfg(test)]
fn parse(
    text: &str,
    source: &str,
) -> Result<BTreeMap<String, Support>, Box<dyn std::error::Error>> {
    let mut nodes = BTreeMap::new();
    let mut applicability = None;
    let mut table = false;
    let mut uri_block = false;
    let build = regex::Regex::new(r"\[(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\]")?;
    for line in text.lines() {
        if line.starts_with('#') {
            applicability = None;
            table = false;
        }
        if line.starts_with("| Scope | Editions | Applicable OS |") {
            table = true;
            continue;
        }
        if table && line.starts_with("| ") && line.contains('✅') {
            let columns = line.split('|').collect::<Vec<_>>();
            let os = columns.get(3).ok_or("invalid Learn scope table")?;
            let mut builds = Vec::new();
            let mut preview = false;
            for branch in os.split('✅').skip(1) {
                if branch.contains("Insider") {
                    preview = true;
                    continue;
                }
                for capture in build.captures_iter(branch) {
                    builds.push([
                        capture[1].parse()?,
                        capture[2].parse()?,
                        capture[3].parse()?,
                        capture
                            .get(4)
                            .map(|v| v.as_str().parse())
                            .transpose()?
                            .unwrap_or(0),
                    ]);
                }
            }
            applicability = Some(Support {
                preview_only: preview && builds.is_empty(),
                builds,
                source: source.into(),
            });
            table = false;
        }
        if line.starts_with("```") {
            uri_block = matches!(line, "```Device" | "```User");
            continue;
        }
        if uri_block
            && line.starts_with("./")
            && let Some(support) = &applicability
        {
            nodes.insert(canonical(line), support.clone());
        }
    }
    Ok(nodes)
}

pub fn canonical(path: &str) -> String {
    let path = path
        .strip_prefix("./Vendor/")
        .map(|p| format!("./Device/Vendor/{p}"))
        .unwrap_or_else(|| path.into());
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}')
                || segment.starts_with('<') && segment.ends_with('>')
            {
                "*".into()
            } else {
                segment.replace("\\_", "_")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uri_sections_keep_preview_separate_from_stable_servicing_branches() {
        let text = "## Native\n| Scope | Editions | Applicable OS |\n| --- | --- | --- |\n| ✅ Device | ✅ Pro | ✅ Windows 11 [10.0.22621.3235] and later ✅ Windows Insider Preview |\n```Device\n./Device/Vendor/MSFT/Test/{Object}/Value\n```\n## Preview\n| Scope | Editions | Applicable OS |\n| --- | --- | --- |\n| ✅ Device | ✅ Pro | ✅ Windows Insider Preview [11.0.26100] |\n```Device\n./Device/Vendor/MSFT/Test/Preview\n```";
        let nodes = parse(text, "source").unwrap();
        assert_eq!(
            nodes["./Device/Vendor/MSFT/Test/*/Value"].builds,
            [[10, 0, 22621, 3235]]
        );
        assert!(!nodes["./Device/Vendor/MSFT/Test/*/Value"].preview_only);
        assert!(nodes["./Device/Vendor/MSFT/Test/Preview"].preview_only);
    }
}
