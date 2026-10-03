use super::{Sources, ddf, policy};
use std::{fmt::Write, path::Path};

pub fn generate(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let sources = Sources::read(root)?;
    let missing = sources.unresolved_admx();
    if !missing.is_empty() {
        return Err(format!("unresolved DDF ADMX references: {missing:?}").into());
    }
    let mut nodes = ddf::compile(&sources.ddf)?;
    super::declared::supplement(&mut nodes)?;
    let used = nodes
        .iter()
        .flat_map(|n| n.constraints.iter().filter_map(|c| c.admx.clone()))
        .collect();
    let mut out = String::from(
        "// Generated offline from the pinned Microsoft DDF and ADMX sources.\n// Run rss-mdm-native-schema --write; never edit this file directly.\nuse super::{Node, Constraint, Format};\nuse super::admx::{AdmxPolicy, AdmxElement, AdmxChoice};\npub(super) static NODES: &[Node] = &[\n",
    );
    let certificate_builds = super::learn::facts(root)?.declared_certificate_builds;
    for mut n in nodes {
        let linked_builds = if super::declared::leaf(&n.path) {
            certificate_builds.clone()
        } else {
            Vec::new()
        };
        let mut stable_source = None;
        let mut preview = false;
        if let Some(support) = sources.learn.get(&super::learn::canonical(&n.path)) {
            stable_source = Some(support.source.as_str());
            preview = support.preview_only;
            // Learn may document fewer release branches than DDF. Preserve each
            // explicit branch and use the stricter revision where sources overlap.
            for build in &support.builds {
                if let Some(existing) = n
                    .applicability
                    .builds
                    .iter_mut()
                    .find(|b| b[..3] == build[..3])
                {
                    existing[3] = existing[3].max(build[3]);
                } else {
                    n.applicability.builds.push(*build);
                }
            }
            n.applicability.builds.sort_unstable();
            n.applicability.builds.dedup();
        }
        // DMClient's "and later" servicing baseline is missing the paired 23H2
        // branch in DDF. KB5034848 explicitly covers both 22621 and 22631:
        // https://support.microsoft.com/en-us/servicing/os/windows-11/2024/02/february-29-2024-kb5034848-os-builds-22621-3235-and-22631-3235-preview
        // Subsequent branches come only from the pinned released OS templates;
        // an unrelated numerically higher branch is not release evidence.
        let bounded_branches = n.path == "./Device/Vendor/MSFT/DMClient/Provider/*/ConfigRefresh"
            || n.path
                .starts_with("./Device/Vendor/MSFT/DMClient/Provider/*/ConfigRefresh/");
        if bounded_branches {
            n.applicability.builds.retain(|b| b[0..2] == [10, 0]);
            n.applicability.builds.push([10, 0, 22631, 3235]);
            for (_, from, until, _) in &sources.templates {
                if *from > 22631 && *until != u32::MAX {
                    n.applicability.builds.push([10, 0, *from, 0]);
                }
            }
            n.applicability.builds.sort_unstable();
            n.applicability.builds.dedup();
        }
        let format = match n.format.as_str() {
            "chr" => "Text",
            "int" => "Integer",
            "bool" => "Boolean",
            "b64" => "Base64",
            "bin" => "Binary",
            "xml" => "Xml",
            "node" => "Node",
            "null" => "Null",
            "time" => "Time",
            _ => return Err("unrecognized DDF format".into()),
        };
        let access = n.access.iter().try_fold(0u8, |mask, verb| {
            Ok::<_, String>(
                mask | match verb.as_str() {
                    "Get" => 1,
                    "Add" => 2,
                    "Replace" => 4,
                    "Delete" => 8,
                    "Exec" => 16,
                    _ => return Err("unrecognized DDF operation".into()),
                },
            )
        })?;
        writeln!(
            out,
            "Node {{ path: {:?}, source: {:?}, format: Format::{format}, preview: {preview}, bounded_branches: {bounded_branches}, certificate_builds: &{linked_builds:?}, stable_source: {}, access: {access}, builds: &{:?}, editions: {}, mime: {:?}, lifetime: {:?}, occurrence: {:?}, case: {}, atomic: {}, deprecated: {}, constraints: &[",
            n.path,
            n.source,
            option(stable_source),
            n.applicability.builds,
            n.applicability
                .editions
                .as_ref()
                .map(|v| format!("Some(&{v:?})"))
                .unwrap_or_else(|| "None".into()),
            n.mime,
            n.lifetime,
            n.occurrence,
            option(n.case.as_deref()),
            n.atomic,
            option(n.deprecated.as_deref())
        )?;
        for c in n.constraints {
            writeln!(
                out,
                "Constraint {{ kind: {:?}, values: &{:?}, delimiter: {}, admx: {} }},",
                c.kind,
                c.values,
                option(c.delimiter.as_deref()),
                c.admx
                    .as_ref()
                    .map(|(file, name)| format!("Some(({file:?}, {name:?}))"))
                    .unwrap_or_else(|| "None".into())
            )?;
        }
        out.push_str("] },\n");
    }
    out.push_str("];\n");
    out.push_str(&policy::emit(&sources, &used)?);
    out.push_str(&super::declared::emit(root)?);
    Ok(out)
}

fn option(value: Option<&str>) -> String {
    value
        .map(|s| format!("Some({s:?})"))
        .unwrap_or_else(|| "None".into())
}
