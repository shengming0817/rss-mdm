//! ADMX element contracts, from the actual OS templates selected for each target release.
use super::Sources;
use crate::xml::{Element, local};
use std::{collections::BTreeSet, fmt::Write};

pub fn emit(
    sources: &Sources,
    used: &BTreeSet<(String, String)>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = String::from("pub(super) static POLICIES: &[AdmxPolicy] = &[\n");
    for (file, from, until, document) in &sources.templates {
        for policy in document
            .child("policies")
            .into_iter()
            .flat_map(|p| p.children("policy"))
        {
            let name = policy
                .attributes
                .get("name")
                .ok_or("ADMX policy name missing")?;
            if !used.contains(&(file.clone(), name.clone())) {
                continue;
            }
            let class = policy
                .attributes
                .get("class")
                .ok_or("ADMX policy class missing")?;
            if !matches!(class.as_str(), "Machine" | "User" | "Both") {
                return Err("unknown ADMX scope".into());
            }
            writeln!(
                out,
                "AdmxPolicy {{ file: {file:?}, name: {name:?}, from: {from}, until: {until}, class: {class:?}, elements: &["
            )?;
            let mut ids = BTreeSet::new();
            for element in policy
                .child("elements")
                .into_iter()
                .flat_map(|p| &p.children)
            {
                let id = element
                    .attributes
                    .get("id")
                    .ok_or("ADMX element ID missing")?;
                if !ids.insert(id) {
                    return Err("duplicate ADMX element ID".into());
                }
                let kind = local(&element.name);
                if !matches!(
                    kind,
                    "text" | "multiText" | "boolean" | "decimal" | "enum" | "list"
                ) {
                    return Err(format!("unrecognized ADMX element kind {kind}").into());
                }
                let min = number(element, "minValue", 0)?;
                let max = number(element, "maxValue", u32::MAX.into())?;
                let length = number(element, "maxLength", 1_048_576)?;
                writeln!(
                    out,
                    "AdmxElement {{ id: {id:?}, kind: {kind:?}, min: {min}, max: {max}, max_length: {length}, choices: &["
                )?;
                if kind == "enum" {
                    for item in element.children("item") {
                        let value = item
                            .child("value")
                            .and_then(|v| v.children.first())
                            .ok_or("ADMX enum value missing")?;
                        match local(&value.name) {
                            "decimal" => writeln!(
                                out,
                                "AdmxChoice::Integer({}),",
                                number(value, "value", 0)?
                            )?,
                            "delete" => out.push_str("AdmxChoice::Delete,\n"),
                            "string" => writeln!(out, "AdmxChoice::Text({:?}),", value.text)?,
                            other => return Err(format!("unknown ADMX enum atom {other}").into()),
                        }
                    }
                }
                out.push_str("] },\n");
            }
            out.push_str("] },\n");
        }
    }
    out.push_str("];\n");
    Ok(out)
}

fn number(e: &Element, key: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(e.attributes
        .get(key)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(default))
}
