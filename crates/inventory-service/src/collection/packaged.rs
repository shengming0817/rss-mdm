//! Join canonical product declarations for the protocol's generated package data.
//! ref: serde-rs/json src/value/mod.rs@v1.0.145 (typed serialization).
use crate::{Error, Failure};
use rss_mdm_agent_wire::packaged_collections::{Definition, Prerequisites};
use rss_mdm_resource::blueprints;

fn invalid() -> Error {
    Error::Unavailable(Failure::Protocol)
}

/// Assemble native baselines from their existing owners; this never creates tenant Resources.
pub fn definitions() -> Result<Vec<Definition>, Error> {
    let fields = rss_mdm_inventory::builtin::fields();
    let mut definitions = Vec::new();
    for blueprint in blueprints::catalog() {
        let blueprints::Definition::AgentCollection { template } = &blueprint.definition else {
            continue;
        };
        template
            .validate_platform(blueprint.platform)
            .map_err(|_| invalid())?;
        let spec = template.spec();
        spec.applicability.validate().map_err(|_| invalid())?;
        let selected = spec
            .mappings
            .keys()
            .map(|key| {
                let field = fields
                    .iter()
                    .find(|f| f.key.as_str() == key)
                    .ok_or_else(invalid)?;
                super::wire::to_wire_field(field)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        rss_mdm_agent_wire::runtime::validate_native_projection(
            &selected,
            &spec.mappings,
            &spec.plan,
            false,
        )
        .map_err(|_| invalid())?;
        let prerequisites: Prerequisites = serde_json::from_value(
            serde_json::to_value(&spec.applicability).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        definitions.push(Definition {
            id: blueprint.id,
            version: blueprint.version,
            category: blueprint
                .presentation
                .get("category")
                .and_then(|v| v.as_str())
                .ok_or_else(invalid)?
                .to_owned(),
            prerequisites,
            plan: spec.plan.clone(),
            fields: selected,
            mappings: spec.mappings.clone(),
        });
    }
    definitions.sort_by(|a, b| (&a.id, &a.version).cmp(&(&b.id, &b.version)));
    if definitions.is_empty()
        || definitions
            .windows(2)
            .any(|p| p[0].id == p[1].id && p[0].version == p[1].version)
    {
        return Err(invalid());
    }
    Ok(definitions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_data_matches_canonical_blueprints_and_inventory() {
        let expected = definitions().unwrap();
        assert_eq!(
            rss_mdm_agent_wire::packaged_collections::definitions().unwrap(),
            expected
        );
        assert_eq!(
            format!("{}\n", serde_json::to_string(&expected).unwrap()),
            rss_mdm_agent_wire::packaged_collections::DATA
        );
        for platform in [
            rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
            rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
        ] {
            assert!(expected.iter().any(|d| d.plan.platform() == platform));
        }
    }
}
