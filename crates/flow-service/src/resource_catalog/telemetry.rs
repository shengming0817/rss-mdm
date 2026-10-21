//! Publication binds sampling to a real immutable collection template and the one catalog.
use super::*;
pub(crate) async fn validate(
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
    catalog: &rss_mdm_inventory::Catalog,
    profile: &r::TelemetryProfile,
) -> Result<Vec<rss_mdm_inventory::FieldDefinition>> {
    let spec = profile.spec();
    let (template, state) = checked(
        pg::lock_reference_in(
            tx,
            &id(&spec.template.resource)?,
            &id(&spec.template.version)?,
        )
        .await?,
    )?;
    if state == r::State::Archived || template.tenant() != tenant {
        return Err(Error::Conflict.into());
    }
    let variant = checked_input(template.resolve(
        spec.template.platform,
        spec.template.architecture,
        &id(&spec.template.variant)?,
    ))?;
    let (source, keys) = match variant.declaration() {
        r::Declaration::AgentCollection { definition, .. } => {
            if !spec.parameters.is_empty()
                || definition.spec().plan.spec().scope
                    != rss_mdm_agent_wire::CollectionScope::Device
            {
                return Err(Error::Malformed.into());
            }
            (
                rss_mdm_inventory::Source::AgentNative,
                definition.spec().mappings.keys().collect::<Vec<_>>(),
            )
        }
        r::Declaration::Script { definition, .. } => match &definition.spec().purpose {
            r::ScriptPurpose::Collection {
                mappings, scope, ..
            } => {
                if spec.budget.execution_millis < 1000
                    || *scope != r::TemplateScope::Device
                    || definition.spec().run_as != r::RunAs::System
                {
                    return Err(Error::Malformed.into());
                }
                checked_input(definition.validate_parameters(&serde_json::json!(spec.parameters)))?;
                (
                    if definition.spec().profile == r::ScriptProfile::Osquery {
                        rss_mdm_inventory::Source::AgentOsquery
                    } else {
                        rss_mdm_inventory::Source::AgentScript
                    },
                    mappings.keys().collect(),
                )
            }
            _ => return Err(Error::Malformed.into()),
        },
        _ => return Err(Error::Malformed.into()),
    };
    let platform = match spec.template.platform {
        r::Platform::Windows => rss_mdm_inventory::Platform::Windows,
        r::Platform::MacOS => rss_mdm_inventory::Platform::Macos,
    };
    let mut fields = Vec::new();
    let mut resources = 0u32;
    for frozen in &spec.fields {
        let key = checked_input(rss_mdm_inventory::FieldKey::parse(&frozen.key))?;
        checked_input(catalog.definition(key))?;
        let version = frozen.version;
        let field = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::field_version_in(c, tenant, key, version)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("field snapshot unavailable".into()))
                })
            })
            .await?
            .ok_or(Error::Conflict)?;
        if field.version != frozen.version
            || !keys.iter().any(|key| key.as_str() == field.key.as_str())
            || !field.sources.contains_key(&source)
            || !field.platforms.contains(&platform)
        {
            return Err(Error::Conflict.into());
        }
        if spec.projection != r::TelemetryProjection::Current && field.time_series.is_none() {
            return Err(Error::Malformed.into());
        }
        resources = resources
            .checked_add(field.time_series.as_ref().map_or(1, |b| b.max_resources))
            .ok_or(Error::Malformed)?;
        fields.push(field.clone());
    }
    if resources > spec.budget.resources || resources > spec.budget.points {
        return Err(Error::Malformed.into());
    }
    Ok(fields)
}
