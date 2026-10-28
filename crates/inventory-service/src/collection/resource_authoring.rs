//! Collection declarations are validated against this owner's fenced catalog.
use crate::{Error, transaction::*};
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
/// Hold the same fence as field edits until the initiating transaction settles.
pub async fn fence_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    crate::transaction::lock(tx).await
}
/// Validate actual Resource declarations, never client-provided validation flags.
pub async fn validate_in(tx: &mut PgTransaction<'_>, version: &r::Version) -> Result<()> {
    let catalog = crate::assets::catalog_in(tx, tx.tenant_id(), i64::MAX).await?;
    for variant in version.variants() {
        let binding = match variant.declaration() {
            r::Declaration::Script { definition, .. } => match &definition.spec().purpose {
                r::ScriptPurpose::Collection { mappings, .. } => Some((
                    if definition.spec().profile == r::ScriptProfile::Osquery {
                        rss_mdm_inventory::Source::AgentOsquery
                    } else {
                        rss_mdm_inventory::Source::AgentScript
                    },
                    mappings.keys().collect::<Vec<_>>(),
                )),
                _ => None,
            },
            r::Declaration::AgentCollection { definition, .. } => Some((
                rss_mdm_inventory::Source::AgentNative,
                definition.spec().mappings.keys().collect(),
            )),
            r::Declaration::NativeCollection { definition, .. } => Some((
                match definition.spec().adapter {
                    r::NativeAdapter::WindowsRead => rss_mdm_inventory::Source::MdmWindows,
                    rss_mdm_resource::NativeAdapter::AppleDeviceInformation
                    | rss_mdm_resource::NativeAdapter::AppleInstalledApplications
                    | rss_mdm_resource::NativeAdapter::AppleSecurity
                    | rss_mdm_resource::NativeAdapter::AppleProfiles
                    | rss_mdm_resource::NativeAdapter::AppleCertificates
                    | rss_mdm_resource::NativeAdapter::AppleUsers => {
                        rss_mdm_inventory::Source::MdmApple
                    }
                },
                definition.spec().mappings.keys().collect(),
            )),
            _ => None,
        };
        if let Some((source, keys)) = binding {
            let platform = match variant.platform() {
                r::Platform::Windows => rss_mdm_inventory::Platform::Windows,
                r::Platform::MacOS => rss_mdm_inventory::Platform::Macos,
            };
            let projection_fields = keys
                .iter()
                .map(|key| {
                    let field = checked_input(
                        catalog.definition(checked_input(rss_mdm_inventory::FieldKey::parse(key))?),
                    )?;
                    crate::collection::wire::to_wire_field(field)
                        .map_err(|_| Error::Malformed.into())
                })
                .collect::<Result<Vec<_>>>()?;
            match variant.declaration() {
                r::Declaration::AgentCollection { definition, .. } => {
                    checked_input(rss_mdm_agent_wire::runtime::validate_projection_size(&(
                        &projection_fields,
                        &definition.spec().mappings,
                    )))?
                }
                r::Declaration::NativeCollection { definition, .. } => {
                    checked_input(rss_mdm_agent_wire::runtime::validate_projection_size(&(
                        &projection_fields,
                        &definition.spec().mappings,
                    )))?
                }
                r::Declaration::Script { definition, .. } => {
                    if let r::ScriptPurpose::Collection { mappings, .. } =
                        &definition.spec().purpose
                    {
                        checked_input(rss_mdm_agent_wire::runtime::validate_projection_size(&(
                            &projection_fields,
                            mappings,
                            &definition.spec().output,
                        )))?;
                    }
                }
                _ => (),
            }
            for key in keys {
                let field = checked_input(
                    catalog.definition(checked_input(rss_mdm_inventory::FieldKey::parse(key))?),
                )?;
                if !field.sources.contains_key(&source) || !field.platforms.contains(&platform) {
                    return Err(Error::Malformed.into());
                }
                if let r::Declaration::AgentCollection { definition, .. } = variant.declaration() {
                    crate::collection::native::validate_agent_mapping(
                        field,
                        definition,
                        &definition.spec().mappings[key],
                    )
                    .map_err(|_| Error::Malformed)?;
                }
                let mapping = match variant.declaration() {
                    // Agent mappings were checked above, including explicit generated columns.
                    r::Declaration::AgentCollection { .. } => None,
                    r::Declaration::NativeCollection { definition, .. } => {
                        Some(&definition.spec().mappings[key].mapping)
                    }
                    r::Declaration::Script { definition, .. } => match &definition.spec().purpose {
                        r::ScriptPurpose::Collection { mappings, .. } => Some(&mappings[key]),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(mapping) = mapping {
                    crate::collection::native::validate_mapping(field, mapping)
                        .map_err(|_| Error::Malformed)?;
                }
            }
        }
    }
    Ok(())
}
/// Load exact published field versions while checking current catalog membership.
pub async fn profile_fields_in(
    tx: &mut PgTransaction<'_>,
    profile: &r::TelemetryProfile,
) -> Result<Vec<rss_mdm_inventory::FieldDefinition>> {
    let tenant = tx.tenant_id();
    let catalog = crate::assets::catalog_in(tx, tenant, i64::MAX).await?;
    let mut fields = Vec::new();
    for frozen in &profile.spec().fields {
        let key = checked_input(rss_mdm_inventory::FieldKey::parse(&frozen.key))?;
        checked_input(catalog.definition(key))?;
        let revision = frozen.version;
        let field = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::field_version_in(c, tenant, key, revision)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("field snapshot unavailable".into()))
                })
            })
            .await?
            .ok_or(Error::Conflict)?;
        fields.push(field);
    }
    Ok(fields)
}
