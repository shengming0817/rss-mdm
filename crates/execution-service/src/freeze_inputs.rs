//! Publication prepares Execution-owned immutable inputs in the existing transaction.
use crate::action_contract::*;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::schedule::Schedule;
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
/// Freeze checked resources under the caller's existing execution transaction.
pub(crate) async fn freeze_script_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    prepared: &r::SelectedScript<'_>,
    parameters: rss_mdm_policy::ParameterSources,
    schedule: Schedule,
    run_lifetime_seconds: u32,
) -> crate::transaction::Result<FrozenAction> {
    let script = prepared.definition();
    let collection = if let r::ScriptPurpose::Collection { mappings, .. } = &script.spec().purpose {
        let source = if script.spec().profile == r::ScriptProfile::Osquery {
            rss_mdm_inventory::Source::AgentOsquery
        } else {
            rss_mdm_inventory::Source::AgentScript
        };
        Some(
            freeze_collection(
                tx,
                tenant,
                prepared.version(),
                prepared.variant(),
                source,
                mappings.keys(),
            )
            .await?,
        )
    } else {
        None
    };
    let artifact = prepared.artifact();
    Ok(FrozenAction {
        collection,
        resource: wire::TaskResource {
            id: prepared.version().resource().as_str().into(),
            version: prepared.version().label().as_str().into(),
            variant: prepared.variant().key().as_str().into(),
        },
        parameters,
        input: ExecutionInput {
            platform: match prepared.variant().platform() {
                r::Platform::Windows => Platform::Windows,
                r::Platform::MacOS => Platform::Macos,
            },
            architecture: match prepared.variant().architecture() {
                r::Architecture::X86_64 => Architecture::X86_64,
                r::Architecture::Aarch64 => Architecture::Aarch64,
            },
            schedule,
            run_lifetime_seconds,
        },
        definition: script.clone(),
        resource_digest: prepared.version().digest().bytes(),
        artifact_reference: artifact.reference().as_str().into(),
        content: wire::TaskContent {
            length: artifact.length(),
            sha256: artifact.digest().bytes(),
        },
    })
}

pub(crate) async fn prepare_collection_in<'a>(
    tx: &mut PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    version: &r::Version,
    variant: &r::Variant,
    source: rss_mdm_inventory::Source,
    keys: impl Iterator<Item = &'a String>,
) -> crate::transaction::Result<(rss_mdm_inventory::CollectionDefinition, bool)> {
    use crate::transaction::{Result, checked_input};
    use sha2::{Digest, Sha256};
    let scope = match variant.declaration() {
        r::Declaration::NativeCollection { definition, .. } => match &definition.spec().scope {
            r::TemplateScope::Device => rss_mdm_inventory::CollectionScope::Device,
            r::TemplateScope::User { identity } => rss_mdm_inventory::CollectionScope::AppleUser {
                identity: identity.clone(),
            },
            _ => return Err(crate::Error::Malformed.into()),
        },
        r::Declaration::AgentCollection { .. } => return Err(crate::Error::Malformed.into()),
        _ => rss_mdm_inventory::CollectionScope::Device,
    };
    let dataset = format!(
        "resource.{:x}",
        Sha256::digest(checked_input(serde_json::to_vec(&(
            version.resource().as_str(),
            variant.key().as_str(),
            &scope
        )))?)
    );
    let template = format!("{:x}", Sha256::digest(version.digest().bytes()));
    let lookup = (dataset.clone(), template.clone());
    let existing = tx
        .with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_inventory_postgres::collection_version_in(
                    c, tenant, source, &lookup.0, &lookup.1,
                )
                .await
                .map_err(|_| sqlx::Error::Protocol("collection lookup".into()))
            })
        })
        .await?;
    if let Some(existing) = existing {
        return Ok((existing, true));
    }
    let catalog = crate::assets::catalog_in(tx, tenant, i64::MAX).await?;
    let fields = keys
        .map(|name| {
            checked_input(
                catalog
                    .definition(checked_input(rss_mdm_inventory::FieldKey::parse(name))?)
                    .cloned(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let platform = match variant.platform() {
        r::Platform::Windows => rss_mdm_inventory::Platform::Windows,
        r::Platform::MacOS => rss_mdm_inventory::Platform::Macos,
    };
    if fields
        .iter()
        .any(|field| !field.platforms.contains(&platform))
    {
        return Err(crate::Error::Malformed.into());
    }
    let definition = checked_input(rss_mdm_inventory::CollectionDefinition::new(
        &dataset,
        template,
        source,
        {
            let fields: Vec<rss_mdm_inventory::FieldDefinition> = fields;
            fields
                .into_iter()
                .map(|definition| rss_mdm_inventory::CollectionField {
                    definition,
                    scope: scope.clone(),
                })
                .collect()
        },
    ))?;
    Ok((definition, false))
}

pub(crate) async fn freeze_collection<'a>(
    tx: &mut PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    version: &r::Version,
    variant: &r::Variant,
    source: rss_mdm_inventory::Source,
    keys: impl Iterator<Item = &'a String>,
) -> crate::transaction::Result<rss_mdm_inventory::CollectionDefinition> {
    let (definition, published) =
        prepare_collection_in(tx, tenant, version, variant, source, keys).await?;
    if published {
        return Ok(definition);
    }
    let frozen = definition.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_inventory_postgres::register_collection_in(c, tenant, &frozen)
                .await
                .map_err(|_| sqlx::Error::Protocol("collection publication".into()))
        })
    })
    .await?;
    Ok(definition)
}

/// Validate publication fields without inventing an execution user's asset namespace.
pub(crate) async fn prepare_agent_fields(
    tx: &mut PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    variant: &r::Variant,
    definition: &r::AgentCollectionDefinition,
) -> crate::transaction::Result<Vec<rss_mdm_inventory::FieldDefinition>> {
    use crate::transaction::checked_input;
    let catalog = crate::assets::catalog_in(tx, tenant, i64::MAX).await?;
    let platform = match variant.platform() {
        r::Platform::Windows => rss_mdm_inventory::Platform::Windows,
        r::Platform::MacOS => rss_mdm_inventory::Platform::Macos,
    };
    let fields = definition
        .spec()
        .mappings
        .iter()
        .map(|(name, binding)| {
            let key = checked_input(rss_mdm_inventory::FieldKey::parse(name))?;
            let field = checked_input(catalog.definition(key))?;
            if !field.platforms.contains(&platform)
                || !field
                    .sources
                    .contains_key(&rss_mdm_inventory::Source::AgentNative)
            {
                return Err(crate::Error::Malformed.into());
            }
            checked_input(
                rss_mdm_inventory_service::collection::native::validate_agent_mapping(
                    field, definition, binding,
                ),
            )?;
            Ok(field.clone())
        })
        .collect::<crate::transaction::Result<Vec<_>>>()?;
    let wire_fields = fields
        .iter()
        .map(rss_mdm_inventory_service::collection::wire::to_wire_field)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| crate::Error::Malformed)?;
    checked_input(wire::validate_native_projection(
        &wire_fields,
        &definition.spec().mappings,
        &definition.spec().plan,
        false,
    ))?;
    Ok(fields)
}
