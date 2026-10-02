//! Publication prepares Execution-owned immutable inputs in the existing transaction.
use rss_mdm_agent_wire as wire;
use rss_mdm_execution_service::action_contract::*;
use rss_mdm_policy::schedule::Schedule;
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
/// Freeze checked resources under the caller's existing execution transaction.
pub(crate) async fn freeze_script_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    prepared: &r::PreparedScript<'_>,
    schedule: Schedule,
    run_lifetime_seconds: u32,
) -> crate::transaction::Result<FrozenAction> {
    let script = prepared.definition();
    let collection = if let r::ScriptPurpose::Collection { mappings } = &script.spec().purpose {
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
        input: ExecutionInput {
            platform: match prepared.variant().platform() {
                r::Platform::Windows => Platform::Windows,
                r::Platform::MacOS => Platform::Macos,
            },
            architecture: match prepared.variant().architecture() {
                r::Architecture::X86_64 => Architecture::X86_64,
                r::Architecture::Aarch64 => Architecture::Aarch64,
            },
            parameters: prepared.parameters().clone(),
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

pub(crate) async fn freeze_collection<'a>(
    tx: &mut PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    version: &r::Version,
    variant: &r::Variant,
    source: rss_mdm_inventory::Source,
    keys: impl Iterator<Item = &'a String>,
) -> crate::transaction::Result<rss_mdm_inventory::CollectionDefinition> {
    use crate::transaction::{Result, checked_input};
    use sha2::{Digest, Sha256};
    let dataset = format!(
        "resource.{:x}",
        Sha256::digest(checked_input(serde_json::to_vec(&(
            version.resource().as_str(),
            variant.key().as_str()
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
        return Ok(existing);
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
    let definition = checked_input(rss_mdm_inventory::CollectionDefinition::new(
        &dataset, template, source, fields,
    ))?;
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
