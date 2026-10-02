//! Frozen execution contract. It deliberately excludes authors, approval rows and Scope internals.
use crate::Error;
use rss_mdm_agent_wire as wire;
use rss_mdm_policy::schedule::Schedule;
pub use rss_mdm_policy::{Architecture, Platform};
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub parameters: Value,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenAction {
    pub input: ExecutionInput,
    pub definition: r::ScriptDefinition,
    pub collection: Option<rss_mdm_inventory::CollectionDefinition>,
    pub resource_digest: [u8; 32],
    pub artifact_reference: String,
    pub content: wire::TaskContent,
}
impl FrozenAction {
    pub fn artifact(&self) -> Result<r::Artifact, Error> {
        r::Artifact::new(
            r::Id::new(&self.artifact_reference).map_err(|_| Error::Malformed)?,
            self.content.length,
            r::Digest::from_bytes(self.content.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
}
/// Enterprise software input frozen at Policy publication, before per-device admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenSoftwareAction {
    pub delivery: rss_mdm_policy::SoftwareDelivery,
    pub resource: String,
    pub version: String,
    pub variants: BTreeMap<rss_mdm_policy::SoftwareTarget, String>,
    pub resource_digest: [u8; 32],
    pub admission_operation: uuid::Uuid,
    pub intent: rss_mdm_policy::SoftwareIntent,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenNativeCollection {
    pub input: ExecutionInput,
    pub definition: r::NativeCollectionDefinition,
    pub windows_queries: Vec<rss_mdm_windows_mdm::native::Request>,
    pub grants: BTreeMap<String, Vec<crate::authorization::UserGrant>>,
    pub collection: rss_mdm_inventory::CollectionDefinition,
    pub resource_digest: [u8; 32],
}
pub trait ScheduledInput {
    fn execution_input(&self) -> &ExecutionInput;
}
impl ScheduledInput for FrozenAction {
    fn execution_input(&self) -> &ExecutionInput {
        &self.input
    }
}
impl ScheduledInput for FrozenNativeCollection {
    fn execution_input(&self) -> &ExecutionInput {
        &self.input
    }
}

impl FrozenNativeCollection {
    pub fn permissions(&self) -> Result<Vec<crate::authorization::Permission>, Error> {
        let mut permissions = vec![crate::authorization::Permission::InventoryCollect];
        if !self.windows_queries.is_empty() {
            permissions.extend(
                crate::execution::Task::Windows {
                    request: rss_mdm_windows_mdm::native::Execution::SyncMl {
                        request: rss_mdm_windows_mdm::native::Request::Sequence {
                            operations: self.windows_queries.clone(),
                        },
                    },
                }
                .permissions()?,
            );
        }
        // Collection facts flow to Inventory; credential-bearing carriers are not asset fields.
        if permissions.contains(&crate::authorization::Permission::Credentials) {
            return Err(Error::Unsupported);
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }
}

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
