//! Resource directory use cases; metadata remains owned by ResourceStore.
use crate::operation::Operation;
use crate::transaction::*;
use crate::{Error, Failure};
use rss_contract::Timepoint;
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
use std::sync::Arc;
pub mod directory;
pub mod wire;

use rss_mdm_resource as r;
use rss_mdm_resource_postgres as pg;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Software,
    Script,
    Configuration,
}
impl Kind {
    fn core(&self) -> r::Kind {
        match self {
            Self::Software => r::Kind::Software,
            Self::Script => r::Kind::Script,
            Self::Configuration => r::Kind::Configuration,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Windows,
    Macos,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    reference: String,
    length: u64,
    sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Declaration {
    Software {
        definition: r::SoftwareDefinition,
    },
    Script {
        artifact: Artifact,
        definition: r::ScriptDefinition,
    },
    Configuration {
        artifact: Artifact,
        schema: String,
        apply: String,
        detect: String,
        remove: Option<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    platform: Platform,
    architecture: Architecture,
    key: String,
    declaration: Declaration,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    FirewallVersion {
        version: String,
        enabled: bool,
    },
    Create {
        kind: Kind,
    },
    Version {
        version: String,
        kind: Kind,
        variants: Vec<Variant>,
    },
    Activate {
        version: String,
    },
    Deprecate {
        version: String,
    },
    Archive {
        version: String,
    },
}
fn id(s: &str) -> Result<r::Id> {
    checked_input(r::Id::new(s))
}
fn artifact(a: &Artifact) -> Result<r::Artifact> {
    checked_input(r::Artifact::new(
        id(&a.reference)?,
        a.length,
        r::Digest::from_bytes(a.sha256),
    ))
}
fn variant(v: &Variant) -> Result<r::Variant> {
    let declaration = match &v.declaration {
        Declaration::Software { definition } => r::Declaration::Software {
            definition: definition.clone(),
        },
        Declaration::Script {
            artifact: a,
            definition,
        } => r::Declaration::Script {
            artifact: artifact(a)?,
            definition: definition.clone(),
        },
        Declaration::Configuration {
            artifact: a,
            schema,
            apply,
            detect,
            remove,
        } => r::Declaration::Configuration {
            artifact: artifact(a)?,
            schema: id(schema)?,
            apply: id(apply)?,
            detect: id(detect)?,
            remove: remove.as_ref().map(|s| id(s)).transpose()?,
        },
    };
    Ok(r::Variant::new(
        match v.platform {
            Platform::Windows => r::Platform::Windows,
            Platform::Macos => r::Platform::MacOS,
        },
        match v.architecture {
            Architecture::X86_64 => r::Architecture::X86_64,
            Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        id(&v.key)?,
        declaration,
    ))
}
impl ResourceCatalog {
    pub async fn resource_change(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        op: &Operation<Change>,
        at: Timepoint,
    ) -> Result<Value> {
        let rid = id(resource)?;
        let command = match &op.input {
            Change::FirewallVersion { version, enabled } => pg::Command::Insert(
                self.author
                    .version_in(tx, resource, version, *enabled)
                    .await?,
            ),
            Change::Create { kind } => pg::Command::Create(kind.core()),
            Change::Version {
                version,
                kind,
                variants,
            } => pg::Command::Insert(checked_input(r::Version::new(
                self.tenant,
                rid.clone(),
                id(version)?,
                kind.core(),
                variants.iter().map(variant).collect::<Result<_>>()?,
            ))?),
            Change::Activate { version } => pg::Command::Activate(id(version)?),
            Change::Deprecate { version } => pg::Command::Deprecate(id(version)?),
            Change::Archive { version } => {
                checked(
                    self.resources
                        .lock_version_in(tx, &rid, &id(version)?)
                        .await?,
                )?;
                let references = self.references.count_in(tx, resource, version).await?;
                pg::Command::Archive {
                    version: id(version)?,
                    references,
                }
            }
        };
        if let pg::Command::Insert(version) = &command
            && version.kind() == r::Kind::Software
        {
            let catalog = rss_mdm_software_service::catalog::Catalog::new(
                self.runtime.clone(),
                self.tenant,
                Arc::new(crate::software_publication::host::Audit(
                    self.audit_store.clone(),
                )),
            );
            catalog.private_authoring_in(tx, version).await?;
        }
        json(&checked(
            self.resources
                .execute_in(
                    tx,
                    &pg::Request {
                        id: id(&op.operation_id.to_string())?,
                        resource: rid,
                        expected_storage_revision: op.expected_revision,
                        as_of: at,
                        command,
                    },
                )
                .await?,
        )?)
    }
    pub async fn resource_read(&self, tx: &mut PgTransaction<'_>, resource: &str) -> Result<Value> {
        let stored = checked(self.resources.get_in(tx, &id(resource)?).await?)?.ok_or(
            Error::Resource(crate::resource_catalog::error::ResourceError::Missing),
        )?;
        let snapshot = stored.resource.snapshot();
        let configurations = self.author.read_in(tx, resource).await?;
        Ok(
            json!({"id":resource,"revision":stored.storage_revision,"kind":resource_kind(snapshot.kind),"versions":snapshot.versions.iter().map(|v|json!({"id":v.version.label().as_str(),"configuration":configurations.get(v.version.label().as_str()).map(|enabled|serde_json::json!({"enabled":enabled})),"digest":v.version.digest().bytes(),"state":resource_state(v.state),"variants":v.version.variants().iter().map(variant_view).collect::<Vec<_>>()})).collect::<Vec<_>>() }),
        )
    }
}

fn artifact_view(a: &r::Artifact) -> Artifact {
    Artifact {
        reference: a.reference().as_str().into(),
        length: a.length(),
        sha256: a.digest().bytes(),
    }
}
fn variant_view(v: &r::Variant) -> Variant {
    let text = |id: &r::Id| id.as_str().to_owned();
    let declaration = match v.declaration() {
        r::Declaration::Software { definition } => Declaration::Software {
            definition: definition.clone(),
        },
        r::Declaration::Script {
            artifact,
            definition,
        } => Declaration::Script {
            artifact: artifact_view(artifact),
            definition: definition.clone(),
        },
        r::Declaration::Configuration {
            artifact,
            schema,
            apply,
            detect,
            remove,
        } => Declaration::Configuration {
            artifact: artifact_view(artifact),
            schema: text(schema),
            apply: text(apply),
            detect: text(detect),
            remove: remove.as_ref().map(text),
        },
    };
    Variant {
        platform: match v.platform() {
            r::Platform::Windows => Platform::Windows,
            r::Platform::MacOS => Platform::Macos,
        },
        architecture: match v.architecture() {
            r::Architecture::X86_64 => Architecture::X86_64,
            r::Architecture::Aarch64 => Architecture::Aarch64,
        },
        key: text(v.key()),
        declaration,
    }
}

fn resource_kind(k: r::Kind) -> &'static str {
    match k {
        r::Kind::Software => "software",
        r::Kind::Script => "script",
        r::Kind::Configuration => "configuration",
    }
}
fn resource_state(s: r::State) -> &'static str {
    match s {
        r::State::Frozen => "frozen",
        r::State::Active => "active",
        r::State::Deprecated => "deprecated",
        r::State::Archived => "archived",
    }
}

pub trait References: Send + Sync {
    fn count_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + 'a>>;
}
type CatalogFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>;
pub trait ConfigurationAuthor: Send + Sync {
    fn read_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a str,
    ) -> CatalogFuture<'a, std::collections::BTreeMap<String, bool>>;

    fn version_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
        enabled: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<r::Version>> + Send + 'a>>;
}
pub struct ResourceCatalog {
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    resources: pg::ResourceStore,
    author: Arc<dyn ConfigurationAuthor>,
    references: Arc<dyn References>,
}
#[derive(Serialize)]
#[serde(tag = "kind")]
pub enum Command {
    Resource {
        id: String,
        change: Operation<Change>,
    },
    ResourceRead {
        id: String,
    },
}
impl ResourceCatalog {
    pub(crate) fn software_resources(&self) -> &pg::ResourceStore {
        &self.resources
    }
    pub async fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        author: Arc<dyn ConfigurationAuthor>,
        references: Arc<dyn References>,
    ) -> std::result::Result<Self, Error> {
        let resources = pg::ResourceStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::ResourceAdmission))?;
        Ok(Self {
            audit_store,
            runtime,
            tenant,
            clock,
            resources,
            author,
            references,
        })
    }
    pub async fn lock_version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &r::Id,
        version: &r::Id,
    ) -> Result<(r::Version, r::State, u64)> {
        checked(
            self.resources
                .lock_version_in(tx, resource, version)
                .await?,
        )
    }
    pub async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<Value, Error> {
        authorize()?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            &(self, command, audit, authorize),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, authorize) = *ctx;
                    if let Command::Resource { id, .. } = command {
                        tx.prepare_outbox_partitions(&[s.resources.partition(id)?])
                            .await?;
                    }
                    crate::transaction::lock(tx).await?;
                    authorize()?;
                    let operation = match command {
                        Command::Resource { change, .. } => Some(change.operation_id),
                        _ => None,
                    };
                    if operation.is_some_and(|v| v.is_nil()) {
                        return Err(Error::Malformed.into());
                    }
                    use sha2::Digest;
                    let fingerprint = sha2::Sha256::digest(checked_input(serde_json::to_vec(&(
                        "resource",
                        audit.tenant(),
                        audit.snapshot().actor,
                        audit.snapshot().instance,
                        command,
                    )))?)
                    .to_vec();
                    if let Some(id) = operation
                        && let Some(old) =
                            crate::resource_catalog::receipts::replay(tx, audit, id, &fingerprint)
                                .await?
                    {
                        wire::Response::decode(old.clone())?;
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                        crate::resource_catalog::receipts::audit(
                            tx,
                            &s.audit_store,
                            audit,
                            Some((id, &fingerprint)),
                            true,
                        )
                        .await?;
                        authorize()?;
                        return Ok(old);
                    }
                    let at = checked_input(Timepoint::try_from(
                        s.clock
                            .unix_seconds()
                            .map_err(|_| Error::Unavailable(Failure::Clock))?,
                    ))?;
                    let value = match command {
                        Command::Resource { id, change } => {
                            s.resource_change(tx, id, change, at).await?
                        }
                        Command::ResourceRead { id } => s.resource_read(tx, id).await?,
                    };
                    wire::Response::decode(value.clone())?;
                    if let Some(id) = operation {
                        crate::resource_catalog::receipts::receipt(
                            tx,
                            audit,
                            id,
                            &fingerprint,
                            &value,
                        )
                        .await?;
                    }
                    crate::resource_catalog::receipts::audit(
                        tx,
                        &s.audit_store,
                        audit,
                        operation.map(|id| (id, fingerprint.as_slice())),
                        false,
                    )
                    .await?;
                    authorize()?;
                    Ok(value)
                })
            },
            crate::transaction::TransactionOwner::ResourceCatalog,
        )
        .await
    }
}

mod receipts;

pub mod error;

/// Stateless archive participant; each store projects its own references.
pub struct StoredReferences;
impl References for StoredReferences {
    fn count_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::transaction::Result<u64>> + Send + 'a>,
    > {
        Box::pin(async move {
            let assignments = crate::planning::references::count_in(tx, resource, version).await?;
            let publications =
                rss_mdm_software_service::publication::references::count_in(tx, resource, version)
                    .await?;
            let approvals =
                rss_mdm_software_service::catalog::reference_count_in(tx, resource, version)
                    .await?;
            assignments
                .checked_add(publications)
                .and_then(|n| n.checked_add(approvals))
                .ok_or_else(|| crate::Error::Unavailable(crate::Failure::FlowStorage).into())
        })
    }
}
