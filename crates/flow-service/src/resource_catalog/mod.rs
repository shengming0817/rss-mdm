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
    NativeCollection,
}
impl Kind {
    fn core(&self) -> r::Kind {
        match self {
            Self::Software => r::Kind::Software,
            Self::Script => r::Kind::Script,
            Self::Configuration => r::Kind::Configuration,
            Self::NativeCollection => r::Kind::NativeCollection,
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
    NativeCollection {
        artifact: Artifact,
        definition: r::NativeCollectionDefinition,
    },
    Configuration {
        artifact: Artifact,
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
        Declaration::NativeCollection {
            artifact: a,
            definition,
        } => r::Declaration::NativeCollection {
            artifact: artifact(a)?,
            definition: definition.clone(),
        },
        Declaration::Configuration { artifact: a } => r::Declaration::Configuration {
            artifact: artifact(a)?,
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
        if let Change::Version { variants, .. } = &op.input {
            let catalog = crate::assets::catalog_in(tx, self.tenant, i64::MAX).await?;
            for variant in variants {
                let binding = match &variant.declaration {
                    Declaration::Script { definition, .. } => match &definition.spec().purpose {
                        r::ScriptPurpose::Collection { mappings } => Some((
                            if definition.spec().profile == r::ScriptProfile::Osquery {
                                rss_mdm_inventory::Source::AgentOsquery
                            } else {
                                rss_mdm_inventory::Source::AgentScript
                            },
                            mappings.keys().collect::<Vec<_>>(),
                        )),
                        _ => None,
                    },
                    Declaration::NativeCollection { definition, .. } => Some((
                        match definition.spec().adapter {
                            r::NativeAdapter::WindowsCsp => rss_mdm_inventory::Source::MdmWindows,
                            _ => rss_mdm_inventory::Source::MdmApple,
                        },
                        definition.spec().mappings.keys().collect(),
                    )),
                    _ => None,
                };
                if let Some((source, keys)) = binding {
                    let platform = match variant.platform {
                        Platform::Windows => rss_mdm_inventory::Platform::Windows,
                        Platform::Macos => rss_mdm_inventory::Platform::Macos,
                    };
                    for key in keys {
                        let field =
                            checked_input(catalog.definition(checked_input(
                                rss_mdm_inventory::FieldKey::parse(key),
                            )?))?;
                        if !field.sources.contains_key(&source)
                            || !field.platforms.contains(&platform)
                        {
                            return Err(Error::Malformed.into());
                        }
                        if let Declaration::NativeCollection { definition, .. } =
                            &variant.declaration
                        {
                            let mapping = &definition.spec().mappings[key];
                            if !mapping.columns.is_empty() {
                                let rss_mdm_inventory::ValueType::Array { items, .. } =
                                    &field.value_type
                                else {
                                    return Err(Error::Malformed.into());
                                };
                                let rss_mdm_inventory::ValueType::Object { properties } =
                                    items.as_ref()
                                else {
                                    return Err(Error::Malformed.into());
                                };
                                if mapping.columns.keys().ne(properties.keys()) {
                                    return Err(Error::Malformed.into());
                                }
                            }
                        }
                    }
                }
            }
        }
        let command = match &op.input {
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
            let catalog = rss_mdm_software_service::catalog::Reader::new(self.tenant);
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
        Ok(
            json!({"id":resource,"revision":stored.storage_revision,"kind":resource_kind(snapshot.kind),"versions":snapshot.versions.iter().map(|v|json!({"id":v.version.label().as_str(),"digest":v.version.digest().bytes(),"state":resource_state(v.state),"variants":v.version.variants().iter().map(variant_view).collect::<Vec<_>>()})).collect::<Vec<_>>() }),
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
        r::Declaration::NativeCollection {
            artifact,
            definition,
        } => Declaration::NativeCollection {
            artifact: artifact_view(artifact),
            definition: definition.clone(),
        },
        r::Declaration::Configuration { artifact } => Declaration::Configuration {
            artifact: artifact_view(artifact),
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
        r::Kind::NativeCollection => "native_collection",
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
pub struct ResourceCatalog {
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    resources: pg::ResourceStore,
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
    pub async fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
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
                    admit_in(tx).await?;
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

/// Locked resource version access for Policy preparation; owns no management service.
pub struct VersionReader {
    tenant: TenantId,
}
impl VersionReader {
    pub fn new(tenant: TenantId) -> Self {
        Self { tenant }
    }
    pub async fn active_version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        version: &str,
    ) -> Result<r::Version> {
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        let (version, state) = checked(
            rss_mdm_resource_postgres::lock_reference_in(
                tx,
                &checked_input(r::Id::new(resource))?,
                &checked_input(r::Id::new(version))?,
            )
            .await?,
        )?;
        if state != r::State::Active {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
}

pub const CATALOG_SQL: &str = include_str!("catalog.sql");

pub const CATALOG_JSON: &str = include_str!("catalog.json");

pub const ADMISSION_SQL: &str = include_str!("admission.sql");

async fn admit_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    crate::storage::verify_contract(
        tx,
        CATALOG_SQL,
        CATALOG_JSON,
        ADMISSION_SQL,
        Failure::ResourceAdmission,
    )
    .await
}
