//! Resource directory use cases; metadata remains owned by ResourceStore.
pub use crate::operation::Operation;
use crate::transaction::*;

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
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Software,
    Script,
    Configuration,
    NativeCollection,
    AgentCollection,
    TelemetryProfile,
}
impl Kind {
    fn core(&self) -> r::Kind {
        match self {
            Self::Software => r::Kind::Software,
            Self::Script => r::Kind::Script,
            Self::Configuration => r::Kind::Configuration,
            Self::NativeCollection => r::Kind::NativeCollection,
            Self::AgentCollection => r::Kind::AgentCollection,
            Self::TelemetryProfile => r::Kind::TelemetryProfile,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Windows,
    Macos,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Artifact {
    reference: String,
    length: u64,
    sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
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
    AgentCollection {
        artifact: Artifact,
        definition: r::AgentCollectionDefinition,
    },
    TelemetryProfile {
        artifact: Artifact,
        definition: r::TelemetryProfile,
    },
    NativeCollection {
        artifact: Artifact,
        definition: r::NativeCollectionDefinition,
    },
    Configuration {
        artifact: Artifact,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    platform: Platform,
    architecture: Architecture,
    key: String,
    declaration: Declaration,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
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
    Present {
        #[schemars(extend("x-rss-extension" = "Bounded descriptive presentation metadata; no execution or authorization authority"))]
        presentation: serde_json::Map<String, Value>,
    },
    Instantiate {
        blueprint: String,
        version: String,
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
        Declaration::TelemetryProfile {
            artifact: a,
            definition,
        } => r::Declaration::TelemetryProfile {
            artifact: artifact(a)?,
            definition: definition.clone(),
        },
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
        Declaration::AgentCollection {
            artifact: a,
            definition,
        } => r::Declaration::AgentCollection {
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
    async fn resource_change(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        op: &Operation<Change>,
        at: Timepoint,
    ) -> Result<Value> {
        checked(self.resources.validate_transaction(tx)?)?;
        let rid = id(resource)?;
        if let Change::Instantiate { blueprint, version } = &op.input {
            if op.expected_revision != 0 {
                return Err(Error::Conflict.into());
            }
            let blueprint = r::blueprints::get(blueprint, version).ok_or(Error::Malformed)?;
            let initial = checked_input(blueprint.instantiate(self.tenant, rid.clone()))?;
            use sha2::Digest;
            let origin = r::BlueprintOrigin {
                blueprint: blueprint.id.clone(),
                version: blueprint.version.clone(),
                digest: initial.digest().bytes(),
            };
            let operation_id = |step: &str| {
                let digest = sha2::Sha256::digest(format!("{}:{step}", op.operation_id).as_bytes());
                uuid::Uuid::from_bytes(digest[..16].try_into().expect("digest"))
            };
            checked(
                self.resources
                    .execute_in(
                        tx,
                        &pg::Request {
                            id: id(&operation_id("create").to_string())?,
                            resource: rid.clone(),
                            expected_storage_revision: 0,
                            as_of: at,
                            command: pg::Command::CreateFromBlueprint {
                                kind: initial.kind(),
                                origin,
                                presentation: blueprint.presentation.clone(),
                            },
                        },
                    )
                    .await?,
            )?;
            Box::pin(self.resource_change(
                tx,
                resource,
                &Operation {
                    operation_id: operation_id("version"),
                    expected_revision: 1,
                    input: Change::Version {
                        version: blueprint.label(),
                        kind: match initial.kind() {
                            r::Kind::Configuration => Kind::Configuration,
                            r::Kind::NativeCollection => Kind::NativeCollection,
                            r::Kind::AgentCollection => Kind::AgentCollection,
                            _ => return Err(Error::Malformed.into()),
                        },
                        variants: initial.variants().iter().map(variant_view).collect(),
                    },
                },
                at,
            ))
            .await?;
            return self.resource_read(tx, resource).await;
        }
        let command = match &op.input {
            Change::Instantiate { .. } => unreachable!("handled above"),
            Change::Create { kind } => pg::Command::Create(kind.core()),
            Change::Present { presentation } => pg::Command::Present(presentation.clone()),
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
        if let pg::Command::Insert(version) = &command {
            self.collections.validate_in(tx, version).await?;
            for variant in version.variants() {
                if let r::Declaration::TelemetryProfile { definition, .. } = variant.declaration() {
                    let reference = &definition.spec().template;
                    let (template, state, _) = checked(
                        self.resources
                            .lock_version_in(
                                tx,
                                &id(&reference.resource)?,
                                &id(&reference.version)?,
                            )
                            .await?,
                    )?;
                    if state == r::State::Archived {
                        return Err(Error::Conflict.into());
                    }
                    self.telemetry
                        .validate_in(tx, &template, definition)
                        .await?;
                }
            }
            if version.kind() == r::Kind::Software {
                self.software.validate_in(tx, version).await?;
            }
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
    async fn resource_read(&self, tx: &mut PgTransaction<'_>, resource: &str) -> Result<Value> {
        let stored = checked(self.resources.get_in(tx, &id(resource)?).await?)?
            .ok_or(Error::Resource(crate::error::ResourceError::Missing))?;
        let snapshot = stored.resource.snapshot();
        let origin = &snapshot.origin;
        Ok(
            json!({"id":resource,"origin":origin,"presentation":snapshot.presentation,"revision":stored.storage_revision,"kind":resource_kind(snapshot.kind),"versions":snapshot.versions.iter().map(|v|json!({"id":v.version.label().as_str(),"digest":v.version.digest().bytes(),"state":resource_state(v.state),"variants":v.version.variants().iter().map(variant_view).collect::<Vec<_>>()})).collect::<Vec<_>>() }),
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
        r::Declaration::TelemetryProfile {
            artifact,
            definition,
        } => Declaration::TelemetryProfile {
            artifact: artifact_view(artifact),
            definition: definition.clone(),
        },
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
        r::Declaration::AgentCollection {
            artifact,
            definition,
        } => Declaration::AgentCollection {
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
        r::Kind::AgentCollection => "agent_collection",
        r::Kind::TelemetryProfile => "telemetry_profile",
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

pub struct ResourceCatalog {
    directory_cursor: rss_mdm_query::cursor::CursorCodec,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    resources: pg::ResourceStore,
    references: Arc<dyn UsageReader<Error = Fault>>,
    collections: Arc<dyn inputs::CollectionValidator>,
    telemetry: Arc<dyn inputs::TelemetryProfileValidator>,
    software: Arc<dyn inputs::SoftwareAuthoringValidator>,
}
#[derive(Serialize, schemars::JsonSchema)]
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
    pub async fn new(deps: Dependencies) -> std::result::Result<Self, Error> {
        let Dependencies {
            audit_store,
            runtime,
            tenant,
            clock,
            references,
            cursor_key: key,
            collections,
            telemetry,
            software,
        } = deps;
        let directory_cursor = rss_mdm_query::cursor::CursorCodec::new(&key)
            .map_err(|_| Error::Unavailable(Failure::ResourceAdmission))?;
        let resources = pg::ResourceStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::ResourceAdmission))?;
        Ok(Self {
            directory_cursor,
            audit_store,
            runtime,
            tenant,
            clock,
            resources,
            references,
            collections,
            telemetry,
            software,
        })
    }
    /// Execute against current authority locked in the same transaction as the effect.
    pub async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &crate::authorization::context::AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        let (Command::Resource { id, .. } | Command::ResourceRead { id }) = command;
        audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, id);
        let permission = match command {
            Command::Resource { .. } => authorization::Permission::ResourceWrite,
            Command::ResourceRead { .. } => authorization::Permission::ResourceRead,
        };
        proof.bind_audit(audit)?;
        proof.require_initialization_target(id)?;
        proof.manage(permission)?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, command, audit, proof, permission),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, proof, permission) = *ctx;
                    if proof.initialization_authority().is_some() {
                        let (Command::Resource { id, .. } | Command::ResourceRead { id }) = command;
                        crate::authorization::baseline::check_in(tx, proof, permission, id).await?;
                    }
                    admit_in(tx).await?;
                    s.collections.fence_in(tx).await?;
                    let current = transaction::current(tx, proof).await?;
                    current.require(proof, permission, None)?;
                    let partitions = match command {
                        Command::Resource { id, .. } => {
                            vec![s.resources.partition(id).map_err(|_| Error::Malformed)?]
                        }
                        _ => vec![],
                    };
                    s.audit_store.prepare_in(tx, audit, &partitions).await?;
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
                        && let Some(old) = checked(
                            pg::replay_operation_in(
                                tx,
                                &audit.snapshot().actor.ok_or(Error::Malformed)?,
                                &id.to_string(),
                                &fingerprint,
                            )
                            .await?,
                        )?
                    {
                        wire::Response::decode(old.clone())?;
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                        crate::receipts::audit(tx, &s.audit_store, audit, Some(id), true).await?;
                        proof.check_live()?;
                        return Ok(old);
                    }
                    let at = checked_input(Timepoint::try_from(
                        s.clock
                            .unix_seconds()
                            .ok_or(Error::Unavailable(Failure::Clock))?,
                    ))?;
                    let value = match command {
                        Command::Resource { id, change } => {
                            s.resource_change(tx, id, change, at).await?
                        }
                        Command::ResourceRead { id } => s.resource_read(tx, id).await?,
                    };
                    wire::Response::decode(value.clone())?;
                    if let Some(id) = operation {
                        pg::record_operation_in(
                            tx,
                            &audit.snapshot().actor.ok_or(Error::Malformed)?,
                            &id.to_string(),
                            &fingerprint,
                            &value,
                        )
                        .await?;
                    }
                    crate::receipts::audit(tx, &s.audit_store, audit, operation, false).await?;
                    proof.check_live()?;
                    Ok(value)
                })
            },
        )
        .await
    }
}

mod receipts;

pub mod error;
pub use error::{Error, Failure};
pub mod inputs;
pub mod transaction;
pub use inputs::UsageReader;
pub mod clock;
mod error_projection;
mod operation;
use rss_mdm_authorization_service as authorization;

pub const ADMISSION_SQL: &str = pg::APPLICATION_ADMISSION_SQL;
async fn admit_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    pg::admit_application_in(tx).await?;
    Ok(())
}
/// Explicit dependencies, constructed by the host without a Flow container.
pub struct Dependencies {
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub clock: Arc<dyn clock::Clock>,
    pub cursor_key: Vec<u8>,
    pub references: Arc<dyn UsageReader<Error = Fault>>,
    pub collections: Arc<dyn inputs::CollectionValidator>,
    pub telemetry: Arc<dyn inputs::TelemetryProfileValidator>,
    pub software: Arc<dyn inputs::SoftwareAuthoringValidator>,
}

pub mod software;
