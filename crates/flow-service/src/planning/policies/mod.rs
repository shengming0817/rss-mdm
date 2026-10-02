//! Authored Policy is the durable authority; execution progress never edits it.
use super::action_contract::{
    Architecture, ExecutionInput, FrozenAction, FrozenNativeCollection, FrozenSoftwareAction,
    Platform, freeze_collection, freeze_script_in,
};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_policy::{Action, Definition, Exit, Frequency, ResourceBinding, SoftwareIntent};
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub mod admission;
pub mod agent_install;
pub mod enrollment;
pub mod onboarding;
pub mod preview;
pub mod reconcile;
pub mod rerun;
pub mod software;
pub mod storage;

pub use rss_mdm_policy::{Change, Policy};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
    NativeCollection {
        action: Box<FrozenNativeCollection>,
        frequency: Frequency,
    },
    Execution {
        action: Box<FrozenAction>,
        frequency: Frequency,
    },
    Configuration {
        #[serde(rename = "native_sealed")]
        native: super::configuration::Protected,
        grants: std::collections::BTreeMap<String, Vec<crate::authorization::UserGrant>>,
        platform: Platform,
        exit: Exit,
        resource_digest: [u8; 32],
    },
    Software {
        action: Box<FrozenSoftwareAction>,
    },
    AgentInstall {
        action: Box<agent_install::FrozenInstall>,
    },
    MdmEnrollment {
        action: Box<enrollment::FrozenEnrollment>,
    },
}
pub struct Policies {
    pub planning: std::sync::Arc<super::Planning>,
    pub execution: std::sync::Arc<crate::execution::ExecutionService>,
}
impl Policies {
    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::operation::Operation<Change>,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if id.is_nil() || op.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::PolicyWrite)?;
        // Verify content outside the database transaction, then bind that proof again at publication.
        let artifact = if let Change::Put { definition, .. } = &op.input {
            if definition.action.resource().is_some() {
                proof.manage(Permission::ResourceRead)?;
            }
            definition.validate()?;
            authorize(proof, definition)?;
            if matches!(definition.action, Action::Execution { .. }) {
                None
            } else {
                inspect(
                    &self.planning.runtime,
                    self.planning.tenant,
                    (self, definition),
                    |ctx, tx| {
                        Box::pin(async move {
                            let (s, d) = *ctx;
                            let Some(binding) = d.action.resource() else {
                                return Ok(None);
                            };
                            let version = s
                                .planning
                                .catalog
                                .active_version_in(tx, binding.id(), binding.version())
                                .await?;
                            if matches!(
                                d.action,
                                Action::Software { .. } | Action::EnsureAgentInstalled { .. }
                            ) {
                                if binding.software().is_none()
                                    || version.kind() != resource::Kind::Software
                                {
                                    return Err(Error::Malformed.into());
                                }
                                Ok(None)
                            } else {
                                let variant = variant(&version, binding)?;
                                Ok(match variant.declaration() {
                                    resource::Declaration::Configuration { artifact } => Some((
                                        artifact.clone(),
                                        rss_mdm_content_service::StorageClass::NativeConfiguration,
                                    )),
                                    resource::Declaration::Script { artifact, .. }
                                    | resource::Declaration::NativeCollection {
                                        artifact, ..
                                    } => Some((
                                        artifact.clone(),
                                        rss_mdm_content_service::StorageClass::Artifact,
                                    )),
                                    _ => None,
                                })
                            }
                        })
                    },
                    TransactionOwner::Planning,
                )
                .await?
            }
        } else {
            None
        };
        let verified = if let Change::Put { definition, .. } = &op.input
            && let Action::Execution {
                resource,
                parameters,
                ..
            } = &definition.action
        {
            Some(
                self.planning
                    .catalog
                    .verify_script(resource, parameters, self.execution.content.as_ref())
                    .await?,
            )
        } else if let Some((artifact, class)) = &artifact {
            Some(
                self.execution
                    .content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .verify_class(artifact, *class)
                    .await?,
            )
        } else {
            None
        };
        run(
            &self.planning.audit_store,
            &self.planning.runtime,
            self.planning.tenant,
            audit,
            (self, proof, id, op, audit, verified.as_ref()),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, id, op, audit, verified) = *ctx;
                    let authorization = crate::action_admission::current(tx, p).await?;
                    authorization.require(p, Permission::PolicyWrite, None)?;
                    if matches!(&op.input, Change::Put { definition, .. } if definition.action.resource().is_some()) {
                        authorization.require(p, Permission::ResourceRead, None)?;
                    }
                    crate::transaction::lock(tx).await?;
                    storage::lock(tx, id).await?;
                    let hash = fingerprint(&(id, &op.input, op.expected_revision, p.user()))?;
                    if let Some(value) = checked(
                        s.planning
                            .policy_store
                            .replay_in(tx, op.operation_id, &hash)
                            .await?,
                    )? {
                        return Ok(value);
                    }
                    let old = storage::read_in(s.planning.policy_store.reader(), tx, id).await?;
                    if let Some(previous) = &old {
                        authorize_snapshot(&authorization, p, &previous.definition)?;
                    }
                    let now = crate::action_admission::now(tx).await?;
                    let changed_policy = Policy::apply(
                        id,
                        old.as_ref(),
                        op.expected_revision,
                        &op.input,
                        Uuid::new_v4(),
                    )?;
                    let semantic = changed_policy.semantic.to_vec();
                    let changed = changed_policy.semantic_changed;
                    let policy = changed_policy.policy;
                    authorize_snapshot(&authorization, p, &policy.definition)?;
                    if changed {
                        let mut frozen = if matches!(policy.definition.action, Action::EnsureAgentInstalled { .. }) {
                            Frozen::AgentInstall { action: Box::new(s.freeze_agent_in(tx,p,&authorization,&policy.definition.action).await?) }
                        } else if matches!(policy.definition.action, Action::RequestMdmEnrollment { .. }) {
                            if s.execution.signer.is_none() { return Err(Error::Unsupported.into()); }
                            Frozen::MdmEnrollment { action: Box::new(enrollment::freeze(p, &authorization, &policy.definition.action, &s.execution.enrollment_entries)?) }
                        } else { s
                            .freeze_in(
                                tx,
                                &policy.definition.action,
                                verified,
                                Some(super::configuration::Owner::Policy { policy: policy.id, version: policy.version }),
                            )
                            .await? };
                        frozen.authorize_native(p,&authorization,None,&s.execution.protection,tx.tenant_id(),Some(super::configuration::Owner::Policy { policy: policy.id, version: policy.version }))?;
                        storage::write_in(
                            &s.planning.policy_store,
                            tx,
                            &policy,
                            Some((&frozen, &semantic)),
                            p,
                            now,
                        )
                        .await?;
                    } else {
                        storage::write_in(&s.planning.policy_store, tx, &policy, None, p, now)
                            .await?;
                    }
                    // Publication performs no Agent fanout. Native reconciliation is a bounded background job.
                    storage::enqueue_change_in(tx, &policy, old.as_ref()).await?;
                    let value = storage::view(&policy)?;
                    checked(
                        s.planning
                            .policy_store
                            .receipt_in(tx, op.operation_id, &hash, &value)
                            .await?,
                    )?;
                    let fact = Fact::business(
                        audit,
                        &format!("policy:{id}:{}", op.operation_id),
                        &hash,
                        200,
                        "success",
                        None,
                    )?;
                    s.planning.audit_store.append_in(tx, &fact, false).await?;
                    p.check_live()?;
                    Ok(value)
                })
            },
            TransactionOwner::Planning,
        )
        .await
    }
    pub async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &Action,
        verified: Option<&rss_mdm_content_service::Verified>,
        owner: Option<super::configuration::Owner>,
    ) -> Result<Frozen> {
        let binding = action.resource().ok_or(Error::Unsupported)?;
        let version = self
            .planning
            .catalog
            .active_version_in(tx, binding.id(), binding.version())
            .await?;
        if let (
            ResourceBinding::Software(selection),
            Action::Software {
                delivery,
                intent,
                admission_operation,
                schedule,
                run_lifetime_seconds,
                ..
            },
        ) = (binding, action)
        {
            if version.kind() != resource::Kind::Software {
                return Err(Error::Malformed.into());
            }
            let catalog = rss_mdm_software_service::catalog::Catalog::new(
                self.planning.runtime.clone(),
                self.planning.tenant,
                std::sync::Arc::new(crate::software_publication::host::Audit(
                    self.planning.audit_store.clone(),
                )),
            );
            let mut approval = None;
            for (target, key) in &selection.variants {
                let (platform, architecture) = target.parts();
                let selected = catalog
                    .resolve_admitted_in(
                        tx,
                        binding.id(),
                        binding.version(),
                        match platform {
                            Platform::Windows => resource::Platform::Windows,
                            Platform::Macos => resource::Platform::MacOS,
                        },
                        match architecture {
                            Architecture::X86_64 => resource::Architecture::X86_64,
                            Architecture::Aarch64 => resource::Architecture::Aarch64,
                        },
                        &checked_input(resource::Id::new(key))?,
                    )
                    .await?;
                if selected.version().digest() != version.digest() {
                    return Err(Error::Conflict.into());
                }
                if let Some(previous) = approval
                    && previous != selected.admission().operation
                {
                    return Err(Error::Conflict.into());
                }
                approval = Some(selected.admission().operation);
                let variant = version
                    .resolve(
                        match platform {
                            Platform::Windows => resource::Platform::Windows,
                            Platform::Macos => resource::Platform::MacOS,
                        },
                        match architecture {
                            Architecture::X86_64 => resource::Architecture::X86_64,
                            Architecture::Aarch64 => resource::Architecture::Aarch64,
                        },
                        &checked_input(resource::Id::new(key))?,
                    )
                    .map_err(|_| Error::Malformed)?;
                let resource::Declaration::Software { definition } = variant.declaration() else {
                    return Err(Error::Malformed.into());
                };
                if matches!(intent, SoftwareIntent::ExplicitUninstall)
                    && !definition.spec().behavior.supports_removal()
                {
                    return Err(Error::Unsupported.into());
                }
            }
            if approval != Some(*admission_operation) {
                return Err(Error::Conflict.into());
            }
            let action_definition = action;
            let action = FrozenSoftwareAction {
                delivery: delivery.clone(),
                resource_digest: version.digest().bytes(),
                resource: binding.id().to_owned(),
                version: binding.version().to_owned(),
                variants: selection.variants.clone(),
                admission_operation: *admission_operation,
                intent: *intent,
                schedule: schedule.clone(),
                run_lifetime_seconds: *run_lifetime_seconds,
            };
            let draft = software::SoftwareExecutionPolicy::draft(
                Definition {
                    scope: Uuid::nil(),
                    action: action_definition.clone(),
                },
                action.clone(),
            );
            for target in selection.variants.keys() {
                let (platform, architecture) = target.parts();
                let steps = draft
                    .execution_steps_in(&self.execution, tx, platform, architecture)
                    .await?
                    .ok_or(Error::Forbidden)?;
                let mut artifact_count = 0usize;
                let mut definition_bytes = 0usize;
                for selected in &steps {
                    let variant = selected
                        .version()
                        .resolve(
                            selected.platform(),
                            selected.architecture(),
                            selected.variant(),
                        )
                        .map_err(|_| Error::Malformed)?;
                    let resource::Declaration::Software { definition } = variant.declaration()
                    else {
                        return Err(Error::Malformed.into());
                    };
                    artifact_count = artifact_count
                        .checked_add(definition.spec().artifacts.len())
                        .ok_or(Error::Malformed)?;
                    definition_bytes = definition_bytes
                        .checked_add(checked_input(serde_json::to_vec(definition.spec()))?.len())
                        .ok_or(Error::Malformed)?;
                }
                if artifact_count > 64 || definition_bytes > 4_000_000 {
                    return Err(Error::Unsupported.into());
                }
            }
            return Ok(Frozen::Software {
                action: Box::new(action),
            });
        }
        if let Action::Execution {
            parameters,
            schedule,
            frequency,
            run_lifetime_seconds,
            ..
        } = action
        {
            if self.execution.signer.is_none() {
                return Err(Error::Conflict.into());
            }
            let prepared = crate::resource_catalog::scripts::prepare(
                &version,
                binding,
                parameters,
                verified.ok_or(Error::Conflict)?,
            )?;
            return Ok(Frozen::Execution {
                action: Box::new(
                    freeze_script_in(
                        tx,
                        self.planning.tenant,
                        &prepared,
                        schedule.clone(),
                        *run_lifetime_seconds,
                    )
                    .await?,
                ),
                frequency: *frequency,
            });
        }
        let v = variant(&version, binding)?;
        let exact = binding.exact().ok_or(Error::Malformed)?;
        match (action, v.declaration()) {
            (
                Action::NativeCollection {
                    schedule,
                    frequency,
                    run_lifetime_seconds,
                    ..
                },
                resource::Declaration::NativeCollection {
                    artifact,
                    definition,
                },
            ) => {
                if !verified.is_some_and(|v| v.matches(artifact)) {
                    return Err(Error::Conflict.into());
                }
                let source = match definition.spec().adapter {
                    resource::NativeAdapter::WindowsCsp => rss_mdm_inventory::Source::MdmWindows,
                    _ => rss_mdm_inventory::Source::MdmApple,
                };
                let collection = freeze_collection(
                    tx,
                    self.planning.tenant,
                    &version,
                    v,
                    source,
                    definition.spec().mappings.keys(),
                )
                .await?;
                Ok(Frozen::NativeCollection {
                    frequency: *frequency,
                    action: Box::new(FrozenNativeCollection {
                        input: ExecutionInput {
                            platform: exact.platform,
                            architecture: exact.architecture,
                            parameters: json!({}),
                            schedule: schedule.clone(),
                            run_lifetime_seconds: *run_lifetime_seconds,
                        },
                        definition: definition.clone(),
                        windows_queries: if definition.spec().adapter
                            == resource::NativeAdapter::WindowsCsp
                        {
                            definition
                                .spec()
                                .mappings
                                .values()
                                .map(|mapping| {
                                    rss_mdm_windows_mdm::native::Request::from_uri(
                                        &mapping.query,
                                        rss_mdm_windows_mdm::native::Verb::Get,
                                        None,
                                        rss_mdm_windows_mdm::native::Scope::Device,
                                    )
                                    .map_err(|_| Error::Unsupported)
                                })
                                .collect::<std::result::Result<_, _>>()?
                        } else {
                            Vec::new()
                        },
                        grants: Default::default(),
                        collection,
                        resource_digest: version.digest().bytes(),
                    }),
                })
            }
            (
                Action::Configuration { exit, .. },
                resource::Declaration::Configuration { artifact },
            ) => {
                let verified = verified
                    .filter(|v| v.matches(artifact))
                    .ok_or(Error::Conflict)?;
                let native = super::configuration::Configuration::read(verified)?;
                if matches!(exit, Exit::Remove) && native.remove.is_none() {
                    return Err(Error::Unsupported.into());
                }
                let expected = match exact.platform {
                    Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
                    Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
                };
                if native.apply.source() != expected {
                    return Err(Error::Malformed.into());
                }
                Ok(Frozen::Configuration {
                    native: super::configuration::Protected::seal(
                        &self.execution.protection,
                        tx.tenant_id(),
                        owner.ok_or(Error::Malformed)?,
                        &native,
                    )?,
                    grants: std::collections::BTreeMap::new(),
                    platform: exact.platform,
                    exit: *exit,
                    resource_digest: version.digest().bytes(),
                })
            }
            _ => Err(Error::Malformed.into()),
        }
    }
}
pub fn authorize_snapshot(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> std::result::Result<(), Error> {
    let permission = match definition.action {
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,
        Action::Software { .. } | Action::EnsureAgentInstalled { .. } => Permission::SoftwareDeploy,
        Action::RequestMdmEnrollment { .. } => Permission::Enrollment,
    };
    if matches!(definition.action, Action::EnsureAgentInstalled { .. }) {
        snapshot.require_all_devices(proof, Permission::Enrollment)?;
    }
    snapshot.require(proof, Permission::ScopeRead, None)?;
    snapshot.require_all_devices(proof, permission)?;
    Ok(())
}
pub fn authorize(
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> std::result::Result<(), Error> {
    let permission = match definition.action {
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,
        Action::Software { .. } | Action::EnsureAgentInstalled { .. } => Permission::SoftwareDeploy,
        Action::RequestMdmEnrollment { .. } => Permission::Enrollment,
    };
    if matches!(definition.action, Action::EnsureAgentInstalled { .. }) {
        proof.require_all_devices(Permission::Enrollment)?;
    }
    proof.manage(Permission::ScopeRead)?;
    proof.require_all_devices(permission).map_err(Error::from)
}

pub fn variant<'a>(
    version: &'a resource::Version,
    binding: &rss_mdm_policy::ResourceBinding,
) -> Result<&'a resource::Variant> {
    let exact = binding.exact().ok_or(Error::Malformed)?;
    checked_input(version.resolve(
        match exact.platform {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        match exact.architecture {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
        &checked_input(resource::Id::new(&exact.variant))?,
    ))
}

pub mod read;

impl Frozen {
    pub fn authorize_native(
        &mut self,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
        devices: Option<&std::collections::BTreeSet<String>>,
        key: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        owner: Option<super::configuration::Owner>,
    ) -> std::result::Result<(), Error> {
        let (mut permissions, grants) = match self {
            Self::Configuration { native, grants, .. } => {
                let native = native.open(key, tenant, owner.ok_or(Error::Malformed)?)?;
                let mut permissions = native.apply.permissions()?;
                if let Some(remove) = &native.remove {
                    permissions.extend(remove.permissions()?);
                }
                (permissions, grants)
            }
            Self::NativeCollection { action, .. } => (action.permissions()?, &mut action.grants),
            _ => return Ok(()),
        };
        permissions.sort();
        permissions.dedup();
        if let Some(devices) = devices {
            for device in devices {
                grants.insert(
                    device.clone(),
                    permissions
                        .iter()
                        .map(|&permission| {
                            crate::authorization::UserGrant::from_proof(
                                snapshot, proof, device, permission,
                            )
                        })
                        .collect::<std::result::Result<_, _>>()?,
                );
            }
        } else {
            grants.insert(
                "*".into(),
                permissions
                    .iter()
                    .map(|&permission| {
                        crate::authorization::UserGrant::all_devices(snapshot, proof, permission)
                    })
                    .collect::<std::result::Result<_, _>>()?,
            );
        }
        Ok(())
    }
}
