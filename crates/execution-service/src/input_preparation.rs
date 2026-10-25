//! Execution-owned resource preparation inside the caller's original transaction.
mod native;
pub(crate) mod preview;
mod publication;
mod request;
mod software;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::{Error, Inputs, action_contract::*, freeze_inputs::*, frozen::Frozen, transaction::*};
pub(crate) use native::windows_collection_plan;
use native::{configuration, native_collection};
pub use request::{PublicationAuthority, PublicationInput, ResourcePreparation, ScriptParameters};
use rss_mdm_content_service::{StorageClass, Verified};
use rss_mdm_policy::{Action, Architecture, ExactResourceBinding, Exit, Platform, SoftwareIntent};
use rss_mdm_resource::{self as resource, self as r, SelectedScript};
use rss_transactional_messaging_postgres::PgTransaction;

impl Inputs {
    /// Validate the closed resource family and verify its content outside a write transaction.
    pub async fn prepare_resource(
        &self,
        input: Option<ResourcePreparation<'_>>,
    ) -> std::result::Result<Option<Verified>, Error> {
        let Some(input) = input else {
            return Ok(None);
        };
        if matches!(input, ResourcePreparation::Script { .. }) && !self.signing_enabled {
            return Err(Error::Conflict);
        }
        let artifact = inspect(&self.runtime, self.tenant, (self, input), |ctx, tx| {
            Box::pin(async move {
                let (service, input) = *ctx;
                let binding = input.identity();
                let version = service
                    .active_version_in(tx, binding.id(), binding.version())
                    .await?;
                resource_artifact(&version, input)
            })
        })
        .await?;
        match artifact {
            Some((artifact, class)) => Ok(Some(self.verify_artifact(&artifact, class).await?)),
            None => Ok(None),
        }
    }
    /// Freeze and authorize immutable execution material, without committing or creating assignments.
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        verified: Option<&Verified>,
        authority: &PublicationAuthority<'_>,
    ) -> Result<Frozen> {
        let mut frozen = match input {
            PublicationInput::DeviceAccess {
                mac,
                windows,
                self_enrollment,
                role,
            } => {
                if !self.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                let frozen = Frozen::DeviceAccess {
                    configuration: rss_mdm_agent_wire::runtime::AccessConfiguration {
                        mac: (*mac).clone(),
                        windows: (*windows).clone(),
                        self_enrollment: *self_enrollment,
                        enabled: true,
                        role: role.map(|r| match r {
                            rss_mdm_policy::AccessRole::Standard => {
                                rss_mdm_agent_wire::runtime::AccessRole::Standard
                            }
                            rss_mdm_policy::AccessRole::Administrator => {
                                rss_mdm_agent_wire::runtime::AccessRole::Administrator
                            }
                        }),
                    },
                    grant: crate::authorization::OperationAuthority::all_devices(
                        authority.snapshot,
                        authority.proof,
                        Permission::AccountWrite,
                    )?,
                };
                if let Frozen::DeviceAccess { configuration, .. } = &frozen {
                    configuration.validate().map_err(|_| Error::Malformed)?;
                }
                frozen
            }
            PublicationInput::Unmanage { schedule, lifetime } => Frozen::UnmanageDevice {
                schedule: (*schedule).clone(),
                run_lifetime_seconds: *lifetime,
                grant: crate::authorization::OperationAuthority::all_devices(
                    authority.snapshot,
                    authority.proof,
                    Permission::DeviceUnmanage,
                )?,
            },
            PublicationInput::Credential {
                operation,
                architecture,
                schedule,
                frequency,
                lifetime,
            } => {
                if !self.recovery_enabled || !self.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                Frozen::Credential {
                    frequency: *frequency,
                    action: Box::new(crate::credential_tasks::FrozenCredential {
                        operation: (*operation).clone(),
                        input: ExecutionInput {
                            platform: Platform::Windows,
                            architecture: *architecture,
                            schedule: (*schedule).clone(),
                            run_lifetime_seconds: *lifetime,
                        },
                        grants: Default::default(),
                    }),
                }
            }
            PublicationInput::AgentInstall {
                binding,
                schedule,
                lifetime,
            } => Frozen::AgentInstall {
                action: Box::new(
                    self.freeze_agent_in(
                        tx,
                        authority.proof,
                        authority.snapshot,
                        binding,
                        schedule,
                        *lifetime,
                    )
                    .await?,
                ),
            },
            PublicationInput::Enrollment {
                organization,
                schedule,
                lifetime,
            } => Frozen::MdmEnrollment {
                action: Box::new(self.prepare_enrollment(
                    authority.proof,
                    authority.snapshot,
                    *organization,
                    schedule,
                    *lifetime,
                )?),
            },
            _ => {
                self.freeze_resource_in(tx, input, verified, authority.owner)
                    .await?
            }
        };
        frozen.authorize_native(
            authority.proof,
            authority.snapshot,
            authority.devices,
            &self.protection,
            tx.tenant_id(),
            authority.owner,
        )?;
        Ok(frozen)
    }
    pub(crate) async fn active_version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        version: &str,
    ) -> Result<r::Version> {
        if tx.tenant_id() != self.tenant {
            return Err(Error::Conflict.into());
        }
        let (version, state) = checked(
            rss_mdm_resource_postgres::lock_reference_in(
                tx,
                &checked_input(r::Id::new(resource))?,
                &checked_input(r::Id::new(version))?,
            )
            .await?,
        )?;
        if (version.kind() == r::Kind::Software && state == r::State::Archived)
            || (version.kind() != r::Kind::Software && state != r::State::Active)
        {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
}
fn select<'a>(
    version: &'a r::Version,
    binding: &ExactResourceBinding,
    parameters: ScriptParameters<'_>,
) -> Result<SelectedScript<'a>> {
    let exact = binding;
    let selected = checked_input(version.select_script(
        match exact.platform {
            Platform::Windows => r::Platform::Windows,
            Platform::Macos => r::Platform::MacOS,
        },
        match exact.architecture {
            Architecture::X86_64 => r::Architecture::X86_64,
            Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        &checked_input(r::Id::new(&exact.variant))?,
    ))?;
    parameters.checked(selected.definition())?;
    Ok(selected)
}

/// Rebind a live content proof to the exact selection read in the caller's transaction.
fn script<'a>(
    version: &'a r::Version,
    binding: &ExactResourceBinding,
    parameters: ScriptParameters<'_>,
    verified: &Verified,
) -> Result<SelectedScript<'a>> {
    let prepared = select(version, binding, parameters)?;
    if !verified.matches(prepared.artifact()) {
        return Err(Error::Conflict.into());
    }
    Ok(prepared)
}

fn variant<'a>(
    version: &'a resource::Version,
    binding: &ExactResourceBinding,
) -> Result<&'a resource::Variant> {
    let exact = binding;
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

fn resource_artifact(
    version: &r::Version,
    input: ResourcePreparation<'_>,
) -> Result<Option<(r::Artifact, StorageClass)>> {
    let (artifact, class) = match input {
        ResourcePreparation::Script {
            binding,
            parameters,
        } => (
            select(version, binding, parameters)?.artifact().clone(),
            StorageClass::Artifact,
        ),
        ResourcePreparation::Configuration { binding } => {
            match variant(version, binding)?.declaration() {
                r::Declaration::Configuration { artifact } => {
                    (artifact.clone(), StorageClass::NativeConfiguration)
                }
                _ => return Err(Error::Malformed.into()),
            }
        }
        ResourcePreparation::AgentCollection { binding } => {
            match variant(version, binding)?.declaration() {
                r::Declaration::AgentCollection { artifact, .. } => {
                    (artifact.clone(), StorageClass::Artifact)
                }
                _ => return Err(Error::Malformed.into()),
            }
        }
        ResourcePreparation::NativeCollection { binding } => {
            match variant(version, binding)?.declaration() {
                r::Declaration::NativeCollection { artifact, .. } => {
                    (artifact.clone(), StorageClass::Artifact)
                }
                _ => return Err(Error::Malformed.into()),
            }
        }
        ResourcePreparation::Software { .. } => {
            if version.kind() != r::Kind::Software {
                return Err(Error::Malformed.into());
            }
            return Ok(None);
        }
    };
    Ok(Some((artifact, class)))
}
pub fn authorize_policy_snapshot(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &rss_mdm_policy::Definition,
) -> std::result::Result<(), crate::Error> {
    let permission = match definition.action {
        Action::Credential { ref operation, .. } => crate::credential_tasks::permission(operation),
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. }
        | Action::AgentCollection { .. }
        | Action::TelemetryProfile { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,
        Action::Software { .. } | Action::EnsureAgentInstalled { .. } => Permission::SoftwareDeploy,
        Action::RequestMdmEnrollment { .. } => Permission::Enrollment,
        Action::DeviceAccess { .. } => Permission::AccountWrite,
        Action::UnmanageDevice { .. } => Permission::DeviceUnmanage,
    };
    if matches!(definition.action, Action::EnsureAgentInstalled { .. }) {
        snapshot.require_all_devices(proof, Permission::Enrollment)?;
    }
    snapshot.require(proof, Permission::ScopeRead, None)?;
    snapshot.require_all_devices(proof, Permission::InventoryRead)?;
    snapshot.require_all_devices(proof, permission)?;
    Ok(())
}

fn agent_collection<'a>(
    version: &'a r::Version,
    binding: &ExactResourceBinding,
    verified: Option<&Verified>,
) -> Result<&'a r::AgentCollectionDefinition> {
    let v = variant(version, binding)?;
    let r::Declaration::AgentCollection {
        definition,
        artifact,
    } = v.declaration()
    else {
        return Err(Error::Malformed.into());
    };
    if !verified.is_some_and(|v| v.matches(artifact)) {
        return Err(Error::Conflict.into());
    }
    if definition
        .spec()
        .mappings
        .values()
        .any(|m| m.counter_normalization.is_some())
    {
        // Durable counter baselines are owned only by the periodic telemetry runtime.
        return Err(Error::Unsupported.into());
    }
    Ok(definition)
}

impl Inputs {
    /// Resolve only backend-owned software lifecycle; caller retains Policy authorization and locks.
    pub async fn software_binding_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &rss_mdm_policy::Action,
    ) -> Result<Option<[u8; 32]>> {
        if let rss_mdm_policy::Action::EnsureAgentInstalled { packages, .. } = action {
            let tenant = tx.tenant_id();
            let mut bindings = Vec::new();
            for (target, id) in packages {
                let id = *id;
                let package = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(
                                rss_mdm_software_service::agent_packages::resolve_in(c, tenant, id)
                                    .await
                                    .map_err(crate::agent_preparation::publication_error),
                            )
                        })
                    })
                    .await??;
                bindings.push((*target, id, package.digest, package.lifecycle));
            }
            return Ok(Some(
                crate::transaction::fingerprint(&bindings)?
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            ));
        }
        let binding = match action {
            rss_mdm_policy::Action::Software { resource, .. } => resource,
            _ => return Ok(None),
        };
        self.software.lock_in(tx).await?;
        let version = self
            .active_version_in(tx, binding.id.as_str(), binding.version.as_str())
            .await?;
        Ok(Some(self.software.binding_in(tx, &version).await?))
    }
}
