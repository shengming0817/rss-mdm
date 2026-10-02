//! Execution prepares immutable resource inputs without creating a Policy.
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::{Error, Inputs, action_contract::*, freeze_inputs::*, frozen::Frozen, transaction::*};
use rss_mdm_policy::{Action, Exit, ResourceBinding, SoftwareIntent};
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::json;
impl Inputs {
    pub async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &Action,
        verified: Option<&rss_mdm_content_service::Verified>,
        owner: Option<crate::configuration::Owner>,
    ) -> Result<Frozen> {
        let binding = action.resource().ok_or(Error::Unsupported)?;
        let version = self
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
            let targets = selection
                .variants
                .iter()
                .map(|(target, key)| {
                    let (platform, architecture) = target.parts();
                    (
                        crate::sources::software::target(platform, architecture),
                        key.clone(),
                    )
                })
                .collect::<Vec<_>>();
            self.software
                .freeze_in(
                    tx,
                    rss_mdm_software_service::preparation::FreezeRequest {
                        resource: binding.id(),
                        version: binding.version(),
                        digest: version.digest().bytes(),
                        admission: *admission_operation,
                        uninstall: matches!(intent, SoftwareIntent::ExplicitUninstall),
                        targets: &targets,
                    },
                )
                .await?;
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
            if !self.signing_enabled {
                return Err(Error::Conflict.into());
            }
            let prepared = script(
                &version,
                binding,
                parameters,
                verified.ok_or(Error::Conflict)?,
            )?;
            return Ok(Frozen::Execution {
                action: Box::new(
                    freeze_script_in(
                        tx,
                        self.tenant,
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
                    self.tenant,
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
                let native = crate::configuration::Configuration::read(verified)?;
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
                    native: crate::configuration::Protected::seal(
                        &self.protection,
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
use rss_mdm_content_service::{Store, Verified};
use rss_mdm_policy::{Architecture, Platform};
use rss_mdm_resource::{self as r, PreparedScript};
use serde_json::Value;
use std::sync::Arc;
pub fn select<'a>(
    version: &'a r::Version,
    binding: &ResourceBinding,
    parameters: &'a Value,
) -> Result<PreparedScript<'a>> {
    let exact = binding.exact().ok_or(Error::Malformed)?;
    checked_input(version.prepare_script(
        match exact.platform {
            Platform::Windows => r::Platform::Windows,
            Platform::Macos => r::Platform::MacOS,
        },
        match exact.architecture {
            Architecture::X86_64 => r::Architecture::X86_64,
            Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        &checked_input(r::Id::new(&exact.variant))?,
        parameters,
    ))
}

/// Rebind a live content proof to the exact selection read in the caller's transaction.
pub fn script<'a>(
    version: &'a r::Version,
    binding: &ResourceBinding,
    parameters: &'a Value,
    verified: &Verified,
) -> Result<PreparedScript<'a>> {
    let prepared = select(version, binding, parameters)?;
    if !verified.matches(prepared.artifact()) {
        return Err(Error::Conflict.into());
    }
    Ok(prepared)
}

impl Inputs {
    pub async fn active_version_in(
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
        if state != r::State::Active {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
    pub async fn verify_script(
        &self,
        binding: &ResourceBinding,
        parameters: &Value,
        content: Option<&Arc<Store>>,
    ) -> std::result::Result<Verified, Error> {
        let artifact = inspect(
            &self.runtime,
            self.tenant,
            (self, binding, parameters),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, binding, parameters) = *ctx;
                    let version = service
                        .active_version_in(tx, binding.id(), binding.version())
                        .await?;
                    Ok(select(&version, binding, parameters)?.artifact().clone())
                })
            },
            TransactionOwner::Execution,
        )
        .await?;
        Ok(content.ok_or(Error::Unsupported)?.verify(&artifact).await?)
    }
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

pub fn authorize_policy_snapshot(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &rss_mdm_policy::Definition,
) -> std::result::Result<(), crate::Error> {
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
