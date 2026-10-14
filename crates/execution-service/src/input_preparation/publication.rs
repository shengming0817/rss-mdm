use super::*;
impl Inputs {
    pub(super) async fn freeze_resource_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &PublicationInput<'_>,
        verified: Option<&rss_mdm_content_service::Verified>,
        owner: crate::configuration::Owner,
    ) -> Result<Frozen> {
        let resource = action.resource().ok_or(Error::Unsupported)?;
        let binding = resource.identity();
        let version = self
            .active_version_in(tx, binding.id(), binding.version())
            .await?;
        if matches!(action, PublicationInput::Software { .. }) {
            return Ok(Frozen::Software {
                action: Box::new(self.software_in(tx, action, &version).await?),
            });
        }
        if let PublicationInput::Script {
            binding: exact,
            parameters,
            schedule,
            frequency,
            lifetime: run_lifetime_seconds,
            ..
        } = action
        {
            if !self.signing_enabled {
                return Err(Error::Conflict.into());
            }
            let prepared = script(
                &version,
                exact,
                *parameters,
                verified.ok_or(Error::Conflict)?,
            )?;
            return Ok(Frozen::Execution {
                action: Box::new(
                    freeze_script_in(
                        tx,
                        self.tenant,
                        &prepared,
                        parameters.checked(prepared.definition())?,
                        (*schedule).clone(),
                        *run_lifetime_seconds,
                    )
                    .await?,
                ),
                frequency: *frequency,
            });
        }
        let exact = match action {
            PublicationInput::NativeCollection { binding, .. }
            | PublicationInput::Configuration { binding, .. } => *binding,
            _ => return Err(Error::Malformed.into()),
        };
        let v = variant(&version, exact)?;
        match (action, v.declaration()) {
            (
                PublicationInput::NativeCollection {
                    schedule,
                    frequency,
                    lifetime: run_lifetime_seconds,
                    ..
                },
                resource::Declaration::NativeCollection {
                    definition: _,
                    artifact: _,
                },
            ) => {
                let (definition, windows_plan) = native_collection(&version, exact, verified)?;
                let source = match definition.spec().adapter {
                    resource::NativeAdapter::WindowsRead => rss_mdm_inventory::Source::MdmWindows,
                    rss_mdm_resource::NativeAdapter::AppleDeviceInformation
                    | rss_mdm_resource::NativeAdapter::AppleInstalledApplications => {
                        rss_mdm_inventory::Source::MdmApple
                    }
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
                            schedule: (*schedule).clone(),
                            run_lifetime_seconds: *run_lifetime_seconds,
                        },
                        definition: definition.clone(),
                        windows_plan,
                        grants: Default::default(),
                        collection,
                        resource_digest: version.digest().bytes(),
                    }),
                })
            }
            (
                PublicationInput::Configuration { exit, .. },
                resource::Declaration::Configuration { .. },
            ) => {
                let native = configuration(&version, exact, *exit, verified)?;
                Ok(Frozen::Configuration {
                    native: crate::configuration::Protected::seal(
                        &self.protection,
                        tx.tenant_id(),
                        owner,
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
