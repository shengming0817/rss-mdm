//! Validate draft material without collection registration, sealing or assignment identities.
use super::*;
pub(crate) enum PreviewInputs {
    DeviceAccess {
        windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration,
    },
    DeviceLifecycle,
    Credential {
        architecture: Architecture,
    },
    Software(Box<FrozenSoftwareAction>),
    Onboarding(Frozen),
}
pub(crate) struct PreparedPreview {
    pub inputs: PreviewInputs,
    resource: Option<r::Version>,
}
impl Inputs {
    pub(crate) async fn prepare_preview_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        verified: Option<&Verified>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
    ) -> Result<PreparedPreview> {
        let inputs = self
            .preview_in(tx, input, verified, proof, snapshot)
            .await?;
        let resource = if let Some(resource) = input.resource() {
            let binding = resource.identity();
            Some(
                self.active_version_in(tx, binding.id(), binding.version())
                    .await?,
            )
        } else {
            None
        };
        Ok(PreparedPreview { inputs, resource })
    }
    pub(crate) async fn recheck_preview_on(
        &self,
        c: &mut sqlx::PgConnection,
        _input: &PublicationInput<'_>,
        prepared: &PreparedPreview,
    ) -> Result<()> {
        if let Some(expected) = &prepared.resource {
            let mut facts = rss_mdm_resource_postgres::version_facts_on(
                c,
                self.tenant,
                &[(
                    expected.resource().as_str().to_owned(),
                    expected.label().as_str().to_owned(),
                )],
            )
            .await?;
            let (version, state) = facts.versions.pop().flatten().ok_or(Error::Conflict)?;
            if version.digest() != expected.digest()
                || (version.kind() == r::Kind::Software && state == r::State::Archived)
                || (version.kind() != r::Kind::Software && state != r::State::Active)
            {
                return Err(Error::Conflict.into());
            }
        }
        match &prepared.inputs {
            PreviewInputs::Software(action) => {
                let requests = action
                    .variants
                    .iter()
                    .map(
                        |(target, variant)| rss_mdm_software_service::catalog::BindingRequest {
                            resource: action.resource.clone(),
                            version: action.version.clone(),
                            digest: action.resource_digest,
                            allow_draft: false,
                            selection: Some((
                                match target.parts().0 {
                                    Platform::Windows => r::Platform::Windows,
                                    Platform::Macos => r::Platform::MacOS,
                                },
                                match target.parts().1 {
                                    Architecture::X86_64 => r::Architecture::X86_64,
                                    Architecture::Aarch64 => r::Architecture::Aarch64,
                                },
                                variant.clone(),
                                matches!(action.intent, SoftwareIntent::ExplicitUninstall),
                            )),
                        },
                    )
                    .collect::<Vec<_>>();
                if rss_mdm_software_service::catalog::bindings_many_on(c, self.tenant, &requests)
                    .await?
                    .iter()
                    .any(Option::is_none)
                {
                    return Err(Error::Conflict.into());
                }
            }
            PreviewInputs::Onboarding(Frozen::AgentInstall { action }) => {
                for package in action.packages.values() {
                    if !package.admitted_snapshot_on(c, self.tenant).await? {
                        return Err(Error::Conflict.into());
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
    pub(crate) async fn preview_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        _verified: Option<&Verified>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
    ) -> Result<PreviewInputs> {
        self.validate_in(tx)?;
        match input {
            PublicationInput::DeviceAccess { windows, .. } => {
                if !self.materials.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                windows.validate().map_err(|_| Error::Malformed)?;
                return Ok(PreviewInputs::DeviceAccess {
                    windows: (*windows).clone(),
                });
            }
            PublicationInput::Unmanage { .. } => return Ok(PreviewInputs::DeviceLifecycle),
            PublicationInput::Credential { architecture, .. } => {
                if !self.materials.recovery_enabled || !self.materials.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                return Ok(PreviewInputs::Credential {
                    architecture: *architecture,
                });
            }
            PublicationInput::AgentInstall {
                binding,
                schedule,
                lifetime,
            } => {
                return Ok(PreviewInputs::Onboarding(Frozen::AgentInstall {
                    action: Box::new(
                        self.freeze_agent_in(tx, proof, snapshot, binding, schedule, *lifetime)
                            .await?,
                    ),
                }));
            }
            PublicationInput::Enrollment {
                organization,
                schedule,
                lifetime,
            } => {
                return Ok(PreviewInputs::Onboarding(Frozen::MdmEnrollment {
                    action: Box::new(self.prepare_enrollment(
                        proof,
                        snapshot,
                        *organization,
                        schedule,
                        *lifetime,
                    )?),
                }));
            }
            _ => (),
        }
        let resource = input.resource().ok_or(Error::Unsupported)?;
        let binding = resource.identity();
        let version = self
            .active_version_in(tx, binding.id(), binding.version())
            .await?;
        match input {
            PublicationInput::Software { .. } => Ok(PreviewInputs::Software(Box::new(
                self.software_in(tx, input, &version).await?,
            ))),
            PublicationInput::DeviceAccess { .. }
            | PublicationInput::Unmanage { .. }
            | PublicationInput::Credential { .. }
            | PublicationInput::AgentInstall { .. }
            | PublicationInput::Enrollment { .. } => {
                unreachable!("onboarding was prepared above")
            }
        }
    }
}
