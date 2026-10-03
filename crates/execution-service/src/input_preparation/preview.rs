//! Validate draft material without collection registration, sealing or assignment identities.
use super::*;
pub(crate) enum PreviewInputs {
    Resource,
    Software(Box<FrozenSoftwareAction>),
    Onboarding(Frozen),
}
impl Inputs {
    pub(crate) async fn preview_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        verified: Option<&Verified>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
    ) -> Result<PreviewInputs> {
        match input {
            PublicationInput::AgentInstall {
                binding,
                admission,
                schedule,
                lifetime,
            } => {
                return Ok(PreviewInputs::Onboarding(Frozen::AgentInstall {
                    action: Box::new(
                        self.freeze_agent_in(
                            tx, proof, snapshot, binding, *admission, schedule, *lifetime,
                        )
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
            PublicationInput::Script {
                binding,
                parameters,
                ..
            } => {
                if !self.signing_enabled {
                    return Err(Error::Conflict.into());
                }
                let prepared = script(
                    &version,
                    binding,
                    parameters,
                    verified.ok_or(Error::Conflict)?,
                )?;
                if let resource::ScriptPurpose::Collection { mappings } =
                    &prepared.definition().spec().purpose
                {
                    let source = if prepared.definition().spec().profile
                        == resource::ScriptProfile::Osquery
                    {
                        rss_mdm_inventory::Source::AgentOsquery
                    } else {
                        rss_mdm_inventory::Source::AgentScript
                    };
                    prepare_collection_in(
                        tx,
                        self.tenant,
                        &version,
                        prepared.variant(),
                        source,
                        mappings.keys(),
                    )
                    .await?;
                }
            }
            PublicationInput::NativeCollection { binding, .. } => {
                let (definition, _) = native_collection(&version, binding, verified)?;
                let source = match definition.spec().adapter {
                    resource::NativeAdapter::WindowsCsp => rss_mdm_inventory::Source::MdmWindows,
                    _ => rss_mdm_inventory::Source::MdmApple,
                };
                prepare_collection_in(
                    tx,
                    self.tenant,
                    &version,
                    variant(&version, binding)?,
                    source,
                    definition.spec().mappings.keys(),
                )
                .await?;
            }
            PublicationInput::Configuration { binding, exit } => {
                configuration(&version, binding, *exit, verified)?;
            }
            PublicationInput::Software { .. } => {
                return Ok(PreviewInputs::Software(Box::new(
                    self.software_in(tx, input, &version).await?,
                )));
            }
            PublicationInput::AgentInstall { .. } | PublicationInput::Enrollment { .. } => {
                unreachable!("onboarding was prepared above")
            }
        }
        Ok(PreviewInputs::Resource)
    }
}
