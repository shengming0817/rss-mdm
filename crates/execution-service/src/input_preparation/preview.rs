//! Remaining Execution previews evaluate only their own current configuration.
use super::*;
pub(crate) enum PreviewInputs {
    DeviceAccess {
        windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration,
    },
    DeviceLifecycle,
    Credential {
        architecture: Architecture,
    },
}
pub(crate) struct PreparedPreview {
    pub inputs: PreviewInputs,
}
impl Inputs {
    pub(crate) async fn prepare_preview_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
    ) -> Result<PreparedPreview> {
        Ok(PreparedPreview {
            inputs: self.preview_in(tx, input, proof, snapshot).await?,
        })
    }
    pub(crate) async fn recheck_preview_on(
        &self,
        _c: &mut sqlx::PgConnection,
        _input: &PublicationInput<'_>,
        _prepared: &PreparedPreview,
    ) -> Result<()> {
        Ok(())
    }
    pub(crate) async fn preview_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        _proof: &AuthorizedPrincipal,
        _snapshot: &crate::authorization::Snapshot,
    ) -> Result<PreviewInputs> {
        self.validate_in(tx)?;
        match input {
            PublicationInput::DeviceAccess { windows, .. } => {
                if !self.materials.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                windows.validate().map_err(|_| Error::Malformed)?;
                Ok(PreviewInputs::DeviceAccess {
                    windows: (*windows).clone(),
                })
            }
            PublicationInput::Unmanage { .. } => Ok(PreviewInputs::DeviceLifecycle),
            PublicationInput::Credential { architecture, .. } => {
                if !self.materials.recovery_enabled || !self.materials.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                Ok(PreviewInputs::Credential {
                    architecture: *architecture,
                })
            }
        }
    }
}
