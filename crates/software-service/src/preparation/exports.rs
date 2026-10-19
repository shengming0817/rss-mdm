//! Exact native source selection and wire projection belong to the software owner.
use super::{Delivery, Error, Preparation, Result};
use crate::{
    catalog::FrozenSoftware,
    publication::{NativeExport, NativeExportProtocol},
};
use rss_mdm_agent_wire::runtime as w;
use rss_transactional_messaging_postgres::PgTransaction;
impl Preparation {
    pub(super) async fn export_in(
        &self,
        tx: &mut PgTransaction<'_>,
        delivery: &Delivery<'_>,
        selected: &FrozenSoftware,
        action: &w::SoftwareTaskAction,
    ) -> Result<w::SoftwareTaskExport> {
        if !matches!(
            &action.behavior,
            w::SoftwareTaskBehavior::Winget(_) | w::SoftwareTaskBehavior::Brew(_)
        ) {
            return Ok(w::SoftwareTaskExport::Direct);
        }
        let Delivery::Native { target } = delivery else {
            return Err(Error::Unsupported);
        };
        let owner = self.exports.get(*target).ok_or(Error::Unsupported)?;
        let exported = owner
            .native_export_in(tx, selected.version())
            .await?
            .map_err(|_| Error::Unsupported)?
            .ok_or(Error::Unsupported)?;
        map(exported)
    }
}
fn map(input: NativeExport) -> Result<w::SoftwareTaskExport> {
    let binding = w::SoftwareExportBinding {
        target: input.target,
        tenant_id: uuid::Uuid::parse_str(&input.tenant.to_string()).map_err(|_| Error::Input)?,
        publication: input.publication,
        target_digest: input.target_digest,
        resource: input.resource,
        resource_version: input.resource_version,
        resource_digest: input.resource_digest,
        definition_digest: input.definition_digest,
        document_sha256: input.document_sha256,
        dependencies: input
            .dependencies
            .into_iter()
            .map(|(resource, version, sha256)| w::SoftwareExportDependency {
                resource,
                version,
                sha256,
            })
            .collect(),
        artifacts: input
            .artifacts
            .into_iter()
            .map(|artifact| w::SoftwareExportArtifact {
                url: artifact.url,
                length: artifact.length,
                sha256: artifact.sha256,
            })
            .collect(),
    };
    Ok(match input.protocol {
        NativeExportProtocol::Winget { uri, identifier } => w::SoftwareTaskExport::Winget {
            binding,
            uri,
            identifier,
        },
        NativeExportProtocol::Brew {
            uri,
            commit,
            tap,
            credential_reference,
        } => w::SoftwareTaskExport::Brew {
            binding,
            uri,
            commit,
            tap,
            credential_reference,
        },
    })
}
