//! Exact native source selection and wire projection belong to the software owner.
use super::{Delivery, Error, Preparation, Result};
use crate::{
    catalog::FrozenSoftware,
    publication::{NativeExport, NativeExportProtocol},
};
use rss_mdm_agent_wire as w;
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
        let Delivery::Native { source, ring } = delivery else {
            return Err(Error::Unsupported);
        };
        let owner = self.exports.get(*source).ok_or(Error::Unsupported)?;
        let exported = owner
            .native_export_in(tx, *ring, selected.version())
            .await?
            .map_err(|_| Error::Unsupported)?
            .ok_or(Error::Unsupported)?;
        map(exported)
    }
}
fn map(input: NativeExport) -> Result<w::SoftwareTaskExport> {
    let binding = w::SoftwareExportBinding {
        source: input.source,
        tenant_id: uuid::Uuid::parse_str(&input.tenant.to_string()).map_err(|_| Error::Input)?,
        ring: match input.ring {
            rss_mdm_software_release::Ring::Test => w::SoftwareExportRing::Test,
            rss_mdm_software_release::Ring::Pilot => w::SoftwareExportRing::Pilot,
            rss_mdm_software_release::Ring::Production => w::SoftwareExportRing::Production,
        },
        publication: input.publication,
        source_digest: input.source_digest,
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
