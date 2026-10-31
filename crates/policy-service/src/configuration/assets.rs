use super::*;
use rss_mdm_resource as r;
pub struct ConfigurationArtifact {
    pub artifact: r::Artifact,
    pub apple_silicon: bool,
    pub verified: rss_mdm_content_service::Verified,
}
impl Transactions {
    pub async fn apple_configuration_artifact_in(
        &self,
        tx: &mut PgTransaction<'_>,
        asset: &rss_mdm_apple_mdm::native::ddm::AssetInput,
    ) -> Result<ConfigurationArtifact> {
        self.runtime.validate_transaction(tx)?;
        let id = r::Id::new(&asset.resource).map_err(|_| Error::Malformed)?;
        let label = r::Id::new(&asset.version).map_err(|_| Error::Malformed)?;
        let (version, state) = rss_mdm_resource_postgres::lock_reference_in(tx, &id, &label)
            .await?
            .map_err(|_| Error::NotFound)?;
        if state == r::State::Archived || version.digest().bytes() != asset.version_digest {
            return Err(Error::Conflict.into());
        }
        let mut variants = version
            .variants()
            .iter()
            .filter(|v| v.platform() == r::Platform::MacOS && v.key().as_str() == asset.variant);
        let variant = variants.next().ok_or(Error::Malformed)?;
        if variants.next().is_some() {
            return Err(Error::Malformed.into());
        }
        let r::Declaration::Configuration { artifact } = variant.declaration() else {
            return Err(Error::Malformed.into());
        };
        if artifact.length() == 0 || artifact.length() > 16 * 1024 * 1024 {
            return Err(Error::Malformed.into());
        }
        let content = self.content.as_ref().ok_or(Error::Unsupported)?;
        let verified = content
            .verify_class(
                artifact,
                rss_mdm_content_service::StorageClass::NativeConfiguration,
                content.upload_budget()?.operation_deadline(),
            )
            .await?;

        Ok(ConfigurationArtifact {
            artifact: artifact.clone(),
            apple_silicon: variant.architecture() == r::Architecture::Aarch64,
            verified,
        })
    }
}
