//! Frozen configuration resources and current download authority for Apple delivery.
use crate::device::DevicePrincipal;
use crate::*;
use rss_mdm_resource as r;
pub struct ConfigurationArtifact {
    pub artifact: r::Artifact,
    pub apple_silicon: bool,
    pub verified: rss_mdm_content_service::Verified,
}
impl ExecutionService {
    pub async fn apple_configuration_artifact_in(
        &self,
        tx: &mut PgTransaction<'_>,
        asset: &rss_mdm_apple_mdm::native::ddm::AssetInput,
    ) -> Result<ConfigurationArtifact> {
        self.transactions.runtime.validate_transaction(tx)?;
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
        let verified = self
            .transactions
            .inputs
            .verify_artifact(
                artifact,
                rss_mdm_content_service::StorageClass::NativeConfiguration,
            )
            .await?;

        Ok(ConfigurationArtifact {
            artifact: artifact.clone(),
            apple_silicon: variant.architecture() == r::Architecture::Aarch64,
            verified,
        })
    }
    pub async fn apple_asset_authority_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        operation: Uuid,
    ) -> Result<(rss_mdm_apple_mdm::native::request::Request, NativeTarget)> {
        self.transactions.runtime.validate_transaction(tx)?;
        storage::lock_device(tx, p.device()).await?;
        let op = storage::load(tx, &self.transactions.protection, operation).await?;
        if op.registration != p.registration()
            || op.registration_generation != p.generation()
            || op.device != p.device()
        {
            return Err(Error::Unauthorized.into());
        }
        let now = storage::now(tx).await?;
        if !storage::authority_decision(
            &self.transactions.source,
            &self.transactions.protection,
            tx,
            &op,
            now,
        )
        .await?
        .is_authorized()
        {
            return Err(Error::Forbidden.into());
        }
        let progress = self.transactions.required_command(tx, &op).await?.status();
        if (progress.is_terminal() && progress != dc::Status::Applied)
            || (!progress.is_terminal() && now >= op.request.deadline)
        {
            return Err(Error::Forbidden.into());
        }
        let Task::Macos { request } = op.request.task else {
            return Err(Error::Malformed.into());
        };
        Ok((request, op.request.target))
    }
}
