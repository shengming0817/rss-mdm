//! Published configuration resources and current download authority for Apple delivery.
use crate::deployment::device::DevicePrincipal;
use crate::deployment::*;
impl SoftwareService {
    pub async fn apple_asset_authority_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        operation: Uuid,
    ) -> Result<(rss_mdm_apple_mdm::native::request::Request, NativeTarget)> {
        self.transactions.runtime.validate_transaction(tx)?;
        storage::lock_device(tx, p.device()).await?;
        let op = storage::load(tx, &self.transactions.protection, operation).await?;
        if op.device != p.device() || op.device != p.device() {
            return Err(Error::Unauthorized.into());
        }
        let now = storage::now(tx).await?;
        if !storage::authority_decision(
            &self.transactions.source,
            &self.transactions.lifecycle,
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
