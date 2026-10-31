use super::*;
impl Inputs {
    pub(super) async fn freeze_resource_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &PublicationInput<'_>,
    ) -> Result<Published> {
        self.validate_in(tx)?;
        let binding = action.resource().ok_or(Error::Unsupported)?;
        let version = self
            .active_version_in(tx, binding.id(), binding.version())
            .await?;
        Ok(Published::Software {
            action: Box::new(self.software_in(tx, action, &version).await?),
        })
    }
}
