use super::*;
impl Inputs {
    pub(super) async fn freeze_resource_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &PublicationInput<'_>,
        _verified: Option<&Verified>,
    ) -> Result<Frozen> {
        self.validate_in(tx)?;
        let resource = action.resource().ok_or(Error::Unsupported)?;
        let binding = resource.identity();
        let version = self
            .active_version_in(tx, binding.id(), binding.version())
            .await?;
        Ok(Frozen::Software {
            action: Box::new(self.software_in(tx, action, &version).await?),
        })
    }
}
