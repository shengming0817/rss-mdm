use super::*;
impl Transactions {
    pub(crate) async fn observations_on(
        &self,
        c: &mut PgConnection,
        ops: &[(&storage::Operation, dc::Status)],
        values: bool,
    ) -> Result<BTreeMap<Uuid, NativeObservation>> {
        let reads = ops
            .iter()
            .map(|(op, status)| channels::ObservationRead {
                id: op.id,
                device: op.device,

                task: op.request.task.clone(),
                profile: op.request.profile_target().is_some(),
                status: *status,
            })
            .collect();
        Ok(self
            .channels
            .observations(c, self.tenant, reads, values)
            .await?)
    }
}
