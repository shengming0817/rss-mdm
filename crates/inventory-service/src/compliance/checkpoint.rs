use super::*;
use crate::assets::evaluation::EvaluationProgress;
impl Compliance {
    pub(super) async fn evaluation(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<Option<EvaluationProgress>> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        let t = self.tenant();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::evaluation(c, t, id).await })
            })
            .await?;
        row.map(|(binding, arrays)| {
            Ok(EvaluationProgress {
                binding,
                arrays: arrays
                    .into_iter()
                    .map(|(v, s)| Ok((v, stored(serde_json::from_value(s))?)))
                    .collect::<Result<_>>()?,
            })
        })
        .transpose()
    }
    pub(super) async fn save_evaluation(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        progress: &EvaluationProgress,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        let t = self.tenant();
        let binding = progress.binding.clone();
        let arrays = progress
            .arrays
            .iter()
            .map(|(v, s)| Ok((v.clone(), json(s)?)))
            .collect::<Result<Vec<_>>>()?;
        tx.with_connection(move |c| {
            Box::pin(async move { pg::tasks::save_evaluation(c, t, id, &binding, arrays).await })
        })
        .await?;
        Ok(())
    }
    pub(super) async fn clear_evaluation(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        let t = self.tenant();
        tx.with_connection(move |c| {
            Box::pin(async move { pg::tasks::clear_evaluation(c, t, id).await })
        })
        .await?;
        Ok(())
    }
}
