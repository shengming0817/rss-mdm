//! Scope owns its management replay identity alongside the mutation it protects.
use crate::{BindingError, ScopeBinding};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;
impl ScopeBinding {
    pub async fn replay_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        actor: &str,
        id: Uuid,
        fingerprint: &[u8],
    ) -> Result<Option<Value>, BindingError> {
        self.validate_in(tx)?;
        if actor.is_empty() {
            return Err(BindingError::Invalid);
        }
        let tenant = self.tenant.to_string();
        let sql = crate::storage_profile::sql(self.profile());
        let row = tx
            .with_connection_context(&mut (actor, &tenant), |(actor, tenant), c| {
                Box::pin(async move {
                    sqlx::query(sql.operation_lock)
                        .bind(*tenant)
                        .bind(*actor)
                        .bind(id.to_string())
                        .execute(&mut *c)
                        .await?;
                    sqlx::query(sql.operation_replay)
                        .bind(*tenant)
                        .bind(*actor)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row
            .try_get::<Vec<u8>, _>("fingerprint")
            .map_err(PgError::from)?
            != fingerprint
        {
            return Err(BindingError::Conflict);
        }
        Ok(Some(row.try_get("response").map_err(PgError::from)?))
    }
    pub async fn record_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        actor: &str,
        id: Uuid,
        fingerprint: &[u8],
        response: &Value,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        if actor.is_empty() {
            return Err(BindingError::Invalid);
        }
        let tenant = self.tenant.to_string();
        let sql = crate::storage_profile::sql(self.profile());
        tx.with_connection_context(
            &mut (actor, &tenant, fingerprint, response),
            |(actor, tenant, fingerprint, response), c| {
                Box::pin(async move {
                    sqlx::query(sql.operation_receipt)
                        .bind(*tenant)
                        .bind(*actor)
                        .bind(id)
                        .bind(*fingerprint)
                        .bind(*response)
                        .execute(c)
                        .await?;
                    Ok(())
                })
            },
        )
        .await?;
        Ok(())
    }
}
