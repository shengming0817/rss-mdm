use super::model::*;
use crate::execution_transaction::Result;
use crate::{Error, Failure};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
pub(super) async fn freeze_in(
    tx: &mut PgTransaction<'_>,
    input: &Targets,
) -> Result<FrozenTargets> {
    match input {
        Targets::Devices { devices } => {
            validate_devices(devices)?;
            Ok(FrozenTargets {
                devices: devices.clone(),
                scope: None,
            })
        }
        Targets::Scope { reference } => {
            let id = reference.id;
            let revision = reference.resolution_revision as i64;
            let document: Option<Value> = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT mdm_planning.action_targets($1::uuid,$2)")
                            .bind(id.to_string())
                            .bind(revision)
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            let value = document.ok_or(Error::Conflict)?;
            if value.get("missing") == Some(&Value::Bool(true)) {
                return Err(Error::ObjectNotFound(crate::ObjectKind::Scope).into());
            }
            let targets: FrozenTargets = serde_json::from_value(value)
                .map_err(|_| Error::Unavailable(Failure::ManagementStorage))?;
            validate_devices(&targets.devices)?;
            Ok(targets)
        }
    }
}
