use super::model::*;
use crate::transaction::Result;
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
            let value = document.ok_or_else(|| {
                Error::from(crate::planning::error::ActionRejection::ScopeUnavailable)
            })?;
            if let Some(rejection) = value.get("rejection").and_then(Value::as_str) {
                use crate::planning::error::ActionRejection;
                return Err(Error::from(match rejection {
                    "unavailable" => ActionRejection::ScopeUnavailable,
                    "stale" => ActionRejection::ScopeStale,
                    _ => return Err(Error::Unavailable(Failure::PlanningStorage).into()),
                })
                .into());
            }
            if value.get("missing") == Some(&Value::Bool(true)) {
                return Err(
                    Error::Planning(crate::planning::error::PlanningError::Missing(
                        crate::planning::error::Missing::Scope,
                    ))
                    .into(),
                );
            }
            let targets: FrozenTargets = serde_json::from_value(value)
                .map_err(|_| Error::Unavailable(Failure::PlanningStorage))?;
            validate_devices(&targets.devices)?;
            Ok(targets)
        }
    }
}
