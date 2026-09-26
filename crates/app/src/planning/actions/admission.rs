use super::storage;
use crate::planning::action_contract::{ExecutionInput, ExecutionTargets, FrozenAction};
use crate::transaction::Result;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub(crate) struct Plan {
    pub id: Uuid,
    pub frozen: FrozenAction,
    pub active: bool,
    pub approved: bool,
    evidence: storage::Plan,
}
pub(crate) async fn read_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Plan> {
    let evidence = storage::load_plan(tx, id).await?;
    Ok(Plan {
        id: evidence.id,
        frozen: FrozenAction {
            input: ExecutionInput {
                platform: evidence.frozen.input.platform.clone(),
                architecture: evidence.frozen.input.architecture.clone(),
                parameters: evidence.frozen.input.parameters.clone(),
                schedule: evidence.frozen.input.schedule.clone(),
                run_lifetime_seconds: evidence.frozen.input.run_lifetime_seconds,
            },
            targets: ExecutionTargets {
                devices: evidence.frozen.targets.devices.clone(),
            },
            definition: evidence.frozen.definition.clone(),
            resource_digest: evidence.frozen.resource_digest,
            artifact_reference: evidence.frozen.artifact_reference.clone(),
            content: evidence.frozen.content.clone(),
        },
        active: evidence.active,
        approved: evidence.reviewer.is_some(),
        evidence,
    })
}
impl Plan {
    pub(crate) async fn authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<bool> {
        storage::valid(tx, &self.evidence, device, now).await
    }
}

pub(crate) async fn event_plans_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
    now: i64,
) -> Result<Vec<String>> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_planning.action_plans WHERE tenant_id=$1::uuid AND active AND reviewer IS NOT NULL AND (document->'input'->'schedule'->>'until')::bigint>$3 AND document->'targets'->'devices' ? $2 AND document->'input'->'schedule'->'trigger'->>'kind' IN ('check_in','registration') ORDER BY id LIMIT 128").bind(tenant).bind(device).bind(now).fetch_all(c).await})).await?)
}
