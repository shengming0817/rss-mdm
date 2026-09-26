use super::{production, storage};
use crate::execution::{ExecutionService, recovery_scope};
use crate::{Error, transaction::Result};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
impl ExecutionService {
    pub(crate) async fn initialize_action_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        now: i64,
    ) -> Result<()> {
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_progress(tenant_id,id,scan_at) VALUES($1::uuid,$2::uuid,$3)").bind(tenant).bind(id.to_string()).bind(now-1).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
    pub(crate) async fn start_action_in(
        &self,
        tx: &mut PgTransaction<'_>,
        writer: &rss_transactional_messaging_postgres::PgOutboxWriter,
        id: Uuid,
    ) -> Result<()> {
        let plan = storage::load_plan(tx, id).await?;
        let now = crate::action_admission::now(tx).await?;
        if matches!(
            plan.definition.frozen.input.schedule.trigger,
            crate::planning::action_schedule::Trigger::Manual
        ) && production::produce(self, writer, tx, &plan, now, "manual", now, None).await?
            == production::ProduceOutcome::CapacityBlocked
        {
            return Err(Error::from(crate::planning::error::ActionRejection::Capacity).into());
        }
        Ok(())
    }
    pub(crate) async fn wake_action_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
        let target =
            rss_reconcile::Target::new(recovery_scope(tx.tenant_id()), format!("action.{id}"))
                .expect("bounded action target");
        rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await?;
        Ok(())
    }
}
