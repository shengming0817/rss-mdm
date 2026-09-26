use super::*;
use crate::execution::ExecutionService;
use crate::execution_transaction::Result;
use crate::planning::actions::{ActionDispatch, storage::Plan};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
impl ActionDispatch for ExecutionService {
    fn target(&self, id: Uuid) -> rss_reconcile::Target {
        rss_reconcile::Target::new(
            crate::execution::recovery_scope(self.tenant),
            format!("action.{id}"),
        )
        .expect("bounded action target")
    }
    fn admit_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(crate::execution::storage::admit(tx))
    }

    fn initialize_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        id: Uuid,
        now: i64,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.action_progress(tenant_id,id,scan_at) VALUES($1::uuid,$2::uuid,$3)").bind(tenant).bind(id.to_string()).bind(now-1).execute(c).await?;Ok(())})).await?;
            Ok(())
        })
    }
    fn manual_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        plan: &'a Plan,
        now: i64,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            let plan = storage::load_plan(tx, plan.id).await?;
            Ok(
                production::produce(self, tx, &plan, now, "manual", now, None).await?
                    != production::ProduceOutcome::CapacityBlocked,
            )
        })
    }
}
