use super::{
    production,
    schedule::Trigger,
    state::{Cancellation, Execution},
    storage as db,
};
use crate::commands::{Commands, Result, corrupt, storage};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub(in crate::commands) fn plan_id(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("action.")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub(in crate::commands) async fn active(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    storage::lock(tx, "action-owner").await?;
    let plan = db::load_plan(tx, id).await?;
    let now = storage::now(tx).await?;
    let scheduled = plan.active
        && plan.reviewer.is_some()
        && now < plan.frozen.input.schedule.until
        && !matches!(plan.frozen.input.schedule.trigger, Trigger::Manual);
    let tenant = tx.tenant_id().to_string();
    let pending=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND ((state->>'execution'='not_started' AND state->>'cancellation'<>'confirmed') OR state->>'execution'='running'))").bind(tenant).bind(id.to_string()).fetch_one(c).await})).await?;
    Ok(scheduled || pending)
}
pub(in crate::commands) async fn recover(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    storage::lock(tx, "action-owner").await?;
    let plan = db::load_plan(tx, id).await?;
    let now = storage::now(tx).await?;
    production::tick(service, tx, &plan, now).await?;
    let tenant = tx.tenant_id().to_string();
    let runs=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND ((state->>'execution'='not_started' AND state->>'cancellation'<>'confirmed') OR state->>'execution'='running') AND id>coalesce((SELECT recovery_after FROM mdm_commands.action_plans WHERE tenant_id=$1::uuid AND id=$2::uuid),'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 128").bind(tenant).bind(id.to_string()).fetch_all(c).await})).await?;
    let next = runs.last().cloned();
    for id in runs {
        let mut run = db::load_run(tx, corrupt(Uuid::parse_str(&id))?).await?;
        let stale = stale_registration(tx, &run.target).await?;
        if stale || !db::valid(tx, &plan, &run.target.device, now).await? {
            run.state.cancel();
        }
        run.state
            .expire(now, plan.frozen.definition.spec().timeout_seconds);
        if run.state.execution == Execution::NotStarted
            && run.state.cancellation == Cancellation::Requested
        {
            run.state.cancel();
        }
        db::save_run(tx, &run).await?;
    }
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_plans SET recovery_after=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(next).execute(c).await?;Ok(())})).await?;
    Ok(())
}
impl Commands {
    pub(in crate::commands) async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), crate::Error> {
        let audit = crate::audit::Audit::new(self.tenant.to_string(), "command_dispatch");
        audit.operation(id, "command_dispatch");
        let result=self.transact((id,fingerprint,&audit),&audit,|ctx,tx|Box::pin(async move{
            let (id,fingerprint,audit)=ctx;let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let changed=tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3").bind(tenant).bind(id).bind(fingerprint).execute(c).await})).await?.rows_affected();
            if changed!=1{return Err(crate::Error::Unavailable(crate::Failure::CommandInvariant).into());}
            storage::audit(tx,audit,200).await?;Ok(())
        })).await;
        audit.finalize(None);
        result
    }
}

#[cfg(all(test, feature = "integration"))]
impl Commands {
    /// Exercise the production recovery transaction through the same action funnel as the worker.
    pub(crate) async fn recover_action_fixture(
        &self,
        id: Uuid,
    ) -> std::result::Result<(), crate::Error> {
        let audit = crate::audit::Audit::new(self.tenant.to_string(), "management_write");
        let result = self
            .transact((self, id), &audit, |ctx, tx| {
                Box::pin(async move {
                    let (service, id) = *ctx;
                    recover(service, tx, id).await
                })
            })
            .await;
        audit.finalize(None);
        result
    }

    /// Drive the production scheduling transaction at a fixed clock without a second worker.
    pub(crate) async fn scan_action_fixture(
        &self,
        id: Uuid,
        now: i64,
    ) -> std::result::Result<(), crate::Error> {
        let audit = crate::audit::Audit::new(self.tenant.to_string(), "management_write");
        let result = self
            .transact((self, id, now), &audit, |ctx, tx| {
                Box::pin(async move {
                    let (service, id, now) = *ctx;
                    storage::lock(tx, "action-owner").await?;
                    let plan = db::load_plan(tx, id).await?;
                    production::tick(service, tx, &plan, now).await
                })
            })
            .await;
        audit.finalize(None);
        result
    }
}

async fn stale_registration(
    tx: &mut PgTransaction<'_>,
    target: &super::model::Target,
) -> Result<bool> {
    match db::registration(tx, &target.device).await {
        Ok(current) => {
            Ok(current.registration != target.registration
                || current.generation != target.generation)
        }
        Err(crate::commands::Fault::Request(crate::Error::Conflict)) => Ok(true),
        Err(error) => Err(error),
    }
}
