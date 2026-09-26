use super::{
    production,
    state::{Cancellation, Execution},
    storage as db,
};
use crate::execution::{ExecutionService, Result, corrupt, storage};
use crate::planning::actions::schedule::Trigger;
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub(in crate::execution) fn plan_id(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("action.")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub(in crate::execution) async fn active(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    storage::lock(tx, "action-owner").await?;
    let plan = db::load_plan(tx, id).await?;
    let now = storage::now(tx).await?;
    let scheduled = plan.definition.active
        && plan.definition.reviewer.is_some()
        && now < plan.definition.frozen.input.schedule.until
        && !matches!(
            plan.definition.frozen.input.schedule.trigger,
            Trigger::Manual
        );
    let tenant = tx.tenant_id().to_string();
    let pending=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND ((state->>'execution'='not_started' AND state->>'cancellation'<>'confirmed') OR state->>'execution'='running'))").bind(tenant).bind(id.to_string()).fetch_one(c).await})).await?;
    Ok(scheduled || pending)
}
pub(in crate::execution) async fn recover(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    storage::lock(tx, "action-owner").await?;
    let plan = db::load_plan(tx, id).await?;
    let now = storage::now(tx).await?;
    production::tick(service, tx, &plan, now).await?;
    let tenant = tx.tenant_id().to_string();
    let runs=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND ((state->>'execution'='not_started' AND state->>'cancellation'<>'confirmed') OR state->>'execution'='running') AND id>coalesce((SELECT recovery_after FROM mdm_commands.action_progress WHERE tenant_id=$1::uuid AND id=$2::uuid),'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 128").bind(tenant).bind(id.to_string()).fetch_all(c).await})).await?;
    let next = runs.last().cloned();
    for id in runs {
        let mut run = db::load_run(tx, corrupt(Uuid::parse_str(&id))?).await?;
        let previous = run.state.clone();
        let stale = stale_registration(tx, &run.target).await?;
        if stale
            || !crate::planning::actions::storage::valid(
                tx,
                &plan.definition,
                &run.target.device,
                now,
            )
            .await?
        {
            run.state.cancel();
        }
        run.state.expire(
            now,
            plan.definition.frozen.definition.spec().timeout_seconds,
        );
        if run.state.execution == Execution::NotStarted
            && run.state.cancellation == Cancellation::Requested
        {
            run.state.cancel();
        }
        db::save_run(tx, &run).await?;
        audit_recovery(service, tx, &run, &previous).await?;
    }
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_progress SET recovery_after=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(next).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub(super) async fn audit_recovery(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &super::state::RunState,
) -> Result<()> {
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            tx.tenant_id().to_string(),
            "command_reconcile",
        );
        audit.identify_service("command-recovery");
        audit.operation(run.id, "command_reconcile");
        audit.plan(run.plan);
        audit.target(&run.target.device);
        audit.registration(run.target.registration);
        let bytes = crate::execution::invalid(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            &format!(
                "action:{}:recover:{:x}",
                run.id,
                sha2::Sha256::digest(&bytes)
            ),
            &bytes,
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"before":previous,"after":run.state}))?;
        audit.finalize(None);
        service.audit_store.append_in(tx, &fact, false).await?;
    }
    Ok(())
}
impl ExecutionService {
    pub(in crate::execution) async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), crate::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.tenant.to_string(),
            "command_dispatch",
        );
        audit.operation(id, "command_dispatch");
        audit.identify_service("command-dispatch");
        let result=crate::execution_transaction::transact(&self.runtime, &self.audit_store, self.tenant, (self,id,fingerprint,&audit),&audit,|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;
            let fact=Fact::business(audit,&format!("action:{id}:dispatch"),fingerprint,200,"success",None)?;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_commands.action_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
            if old{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            service.audit_store.append_in(tx,&fact,old).await?;Ok(())
        })).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}

#[cfg(all(test, feature = "integration"))]
impl ExecutionService {
    /// Exercise the production recovery transaction through the same action funnel as the worker.
    pub(crate) async fn recover_action_fixture(
        &self,
        id: Uuid,
    ) -> std::result::Result<(), crate::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.tenant.to_string(),
            "management_write",
        );
        let result = crate::execution_transaction::transact(
            &self.runtime,
            &self.audit_store,
            self.tenant,
            (self, id),
            &audit,
            |ctx, tx| {
                Box::pin(async move {
                    let (service, id) = *ctx;
                    recover(service, tx, id).await
                })
            },
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }

    /// Drive the production scheduling transaction at a fixed clock without a second worker.
    pub(crate) async fn scan_action_fixture(
        &self,
        id: Uuid,
        now: i64,
    ) -> std::result::Result<(), crate::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.tenant.to_string(),
            "management_write",
        );
        let result = crate::execution_transaction::transact(
            &self.runtime,
            &self.audit_store,
            self.tenant,
            (self, id, now),
            &audit,
            |ctx, tx| {
                Box::pin(async move {
                    let (service, id, now) = *ctx;
                    storage::lock(tx, "action-owner").await?;
                    let plan = db::load_plan(tx, id).await?;
                    production::tick(service, tx, &plan, now).await
                })
            },
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
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
        Err(crate::execution::Fault::Request(crate::Error::Conflict)) => Ok(true),
        Err(error) => Err(error),
    }
}
