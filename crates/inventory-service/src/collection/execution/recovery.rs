//! Durable Collection recovery retains uncertainty until original-attempt evidence arrives.
use super::{CollectionService, model::AgentRun as Run, storage};
use crate::{Error, transaction::Result};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub async fn audit_recovery(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    run: &Run,
    previous: &rss_mdm_task_state::RunState,
) -> Result<()> {
    if (run.state.cancellation != Cancellation::None || run.state.execution == Execution::Unknown)
        && let Some(attempt) = run.state.attempt()
    {
        service
            .abandon_in(
                tx,
                attempt,
                if run.state.cancellation != Cancellation::None {
                    "revoked"
                } else {
                    "timeout"
                },
            )
            .await?;
    }
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            tx.tenant_id().to_string(),
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("collection-recovery");
        audit.operation(
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.plan(run.policy_version);
        audit.target_device(&run.target.device);
        audit.registration(run.target.registration);
        let bytes =
            crate::transaction::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            &format!(
                "collection:{}:recover:{:x}",
                run.id,
                sha2::Sha256::digest(&bytes)
            ),
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"before":previous,"after":run.state}))?
        .with_activity(&super::activity::run(
            run,
            rss_mdm_audit_integration::activity::ActivityPhase::Reconciled,
        ))?;
        audit.finalize(None);
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
    }
    Ok(())
}

impl CollectionService {
    pub async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.transactions.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.operation(
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("collection-dispatch");
        audit.target(&id.to_string());
        let result = crate::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move {
            let (service,id,fingerprint,audit)=ctx;
            service.transactions.audit_store.prepare_in(tx,audit,&[]).await?;
            let tenant=tx.tenant_id().to_string();let id=*id;let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move {
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_inventory.collection_tasks SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Unavailable(crate::Failure::PlanningStorage))?;
            if old { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            else { service.transactions.audit_store.append_in(tx,&Fact::business(audit,&format!("collection:{id}:dispatch"),200,"success",None)?).await?; }
            super::wake::run_in(&service.transactions.reconcile_messaging,tx,id).await?;
            Ok(())
        }),crate::transaction::TransactionOwner::Collections).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
pub async fn recover_one(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    use sqlx::Row;
    service.transactions.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    let (device,channel): (String,String)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT device,channel FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await
    })).await?;
    storage::lock_device(tx, &device).await?;
    let now = storage::now(tx).await?;
    if channel == "agent" {
        let mut run = storage::load_run(tx, id).await?;
        let plan = super::policy::read_in(&service.transactions, tx, run.policy_version).await?;
        let previous = run.state.clone();
        if stale_in(tx, &run.target).await? || !plan.active {
            run.state.cancel();
        }
        run.state.expire(now);
        storage::save_run(&service.transactions, tx, &run).await?;
        audit_recovery(service, tx, &run, &previous).await?;
    } else if channel == "mdm" {
        let mut run = storage::native_run(tx, id).await?;
        let plan = super::policy::read_in(&service.transactions, tx, run.policy_version).await?;
        let revoked = stale_in(tx, &run.target).await? || !plan.active;
        if revoked || now >= run.deadline {
            if let Some(report) = run.collection_run {
                service
                    .abandon_in(tx, report, if revoked { "revoked" } else { "timeout" })
                    .await?;
            }
            if (revoked || run.collection_run.is_none())
                && run.delivery != super::model::NativeDelivery::Sent
            {
                run.delivery = super::model::NativeDelivery::Cancelled;
            }
            storage::save_native(&service.transactions, tx, &run).await?;
        } else {
            super::native::advance_in(&service.transactions, tx, &mut run, &plan, now).await?;
        }
        if let Some(report) = run.collection_run {
            let tenant = tx.tenant_id().to_string();
            let terminal=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("SELECT result,reason,sealed_at FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NOT NULL").bind(tenant).bind(report).fetch_optional(c).await
            })).await?;
            if let Some(row) = terminal {
                // A report is the only terminal authority; this event adds no second result state.
                let result: String = row.try_get("result")?;
                let reason: String = row.try_get("reason")?;
                let status = if reason == "complete" {
                    if result == "failed" {
                        "failed"
                    } else {
                        "succeeded"
                    }
                } else if reason == "timeout" {
                    // Native report deadlines are final; Script execution uncertainty is not.
                    "expired"
                } else {
                    "cancelled"
                };
                use rss_mdm_webhook_service::{events, model::*};
                let event = Event {
                    event_id: events::identity(run.id, &format!("terminal:{status}")),
                    event_type: EventType::PolicyTerminal,
                    version: 1,
                    occurred_at: row.try_get("sealed_at")?,
                    tenant_id: crate::transaction::stored(Uuid::parse_str(
                        &tx.tenant_id().to_string(),
                    ))?,
                    device_id: run.target.device.clone(),
                    data: EventData::Policy {
                        run_id: run.id,
                        policy_version: run.policy_version,
                        registration_id: run.target.registration,
                        generation: run.target.generation,
                        status: status.into(),
                    },
                };
                events::emit_in(tx, event)
                    .await
                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                // Completion means the report-derived event and its outbox entry committed.
                // Keep this delivery receipt separate from the report's terminal authority.
                let tenant = tx.tenant_id().to_string();
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("UPDATE mdm_inventory.collection_tasks SET terminal_notified=true WHERE tenant_id=$1::uuid AND id=$2 AND channel='mdm' AND collection_run=$3 AND NOT terminal_notified")
                        .bind(tenant).bind(id).bind(report).execute(c).await?;
                    Ok(())
                })).await?;
            }
        }
    } else {
        return Err(Error::Unavailable(crate::Failure::PlanningStorage).into());
    }
    Ok(())
}
async fn stale_in(tx: &mut PgTransaction<'_>, target: &super::model::Target) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(
                rss_mdm_registration_service::device::read::stale_registration_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    tenant,
                    target.registration,
                    target.device,
                    target.generation,
                ),
            )
        })
        .await?)
}
