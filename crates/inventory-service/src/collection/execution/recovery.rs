//! Durable Collection recovery retains uncertainty until original-attempt evidence arrives.
use super::{CollectionService, model::AgentRun as Run, storage};
use crate::{Error, transaction::Result};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub async fn audit_recovery(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
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
                binding,
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
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("collection-recovery");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::CollectionExecution,
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.plan(run.policy_version);
        audit.target_device(&run.target.device);
        let bytes =
            crate::transaction::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::CollectionExecution,
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
    pub async fn project_action_in(
        tx: &mut PgTransaction<'_>,
        dispatch: &rss_mdm_work_page::relay::Dispatch<'_>,
        store: &rss_mdm_audit_integration::AuditStore,
    ) -> Result<bool> {
        use rss_mdm_audit_integration::operation::OperationOwner;
        let id = dispatch.id;
        store.bind_in(tx).await?;
        if !dispatch.accept_in(tx, "UPDATE mdm_inventory.collection_tasks SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted").await? {
            return Ok(false);
        }
        let audit = rss_mdm_audit_integration::command_transaction::dispatch_audit(
            rss_mdm_audit_integration::StorageProfile::Mdm,
            dispatch.binding,
            OperationOwner::CollectionExecution,
            id,
            "collection-dispatch",
        );
        audit.target(&id.to_string());
        let fact = Fact::business(
            &audit,
            OperationOwner::CollectionExecution,
            &format!("collection:{id}:dispatch"),
            200,
            "success",
            None,
        )?;
        store.append_in(tx, &fact).await?;
        let fingerprint = dispatch.fingerprint;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT public.mdm_dispatch_collection_wake($1,$2)")
                    .bind(id)
                    .bind(fingerprint.as_bytes().as_slice())
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        audit.finalize(None);
        Ok(true)
    }
}
pub async fn recover_one(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    use sqlx::Row;
    service.transactions.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    let (device,channel): (Uuid,String)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT device,channel FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await
    })).await?;
    let device = crate::database::device_id(device)?;
    if channel == "agent" {
        let tenant = tx.tenant_id().to_string();

        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    rss_mdm_registration_service::lifecycle::lock_recovery_in(c, &tenant, &device)
                        .await,
                )
            })
        })
        .await??;
    } else {
        storage::lock_device(tx, &device).await?;
    }
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
        audit_recovery(binding, service, tx, &run, &previous).await?;
    } else if channel == "mdm" {
        let mut run = storage::native_run(tx, id).await?;
        let plan = super::policy::read_in(&service.transactions, tx, run.policy_version).await?;
        let revoked = stale_in(tx, &run.target).await? || !plan.active;
        if revoked || now >= run.deadline {
            if let Some(report) = run.collection_run {
                service
                    .abandon_in(
                        binding,
                        tx,
                        report,
                        if revoked { "revoked" } else { "timeout" },
                    )
                    .await?;
            }
            if (revoked || run.collection_run.is_none())
                && run.delivery != super::model::NativeDelivery::Sent
            {
                run.delivery = super::model::NativeDelivery::Cancelled;
            }
            storage::save_native(&service.transactions, tx, &run).await?;
        } else {
            super::native::advance_in(binding, &service.transactions, tx, &mut run, &plan, now)
                .await?;
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
                let status = super::model::native_terminal_status(true, &reason, &result)
                    .expect("sealed report has a terminal lifecycle status");
                use rss_mdm_webhook_service::{events, model::*};
                let event = Event {
                    event_id: events::identity(run.id, &format!("terminal:{status}")),
                    event_type: EventType::PolicyTerminal,
                    version: 1,
                    occurred_at: row.try_get("sealed_at")?,
                    tenant_id: crate::transaction::stored(Uuid::parse_str(
                        &tx.tenant_id().to_string(),
                    ))?,
                    device_id: run.target.device,
                    data: EventData::Policy {
                        run_id: run.id,
                        policy_version: run.policy_version,
                        device_id: run.target.device,

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
            Box::pin(rss_mdm_registration_service::device::read::inactive_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                target.device,
            ))
        })
        .await?)
}
