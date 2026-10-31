//! Configuration reduces channel facts using the canonical RSS command store.
use super::*;
use rss_mdm_registration_service::DevicePrincipal;
use serde_json::json;
pub async fn settle_windows_in(
    s: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    complete: bool,
    audit: &RequestAudit,
) -> Result<()> {
    let op = storage::load(tx, &s.protection, id).await?;
    let command = s.required_command(tx, &op).await?;
    if command.status().is_terminal() {
        return Ok(());
    }
    let now = storage::now(tx).await?;
    if now >= op.request.deadline || !storage::receipt_valid(&s.protection, tx, &op).await? {
        return Ok(());
    }
    let tenant = tx.tenant_id();
    let evidence = s.channels.clone();
    let decision = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(evidence.settlement(c, tenant, id, complete).await) })
        })
        .await??;
    let (event, query_complete, values_complete) = match decision {
        rss_mdm_windows_mdm::native::receipt::Settlement::Wait => return Ok(()),
        rss_mdm_windows_mdm::native::receipt::Settlement::Reject => {
            (dc::DeviceEvent::Rejected, false, false)
        }
        rss_mdm_windows_mdm::native::receipt::Settlement::Receive {
            query_complete,
            values_complete,
        } => (dc::DeviceEvent::Received, query_complete, values_complete),
    };
    let mut report = dc::DeviceReport {
        scope: op.scope,
        command_id: op.command_id()?,
        coordinate: op.coordinate,
        event,
    };
    let result = s.store.report(tx, &report).await?;
    if result.outcome == dc::Outcome::OutOfOrder {
        return Ok(());
    }
    if (query_complete
        || (values_complete
            && effect_assessment(s.channels.clone(), tx, &op).await?.state
                == rss_mdm_windows_mdm::native::verification::EffectState::Verified))
        && !result.command.status().is_terminal()
    {
        report.event =
            dc::DeviceEvent::Reported(op.request.digest(&s.protection, s.tenant, &op.device)?);
        if s.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    let current = s.required_command(tx, &op).await?;
    if current.version() != command.version() {
        native_fact_in(s, tx, &op, current.status(), current.version(), audit).await?;
    }
    s.wake_devices_in(tx, &[op.device.clone()]).await?;
    Ok(())
}
/// A server-side native validation failure cancels dispatch; it is never a device rejection.
pub async fn settle_dispatch_failures(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    audit: &RequestAudit,
) -> Result<()> {
    use rss_mdm_audit_integration::Fact;
    let tenant = tx.tenant_id().to_string();
    let registration = principal.registration();
    let generation = principal.generation();
    let ids = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, Uuid>("SELECT o.id FROM mdm_planning.configuration_operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.dispatch_failure IS NOT NULL AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, &service.protection, id).await?;
        let transition = service
            .store
            .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }

        let fact = Fact::business(
            audit,
            &format!("native-dispatch-failure:{id}"),
            200,
            "failed",
            None,
        )?
        .with_details(json!({"operation":id,"failure":op.dispatch_failure}))?;
        service.audit_store.append_in(tx, &fact).await?;
        service.wake_devices_in(tx, &[op.device.clone()]).await?;
    }
    Ok(())
}

async fn effect_assessment(
    channels: Arc<dyn channels::Channels>,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<rss_mdm_windows_mdm::native::verification::EffectAssessment> {
    let tenant = tx.tenant_id();
    let id = op.id;
    let registration = op.registration;
    let generation = op.registration_generation;
    let Task::Windows { request } = &op.request.task else {
        return Err(Error::Malformed.into());
    };
    let request = request.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(channels
                    .assessment(c, tenant, id, registration, generation, request)
                    .await)
            })
        })
        .await??)
}
pub(crate) async fn native_fact_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
    status: dc::Status,
    version: impl std::fmt::Display,
    audit: &RequestAudit,
) -> Result<()> {
    use rss_mdm_audit_integration::{Fact, activity::*};
    let mut activity = super::recovery::activity(
        op,
        status,
        if status == dc::Status::Received {
            ActivityPhase::Received
        } else {
            ActivityPhase::Result
        },
    );
    activity.effect = Some(match &op.request.task {
        Task::Windows { .. } => match effect_assessment(service.channels.clone(), tx, op)
            .await?
            .state
        {
            rss_mdm_windows_mdm::native::verification::EffectState::Verified => {
                ActivityEffect::Verified
            }
            rss_mdm_windows_mdm::native::verification::EffectState::Diverged => {
                ActivityEffect::Diverged
            }
            rss_mdm_windows_mdm::native::verification::EffectState::Waiting => {
                ActivityEffect::Waiting
            }
            rss_mdm_windows_mdm::native::verification::EffectState::Unverifiable => {
                ActivityEffect::Unverifiable
            }
        },
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Declarations { .. },
        } => ActivityEffect::Unknown,
        Task::Macos { .. } if status == dc::Status::Applied => ActivityEffect::Verified,
        Task::Macos { .. } => ActivityEffect::Unknown,
    });
    let context = audit.transaction_copy();
    context.operation(
        op.id,
        "command_reconcile",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    context.target_device(&op.device);
    context.registration(op.registration);
    let fact = Fact::business(
        &context,
        &format!("command:{}:receipt:{version}", op.id),
        200,
        "success",
        None,
    )?
    .with_activity(&activity)?;
    context.finalize(None);
    service.audit_store.append_in(tx, &fact).await?;
    let tenant = tx.tenant_id().to_string();
    let id = op.id;
    let version = service.required_command(tx, op).await?.version();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.configuration_operations SET observed_command_version=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(version).execute(c).await?;Ok(())})).await?;
    Ok(())
}
