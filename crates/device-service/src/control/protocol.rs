use super::*;
use crate::control::device::DevicePrincipal;
use serde_json::json;
impl Service {
    pub async fn windows_prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = self.transactions.tenant.to_string();
        let instance = self.transactions.instance.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(crate::control::authorization::lock_shared_on(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    &instance,
                )
                .await)
            })
        })
        .await??;
        actions::run_recovery::lock_device(tx, p.device()).await?;
        crate::control::transaction::prepare_audit_in(
            &self.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await
        .map_err(Into::into)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "the protocol transaction borrows identity, audit and distinct settlement facts"
    )]
    pub async fn windows_before_receipts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        authenticated: bool,
        retirement: rss_mdm_windows_mdm::native::Request,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        if authenticated {
            self.queue_windows_retirement_in(tx, p, retirement, audit)
                .await?;
        }
        settle_dispatch_failures(self, tx, p, audit).await?;
        Ok(())
    }
}
pub async fn settle_one(
    s: &Service,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    complete: bool,
    audit: &RequestAudit,
) -> Result<()> {
    let op = storage::load(tx, &s.transactions.protection, id).await?;
    let command = s.transactions.required_command(tx, &op).await?;
    if command.status().is_terminal() {
        return Ok(());
    }
    let now = storage::now(tx).await?;
    if now >= op.request.deadline
        || !storage::receipt_valid(&s.transactions.protection, tx, &op, now).await?
    {
        return Ok(());
    }
    let tenant = tx.tenant_id();
    let evidence = s.transactions.windows_results.clone();
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
    let result = s.transactions.store.report(tx, &report).await?;
    if result.outcome == dc::Outcome::OutOfOrder {
        return Ok(());
    }
    if (query_complete
        || (values_complete
            && effect_assessment(s.transactions.windows_results.clone(), tx, &op)
                .await?
                .state
                == rss_mdm_windows_mdm::native::verification::EffectState::Verified))
        && !result.command.status().is_terminal()
    {
        report.event = dc::DeviceEvent::Reported(op.request.digest(
            &s.transactions.protection,
            s.transactions.tenant,
            &op.device,
        )?);
        if s.transactions.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    let current = s.transactions.required_command(tx, &op).await?;
    if current.version() != command.version() {
        crate::control::timeline::native_fact_in(
            s,
            tx,
            &op,
            current.status(),
            current.version(),
            audit,
        )
        .await?;
    }
    crate::control::wake::wake_native_in(&s.transactions.reconcile_messaging, tx, &op.device)
        .await?;
    Ok(())
}
pub async fn observation(
    tx: &mut PgTransaction<'_>,
    windows_results: Arc<dyn crate::control::windows_results::Store>,
    apple_results: Arc<dyn apple_facts::AppleResults>,
    op: &storage::Operation,
    command_status: dc::Status,
    native_values: bool,
) -> Result<crate::control::queries::records::NativeObservation> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(
        &mut (
            windows_results,
            apple_results,
            op,
            command_status,
            native_values,
        ),
        move |args, c| {
            Box::pin(async move {
                Ok(observation_on(
                    c,
                    tenant,
                    args.0.clone(),
                    args.1.clone(),
                    args.2,
                    args.3,
                    args.4,
                )
                .await)
            })
        },
    )
    .await?
}

pub async fn observation_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    windows_results: Arc<dyn crate::control::windows_results::Store>,
    apple_results: Arc<dyn apple_facts::AppleResults>,
    op: &storage::Operation,
    command_status: dc::Status,
    native_values: bool,
) -> Result<crate::control::queries::records::NativeObservation> {
    if matches!(op.request.task, Task::Macos { .. }) {
        return super::apple::observation_on(
            c,
            tenant,
            apple_results,
            op,
            command_status,
            native_values,
        )
        .await;
    }
    windows_observations_on(
        c,
        tenant,
        windows_results,
        &[(op, command_status)],
        native_values,
    )
    .await?
    .remove(&op.id)
    .ok_or(Error::Conflict.into())
}
fn read(op: &storage::Operation, values: bool) -> Result<crate::control::windows_results::Read> {
    let Task::Windows { request } = &op.request.task else {
        return Err(Error::Malformed.into());
    };
    let sensitive = op.request.task.permissions()?.iter().any(|p| {
        matches!(
            p,
            crate::control::authorization::Permission::DeviceDiagnostics
                | crate::control::authorization::Permission::SecurityOperate
                | crate::control::authorization::Permission::Credentials
                | crate::control::authorization::Permission::AccountWrite
        )
    });
    Ok(crate::control::windows_results::Read {
        id: op.id,
        registration: op.registration,
        registration_generation: op.registration_generation,
        request: request.clone(),
        values: values && !sensitive,
    })
}
pub(crate) async fn windows_observations_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    store: Arc<dyn crate::control::windows_results::Store>,
    ops: &[(&storage::Operation, dc::Status)],
    native_values: bool,
) -> Result<std::collections::BTreeMap<Uuid, crate::control::queries::records::NativeObservation>> {
    let reads = ops
        .iter()
        .map(|(op, _)| read(op, native_values))
        .collect::<Result<Vec<_>>>()?;
    let mut evidence = store.observations(c, tenant, reads).await?;
    ops.iter()
        .map(|(op, status)| {
            let v = evidence.remove(&op.id).ok_or(Error::Conflict)?;
            Ok((
                op.id,
                crate::control::queries::records::NativeObservation::Windows {
                    receipts: v.receipts,
                    progress: crate::control::queries::records::CommandStatus(*status),
                    effect: v.assessment.state,
                    reason: v.assessment.reason,
                },
            ))
        })
        .collect()
}
async fn effect_assessment(
    store: Arc<dyn crate::control::windows_results::Store>,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<rss_mdm_windows_mdm::native::verification::EffectAssessment> {
    let tenant = tx.tenant_id();
    let input = read(op, false)?;
    let id = op.id;
    let mut evidence = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(store.observations(c, tenant, vec![input]).await) })
        })
        .await??;
    Ok(evidence.remove(&id).ok_or(Error::Conflict)?.assessment)
}

/// A server-side native validation failure cancels dispatch; it is never a device rejection.
pub(super) async fn settle_dispatch_failures(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    audit: &RequestAudit,
) -> Result<()> {
    use rss_mdm_audit_integration::Fact;
    let tenant = tx.tenant_id().to_string();
    let registration = principal.registration();
    let generation = principal.generation();
    let ids = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, Uuid>("SELECT o.id FROM mdm_devices.control_operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.dispatch_failure IS NOT NULL AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, &service.transactions.protection, id).await?;
        let transition = service
            .transactions
            .store
            .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }

        let fact = Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
            &format!("native-dispatch-failure:{id}"),
            200,
            "failed",
            None,
        )?
        .with_details(json!({"operation":id,"failure":op.dispatch_failure}))?;
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
        crate::control::wake::wake_native_in(
            &service.transactions.reconcile_messaging,
            tx,
            &op.device,
        )
        .await?;
    }
    Ok(())
}

impl Service {
    pub async fn windows_received_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        session: u32,
        after: Option<Uuid>,
    ) -> Result<Vec<Uuid>> {
        self.transactions.runtime.validate_transaction(tx)?;
        tx.with_connection_context(
            &mut (self.transactions.windows_results.clone(), p),
            |ctx, c| Box::pin(async move { Ok(ctx.0.received(c, ctx.1, session, after).await) }),
        )
        .await?
        .map_err(Into::into)
    }
}
