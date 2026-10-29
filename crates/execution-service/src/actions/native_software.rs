//! Native protocol operations belong to the original shared software run.
use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::{Error, ExecutionService, Result, storage};
use rss_device_command::Store;
use rss_transactional_messaging_postgres::PgTransaction;
pub async fn advance_run(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &mut db::Run,
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    now: i64,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let operation: Option<String> = tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT d.status FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(tenant).bind(id).fetch_optional(c).await
    })).await?;
    if let Some(status) = operation {
        let tenant = tx.tenant_id().to_string();
        let id = run.id;
        let dispatched = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(crate::agent_install::dispatched_on(c, &tenant, id).await) },
                )
            })
            .await??;
        if !dispatched
            && (run.state.cancellation != Cancellation::None
                || !service.inputs.software_distribution.mdm_enabled
                || run.deadline <= now
                || matches!(
                    status.as_str(),
                    "failed" | "rejected" | "expired" | "cancelled"
                ))
        {
            run.state.execution = Execution::NotStarted;
            run.state.cancellation = Cancellation::Confirmed;
            run.result = Some(super::result::RunResult::NativeSoftware(
                super::result::NativeSoftware::NotStarted { operation: run.id },
            ));
            return Ok(());
        }
        let op = storage::load(tx, &service.protection, run.id).await?;
        let command = service.required_command(tx, &op).await?;
        let observation = crate::protocol::observation(
            tx,
            &service.protection,
            service.apple_results.clone(),
            &op,
            command.status(),
            true,
        )
        .await?;
        let apple_received = matches!(
            &observation,
            crate::queries::records::NativeObservation::Apple {
                facts: rss_mdm_apple_mdm::native::evidence::ReadEvidence::Command { receipts, .. },
                ..
            } if receipts.iter().any(|receipt| {
                use rss_mdm_apple_mdm::native::evidence::{Phase, ReceiptState};
                receipt.accepted && receipt.phase == Phase::Execute
                    && matches!(receipt.state, ReceiptState::Acknowledged | ReceiptState::Error)
            })
        );
        if let crate::queries::records::NativeObservation::Windows { receipts, .. } = observation {
            let latest = receipts
                .iter()
                .filter(|r| {
                    r.phase == crate::AttemptPhase::Observe
                        && r.accepted == Some(true)
                        && r.result_accepted == Some(true)
                        && r.status == Some(200)
                })
                .map(|r| r.ordinal)
                .max();
            if let Some(latest) = latest {
                let value = |suffix: &str| {
                    receipts
                        .iter()
                        .find(|r| {
                            r.ordinal == latest
                                && r.uri.as_deref().is_some_and(|uri| uri.ends_with(suffix))
                                && r.accepted == Some(true)
                                && r.result_accepted == Some(true)
                                && r.status == Some(200)
                        })
                        .and_then(|r| r.value.as_deref())
                };
                let verified = match &op.request.task {
                    crate::Task::Windows {
                        request: rss_mdm_windows_mdm::native::Execution::Msi { job },
                    } => {
                        value("/Status") == Some("70")
                            && value("/Version") == Some(job.version.as_str())
                    }
                    _ => {
                        let actual =
                            serde_json::to_value(&op.request.task).map_err(|_| Error::Malformed)?;
                        policy
                            .assignment
                            .frozen
                            .native_packages
                            .values()
                            .find(|p| {
                                p.task(run.id, &service.protection, service.tenant)
                                    .ok()
                                    .and_then(|t| serde_json::to_value(t).ok())
                                    .as_ref()
                                    == Some(&actual)
                            })
                            .is_some_and(|p| match &p.identity {
                                crate::native_software::Identity::Msix { identity, .. } => {
                                    matches!(value("/IsProvisioned"), Some("1" | "true"))
                                        && value("/Version")
                                            == Some(
                                                identity
                                                    .version
                                                    .map(|v| v.to_string())
                                                    .join(".")
                                                    .as_str(),
                                            )
                                }
                                _ => false,
                            })
                    }
                };
                if verified {
                    if !command.status().is_terminal() {
                        let report = crate::dc::DeviceReport {
                            scope: op.scope,
                            command_id: op.command_id()?,
                            coordinate: op.coordinate,
                            event: crate::dc::DeviceEvent::Reported(op.request.digest(
                                &service.protection,
                                service.tenant,
                                &op.device,
                            )?),
                        };
                        if service.store.report(tx, &report).await?.outcome
                            == crate::dc::Outcome::OutOfOrder
                        {
                            return Err(Error::Conflict.into());
                        }
                    }
                    run.state.result(run.id, true)?;
                    run.result = Some(super::result::RunResult::NativeSoftware(
                        super::result::NativeSoftware::Verified {
                            operation: run.id,
                            effect_observed_at: now
                                .checked_mul(1_000_000)
                                .ok_or(Error::Malformed)?,
                            effect_received_at: super::software::effect_received_at(tx).await?,
                        },
                    ));
                    return Ok(());
                }
            }
        }
        // Protocol acknowledgement does not prove the package's actual installed state.
        if (apple_received
            || matches!(
                status.as_str(),
                "applied" | "failed" | "expired" | "cancelled"
            ))
            && matches!(run.state.execution, Execution::Running | Execution::Unknown)
        {
            run.state.uncertain_result(run.id)?;
            run.result = Some(super::result::RunResult::NativeSoftware(
                super::result::NativeSoftware::Unknown {
                    operation: run.id,
                    protocol: status,
                },
            ));
        }
        return Ok(());
    }
    if run.state.execution != Execution::NotStarted
        || run.state.cancellation != Cancellation::None
        || run.available_at > now
        || run.deadline <= now
        || !service.inputs.software_distribution.mdm_enabled
    {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let accepted=tx.with_connection(move|c|Box::pin(async move { sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await })).await?;
    if !accepted {
        return Ok(());
    }
    let crate::native_software::TargetAdmission::Eligible(crate::native_software::NativeTarget {
        target,
        platform: p,
        architecture: a,
    }) = crate::native_software::target_admission_in(tx, &run.target.device).await?
    else {
        return Ok(());
    };
    if target.registration != run.target.registration
        || target.generation != run.target.generation
        || !policy
            .assignment
            .authorized_run_in(&service.admission(), tx, &run.target.device, p, a, now)
            .await?
    {
        return Ok(());
    }
    let package = policy
        .assignment
        .frozen
        .native_packages
        .get(&rss_mdm_policy::SoftwareTarget::new(p, a))
        .ok_or(Error::Unsupported)?;
    let input = crate::Create {
        operation_id: run.id,
        input_version: policy.id.to_string(),
        target: crate::NativeTarget::Device,
        task: package.task(run.id, &service.protection, service.tenant)?,
        deadline: run.deadline,
    };
    let authority = crate::authority::ExecutionAuthority::Software {
        origin: run.origin,
        retirement: run.retirement,
        target: rss_mdm_policy::SoftwareTarget::new(p, a),
        tenant: tx.tenant_id().to_string(),
        version: policy.id,
        device: run.target.device.clone(),
        operation: run.id,
        required: vec![crate::authorization::Permission::SoftwareDeploy],
    };
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        tx.tenant_id().to_string(),
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("native-software");
    audit.operation(
        run.id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.plan(policy.id);
    audit.target_device(&run.target.device);
    let fingerprint = crate::protection::fingerprint(
        &service.protection,
        service.tenant,
        &run.target.device,
        "software-install-command/v1",
        &(&input, policy.id),
    )?;
    service
        .queue_authorized_in(
            tx,
            &run.target.device,
            &input,
            authority,
            fingerprint,
            &audit,
        )
        .await?;
    let target = crate::service::target(tx.tenant_id(), &run.target.device);
    service
        .reconcile_messaging
        .wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    audit.finalize(None);
    run.state.claim(run.id, now)?;
    run.state.received(run.id, now)?;
    run.state.start(run.id, now)?;
    Ok(())
}
