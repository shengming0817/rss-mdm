//! Read-only associations in the producer's identity space; parent links are search links.
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identity {
    Operation(Uuid),
    ActionRun(Uuid),
    ChangeRequest(Uuid),
}
/// Resolve a single fact's device and immutable operation links, never parent target sets.
pub async fn association_in(
    c: &mut PgConnection,
    tenant: &str,
    actor: &str,
    identity: Identity,
) -> Result<Option<(String, Option<Uuid>)>, sqlx::Error> {
    let (statement, id) = match identity {
        Identity::Operation(id) => (
            "SELECT device,NULL::uuid FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ActionRun(id) => (
            "SELECT device,NULL::uuid FROM mdm_devices.unmanage_runs WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ChangeRequest(id) => (
            "SELECT o.device,r.operation FROM mdm_devices.control_requests r JOIN mdm_devices.control_operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.actor=$3",
            id,
        ),
    };
    let query = sqlx::query_as(statement).bind(tenant).bind(id);
    if matches!(identity, Identity::ChangeRequest(_)) {
        query.bind(actor).fetch_optional(c).await
    } else {
        query.fetch_optional(c).await
    }
}

/// Record native progress and readback evidence in the receipt's original transaction.
pub(crate) async fn native_fact_in(
    service: &crate::control::Service,
    tx: &mut crate::control::PgTransaction<'_>,
    op: &crate::control::storage::Operation,
    status: crate::control::dc::Status,
    version: impl std::fmt::Display,
    audit: &crate::control::RequestAudit,
) -> crate::control::Result<()> {
    use crate::control::queries::records::NativeObservation as O;
    use rss_mdm_audit_integration::{Fact, activity::*};
    let mut activity = native_activity(
        op,
        status,
        if status == crate::control::dc::Status::Received {
            ActivityPhase::Received
        } else {
            ActivityPhase::Result
        },
    );
    let observation = crate::control::protocol::observation(
        tx,
        service.transactions.windows_results.clone(),
        service.transactions.apple_results.clone(),
        op,
        status,
        false,
    )
    .await?;
    activity.effect = Some(match observation {
        O::Windows { effect, .. } => match effect {
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
        O::Apple {
            effect_confirmed: true,
            ..
        } => ActivityEffect::Verified,
        O::Apple {
            effect_confirmed: false,
            ..
        } => ActivityEffect::Unknown,
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
    service
        .transactions
        .audit_store
        .append_in(tx, &fact)
        .await?;
    Ok(())
}

pub(crate) fn native_activity(
    op: &crate::control::storage::Operation,
    status: crate::control::dc::Status,
    phase: rss_mdm_audit_integration::activity::ActivityPhase,
) -> rss_mdm_audit_integration::activity::Activity {
    use crate::control::authority::Authority as A;
    use rss_mdm_audit_integration::activity::*;
    let kind = ActivityKind::Execution;
    let mut activity = Activity::new(kind, phase);
    activity.target = Some(ActivityTarget {
        device: op.device.clone(),
        registration: op.registration,
        generation: op.registration_generation,
    });
    activity.links.operation = Some(op.id);
    match &op.authority {
        A::Retirement {
            version,
            origin,
            retirement,
            ..
        } => {
            activity.links.version = Some(*version);
            activity.links.retirement = Some(*retirement);
            activity.origin = *origin;
        }
        A::DeviceControl { .. } => activity.origin = ActivityOrigin::Human,
    }
    activity.execution = Some(match status {
        crate::control::dc::Status::Queued => ActivityExecution::Queued,
        crate::control::dc::Status::Published => ActivityExecution::Published,
        crate::control::dc::Status::Received => ActivityExecution::Received,
        crate::control::dc::Status::Applied => ActivityExecution::Applied,
        crate::control::dc::Status::Rejected => ActivityExecution::Rejected,
        crate::control::dc::Status::TimedOut => ActivityExecution::TimedOut,
        crate::control::dc::Status::Superseded => ActivityExecution::Superseded,
        crate::control::dc::Status::Cancelled => ActivityExecution::Cancelled,
    });
    activity.delivery = Some(match status {
        crate::control::dc::Status::Queued => ActivityDelivery::Queued,
        crate::control::dc::Status::Published => ActivityDelivery::Dispatched,
        crate::control::dc::Status::Received
        | crate::control::dc::Status::Applied
        | crate::control::dc::Status::Rejected => ActivityDelivery::Received,
        _ => ActivityDelivery::Unknown,
    });
    activity
}
