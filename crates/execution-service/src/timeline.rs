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
            "SELECT device,NULL::uuid FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ActionRun(id) => (
            "SELECT device,NULL::uuid FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ChangeRequest(id) => (
            "SELECT o.device,r.operation FROM mdm_commands.requests r JOIN mdm_commands.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.actor=$3",
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
    service: &crate::ExecutionService,
    tx: &mut crate::PgTransaction<'_>,
    op: &crate::storage::Operation,
    status: crate::dc::Status,
    version: impl std::fmt::Display,
    audit: &crate::RequestAudit,
) -> crate::Result<()> {
    use crate::queries::records::NativeObservation as O;
    use rss_mdm_audit_integration::{Fact, activity::*};
    let mut activity = native_activity(
        op,
        status,
        if status == crate::dc::Status::Received {
            ActivityPhase::Received
        } else {
            ActivityPhase::Result
        },
    );
    let observation = crate::protocol::observation(
        tx,
        &service.transactions.protection,
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
        }
        | O::Declarations { .. } => ActivityEffect::Unknown,
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
    op: &crate::storage::Operation,
    status: crate::dc::Status,
    phase: rss_mdm_audit_integration::activity::ActivityPhase,
) -> rss_mdm_audit_integration::activity::Activity {
    use crate::authority::ExecutionAuthority as A;
    use rss_mdm_audit_integration::activity::*;
    let kind = if matches!(&op.authority, A::Policy { .. }) {
        ActivityKind::Configuration
    } else {
        ActivityKind::Execution
    };
    let mut activity = Activity::new(kind, phase);
    activity.target = Some(ActivityTarget {
        device: op.device.clone(),
        registration: op.registration,
        generation: op.registration_generation,
    });
    activity.links.operation = Some(op.id);
    match &op.authority {
        A::Policy {
            policy,
            version,
            origin,
            ..
        }
        | A::AgentInstall {
            policy,
            version,
            origin,
            ..
        } => {
            activity.links.policy = Some(*policy);
            activity.links.version = Some(*version);
            activity.origin = *origin;
        }
        A::Software {
            version,
            origin,
            retirement,
            operation,
            ..
        } => {
            activity.links.version = Some(*version);
            activity.links.task = Some(*operation);
            activity.links.retirement = *retirement;
            activity.origin = *origin;
        }
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
        A::Credential { .. } | A::DeviceControl { .. } => activity.origin = ActivityOrigin::Human,
    }
    activity.execution = Some(match status {
        crate::dc::Status::Queued => ActivityExecution::Queued,
        crate::dc::Status::Published => ActivityExecution::Published,
        crate::dc::Status::Received => ActivityExecution::Received,
        crate::dc::Status::Applied => ActivityExecution::Applied,
        crate::dc::Status::Rejected => ActivityExecution::Rejected,
        crate::dc::Status::TimedOut => ActivityExecution::TimedOut,
        crate::dc::Status::Superseded => ActivityExecution::Superseded,
        crate::dc::Status::Cancelled => ActivityExecution::Cancelled,
    });
    activity.delivery = Some(match status {
        crate::dc::Status::Queued => ActivityDelivery::Queued,
        crate::dc::Status::Published => ActivityDelivery::Dispatched,
        crate::dc::Status::Received | crate::dc::Status::Applied | crate::dc::Status::Rejected => {
            ActivityDelivery::Received
        }
        _ => ActivityDelivery::Unknown,
    });
    activity
}
