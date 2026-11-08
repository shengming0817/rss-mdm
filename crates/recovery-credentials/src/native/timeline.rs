//! Read-only associations in the producer's identity space; parent links are search links.
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identity {
    Operation(Uuid),
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
            "SELECT device,NULL::uuid FROM mdm_recovery_tasks.operations WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ChangeRequest(id) => (
            "SELECT o.device,r.operation FROM mdm_recovery_tasks.requests r JOIN mdm_recovery_tasks.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.actor=$3",
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

pub(crate) fn native_activity(
    op: &crate::native::storage::Operation,
    status: crate::native::dc::Status,
    phase: rss_mdm_audit_integration::activity::ActivityPhase,
) -> rss_mdm_audit_integration::activity::Activity {
    use rss_mdm_audit_integration::activity::*;
    let kind = ActivityKind::Execution;
    let mut activity = Activity::new(kind, phase);
    activity.target = Some(ActivityTarget {
        device: op.device.clone(),
    });
    activity.links.operation = Some(op.id);
    activity.origin = ActivityOrigin::Human;
    activity.execution = Some(match status {
        crate::native::dc::Status::Queued => ActivityExecution::Queued,
        crate::native::dc::Status::Published => ActivityExecution::Published,
        crate::native::dc::Status::Received => ActivityExecution::Received,
        crate::native::dc::Status::Applied => ActivityExecution::Applied,
        crate::native::dc::Status::Rejected => ActivityExecution::Rejected,
        crate::native::dc::Status::TimedOut => ActivityExecution::TimedOut,
        crate::native::dc::Status::Superseded => ActivityExecution::Superseded,
        crate::native::dc::Status::Cancelled => ActivityExecution::Cancelled,
    });
    activity.delivery = Some(match status {
        crate::native::dc::Status::Queued => ActivityDelivery::Queued,
        crate::native::dc::Status::Published => ActivityDelivery::Dispatched,
        crate::native::dc::Status::Received
        | crate::native::dc::Status::Applied
        | crate::native::dc::Status::Rejected => ActivityDelivery::Received,
        _ => ActivityDelivery::Unknown,
    });
    activity
}

pub(crate) async fn native_fact_in(
    service: &super::Service,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    op: &super::storage::Operation,
    status: super::dc::Status,
    version: impl std::fmt::Display,
    audit: &rss_mdm_audit_integration::RequestAudit,
) -> super::Result<()> {
    let activity = native_activity(
        op,
        status,
        rss_mdm_audit_integration::activity::ActivityPhase::Result,
    );
    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        rss_mdm_audit_integration::operation::OperationOwner::RecoveryCommand,
        &format!("recovery-native:{}:receipt:{version}", op.id),
        200,
        "success",
        None,
    )?
    .with_activity(&activity)?;
    service
        .transactions
        .audit_store
        .append_in(tx, &fact)
        .await?;
    Ok(())
}
