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
            "SELECT device,NULL::uuid FROM mdm_registration_tasks.operations WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ChangeRequest(id) => (
            "SELECT o.device,r.operation FROM mdm_registration_tasks.requests r JOIN mdm_registration_tasks.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.actor=$3",
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
    op: &crate::installation::storage::Operation,
    status: crate::installation::dc::Status,
    phase: rss_mdm_audit_integration::activity::ActivityPhase,
) -> rss_mdm_audit_integration::activity::Activity {
    use rss_mdm_audit_integration::activity::*;
    let kind = ActivityKind::Execution;
    let mut activity = Activity::new(kind, phase);
    activity.target = Some(ActivityTarget {
        device: op.device.clone(),
        registration: op.registration,
        generation: op.registration_generation,
    });
    activity.links.operation = Some(op.id);
    let installation = op.authority.installation();
    activity.links.policy = Some(installation.policy);
    activity.links.version = Some(installation.version);
    activity.links.operations.push(ActivityOperation::Native {
        id: installation.id,
    });
    activity.origin = op.authority.installation().origin;
    activity.execution = Some(match status {
        crate::installation::dc::Status::Queued => ActivityExecution::Queued,
        crate::installation::dc::Status::Published => ActivityExecution::Published,
        crate::installation::dc::Status::Received => ActivityExecution::Received,
        crate::installation::dc::Status::Applied => ActivityExecution::Applied,
        crate::installation::dc::Status::Rejected => ActivityExecution::Rejected,
        crate::installation::dc::Status::TimedOut => ActivityExecution::TimedOut,
        crate::installation::dc::Status::Superseded => ActivityExecution::Superseded,
        crate::installation::dc::Status::Cancelled => ActivityExecution::Cancelled,
    });
    activity.delivery = Some(match status {
        crate::installation::dc::Status::Queued => ActivityDelivery::Queued,
        crate::installation::dc::Status::Published => ActivityDelivery::Dispatched,
        crate::installation::dc::Status::Received
        | crate::installation::dc::Status::Applied
        | crate::installation::dc::Status::Rejected => ActivityDelivery::Received,
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
        rss_mdm_audit_integration::operation::OperationOwner::Installation,
        &format!("registration-native:{}:receipt:{version}", op.id),
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
