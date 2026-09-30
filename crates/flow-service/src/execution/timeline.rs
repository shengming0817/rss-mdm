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
            "SELECT device,remote_operation FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2",
            id,
        ),
        Identity::ActionRun(id) => (
            "SELECT device,remote_operation FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
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
