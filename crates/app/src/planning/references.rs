use crate::transaction::Result;
use rss_transactional_messaging_postgres::PgTransaction;
pub(crate) async fn count_in(
    tx: &mut PgTransaction<'_>,
    resource: &str,
    version: &str,
) -> Result<u64> {
    let tenant = tx.tenant_id().to_string();
    let resource = resource.to_owned();
    let version = version.to_owned();
    let count:i64=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_planning.resource_references WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3)+(SELECT count(*) FROM mdm_planning.remote_operations WHERE tenant_id=$1::uuid AND resource=$2 AND resource_version=$3)+(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND resource=$2 AND resource_version=$3)").bind(tenant).bind(resource).bind(version).fetch_one(c).await})).await?;
    Ok(count as u64)
}
