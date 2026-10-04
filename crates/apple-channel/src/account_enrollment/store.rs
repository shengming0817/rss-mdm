use super::*;
use crate::database::db;
use sqlx::{PgConnection, postgres::PgRow};
// A binding is a current control-plane fact, while device status stays in registration.
pub(super) async fn binding(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<PgRow, Error> {
    binding_read(c, tenant, id, true).await
}
pub(super) async fn binding_read(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    lock: bool,
) -> Result<PgRow, Error> {
    let query = "SELECT f.* FROM mdm_apple.account_flows f JOIN mdm_apple.account_organizations o ON(o.tenant_id,o.id,o.revision)=(f.tenant_id,f.organization,f.organization_revision) JOIN mdm_apple.account_bindings b ON(b.tenant_id,b.organization,b.account,b.revision)=(f.tenant_id,f.organization,f.account,f.binding_revision) JOIN mdm_access.requests q ON(q.tenant_id,q.id,q.account_version)=(f.tenant_id,f.enrollment,f.authorization_version) JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE f.tenant_id=$1::uuid AND f.enrollment=$2 AND NOT f.revoked AND o.enabled AND b.enabled AND b.principal::text=g.actor AND b.instance::text=g.instance AND q.authority_kind='apple_account' AND q.state<>'cancelled' AND (q.state='pending' OR EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.state='active')) ";
    let mut query = sqlx::QueryBuilder::new(query);
    if lock {
        query.push(" FOR SHARE OF f,o,b,q,g");
    }
    query
        .build()
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)
}
pub(super) async fn token(c: &mut PgConnection, tenant: &str, token: &str) -> Result<PgRow, Error> {
    if token.len() != 43 {
        return Err(Error::Unauthorized);
    }
    let id:Uuid=sqlx::query_scalar("SELECT enrollment FROM mdm_apple.account_flows WHERE tenant_id=$1::uuid AND token_hash=$2 AND NOT revoked")
        .bind(tenant).bind(token_hash(tenant,token)).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let row = binding(c, tenant, id).await?;
    if row.try_get::<String, _>("token_hash").map_err(db)? != token_hash(tenant, token) {
        return Err(Error::Unauthorized);
    }
    Ok(row)
}
pub(super) struct NewFlow {
    pub id: Uuid,
    pub organization: Uuid,
    pub revision: i64,
    pub target: Uuid,
    pub request_digest: String,
    pub expected_account: Option<String>,
}
pub(super) async fn new_flow(
    c: &mut PgConnection,
    tenant: &str,
    input: NewFlow,
) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2672))")
        .bind(format!("apple-flows:{tenant}"))
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_apple.account_flows WHERE tenant_id=$1::uuid AND expires_at>clock_timestamp() AND NOT revoked").bind(tenant).fetch_one(&mut *c).await.map_err(db)?;
    if count >= 1024 {
        return Err(Error::Unavailable(Failure::Capacity));
    }
    sqlx::query("INSERT INTO mdm_apple.account_flows(tenant_id,id,organization,organization_revision,target_enrollment,request_digest,expected_account,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '300 seconds')")
        .bind(tenant).bind(input.id).bind(input.organization).bind(input.revision).bind(input.target).bind(input.request_digest).bind(input.expected_account).execute(c).await.map_err(db)?;
    Ok(())
}
/// Same transaction protects flow use from organization/account reconfiguration.
pub(super) async fn flow(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<PgRow, Error> {
    sqlx::query("SELECT f.*,o.domain,o.server_uuid,o.signing_key FROM mdm_apple.account_flows f JOIN mdm_apple.account_organizations o ON(o.tenant_id,o.id,o.revision)=(f.tenant_id,f.organization,f.organization_revision) WHERE f.tenant_id=$1::uuid AND f.id=$2 AND o.enabled AND NOT f.revoked AND f.expires_at>clock_timestamp() FOR UPDATE OF o,f")
        .bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?.ok_or(Error::Unauthorized)
}
pub(super) async fn bound_account(
    c: &mut PgConnection,
    tenant: &str,
    organization: Uuid,
    name: &str,
) -> Result<PgRow, Error> {
    sqlx::query("SELECT * FROM mdm_apple.account_bindings WHERE tenant_id=$1::uuid AND organization=$2 AND account=$3 AND enabled FOR UPDATE")
        .bind(tenant).bind(organization).bind(name).fetch_optional(c).await.map_err(db)?.ok_or(Error::Unauthorized)
}
