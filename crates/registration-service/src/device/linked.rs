//! Parent certificate authority for independent WinDC registration lifecycle.
//! ref: Microsoft declared-configuration-enrollment; sqlx src/transaction.rs.
use super::*;
use crate::database::db;
use sqlx::Row;

/// Create an enrollment request from a real current parent, without a browser grant.
pub async fn request_in(c: &mut sqlx::PgConnection, parent: &DevicePrincipal, id: Uuid, operation: Uuid) -> Result<(), Error> {
    if parent.purpose() != Purpose::Primary || parent.channel() != Channel::Mdm || id.is_nil() || operation.is_nil() { return Err(Error::Forbidden); }
    store::revalidate_management(c, parent).await?;
    let tenant = parent.tenant().to_string();
    let profile: String = sqlx::query_scalar("SELECT windows_profile FROM mdm_access.requests q JOIN mdm_access.registrations r ON(r.tenant_id,r.request_id)=(q.tenant_id,q.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND q.source='mdm.windows'")
        .bind(&tenant).bind(parent.registration()).fetch_one(&mut *c).await.map_err(db)?;
    let expected: i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='windows_declared'")
        .bind(&tenant).bind(parent.device()).fetch_one(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,authority_kind,parent_id,parent_generation,parent_credential,state,expected_generation,expires_at,issuance_operation,source,windows_profile) VALUES($1::uuid,$2,'parent_certificate',$3,$4,$5,'pending',$6,clock_timestamp()+interval '5 minutes',$7,'mdm.windows',$8)")
        .bind(tenant).bind(id).bind(parent.registration()).bind(parent.generation()).bind(parent.credential()).bind(expected).bind(operation).bind(profile).execute(c).await.map_err(db)?;
    Ok(())
}
/// Bind certificate and child registration in the caller's audit transaction; no report source.
#[allow(clippy::too_many_arguments, reason = "explicit parent proof and certificate receipt identities in one borrowed transaction")]
pub async fn bind_in(c: &mut sqlx::PgConnection, parent: &DevicePrincipal, credential: &VerifiedChannelCredential, request: Uuid, ids: [Uuid;3], facts: &mut Vec<rss_mdm_audit_integration::Fact>, retirement: &dyn crate::Retirement) -> Result<RegistrationReceipt, Error> {
    if credential.tenant != parent.tenant() || credential.purpose != Purpose::WindowsDeclared || credential.source != ReportSource::MdmWindows { return Err(Error::Forbidden); }
    store::revalidate_management(c, parent).await?;
    let tenant = parent.tenant().to_string();
    let row = sqlx::query("SELECT expected_generation,issuance_operation FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2 AND authority_kind='parent_certificate' AND parent_id=$3 AND parent_generation=$4 AND parent_credential=$5 AND state='pending' AND expires_at>clock_timestamp() FOR UPDATE")
        .bind(&tenant).bind(request).bind(parent.registration()).bind(parent.generation()).bind(parent.credential()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let current: i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='windows_declared'")
        .bind(&tenant).bind(parent.device()).fetch_one(&mut *c).await.map_err(db)?;
    if current != row.try_get::<i64,_>("expected_generation").map_err(db)? { return Err(Error::Conflict); }
    let old = sqlx::query_scalar::<_, Uuid>("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='windows_declared' AND state='active' FOR UPDATE")
        .bind(&tenant).bind(parent.device()).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(old) = old { crate::lifecycle::retire(c, facts, &tenant, old, "superseded", retirement).await?; }
    let generation = current.checked_add(1).ok_or(Error::Conflict)?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch,parent_id,parent_generation) VALUES($1::uuid,$2,$3,'mdm',$4,$5,'active','windows_declared',$6,$7,$8)")
        .bind(&tenant).bind(ids[0]).bind(parent.device()).bind(generation).bind(request).bind(ids[2]).bind(parent.registration()).bind(parent.generation()).execute(&mut *c).await.map_err(db)?;
    let locator: String = credential.locator.iter().map(|v|format!("{v:02x}")).collect();
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2,$3,'mdm',$4,'active')")
        .bind(&tenant).bind(ids[1]).bind(ids[0]).bind(locator).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(request).execute(c).await.map_err(db)?;
    Ok(RegistrationReceipt { operation_id: row.try_get("issuance_operation").map_err(db)?, request_id: request, device: parent.device().into(), registration: ids[0], generation, channel: Channel::Mdm, credential: ids[1], epoch: ids[2] })
}
/// Publish readiness only after a real authenticated SyncML exchange.
pub async fn ready_in(c: &mut sqlx::PgConnection, p: &DevicePrincipal) -> Result<(), Error> {
    store::revalidate_management(c,p).await?;
    if p.purpose() == Purpose::WindowsDeclared {
        sqlx::query("UPDATE mdm_access.registrations SET ready=true WHERE tenant_id=$1::uuid AND id=$2 AND purpose='windows_declared' AND NOT ready")
            .bind(p.tenant().to_string()).bind(p.registration()).execute(c).await.map_err(db)?;
    }
    Ok(())
}
