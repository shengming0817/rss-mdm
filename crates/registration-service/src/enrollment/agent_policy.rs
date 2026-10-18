//! A started Agent enrollment task authorizes one short native handoff.
use super::*;
use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_authorization_service::{OperationAuthority, Permission};
use sqlx::{PgConnection, Row};
pub struct Create<'a> {
    pub principal: &'a DevicePrincipal,
    pub task: Uuid,
    pub attempt: Uuid,
    pub operation: Uuid,
    pub password: &'a Password,
    pub authority: &'a OperationAuthority,
    pub source: ReportSource,
    pub deadline: i64,
}
pub async fn create_in(c: &mut PgConnection, input: Create<'_>) -> Result<(Receipt, bool), Error> {
    let p = input.principal;
    crate::admission::lock_in(c, &p.tenant().to_string()).await?;
    crate::device::store::revalidate_source(c, p, ReportSource::AgentBuiltin).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if input.source == ReportSource::AgentBuiltin
        || input.task.is_nil()
        || input.operation.is_nil()
        || input.attempt.is_nil()
        || input.deadline <= now
        || !input
            .authority
            .valid(c, Permission::Enrollment, now)
            .await?
    {
        return Err(Error::Forbidden);
    }
    let tenant = p.tenant().to_string();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2636))")
        .bind(format!("{tenant}:{}", input.task))
        .execute(&mut *c)
        .await
        .map_err(db)?;
    if let Some(row)=sqlx::query("SELECT l.*,g.device,r.state,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.source FROM mdm_access.agent_native_enrollments l JOIN mdm_access.requests r ON(r.tenant_id,r.id)=(l.tenant_id,l.request) JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE l.tenant_id=$1::uuid AND l.task=$2")
        .bind(&tenant).bind(input.task).fetch_optional(&mut *c).await.map_err(db)? {
        let device:String=row.try_get("device").map_err(db)?;
        let hash=digest(&(input.operation,input.attempt,p.registration(),p.generation(),input.source,input.password.digest(&tenant,&device)?));
        if row.try_get::<String,_>("request_digest").map_err(db)?!=hash {return Err(Error::Conflict);}
        return Ok((Receipt {operation_id:input.operation,enrollment_id:row.try_get("request").map_err(db)?,status:row.try_get("state").map_err(db)?,expires_at:row.try_get("expiry").map_err(db)?,registration:None,source:input.source},true));
    }
    crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::source(input.source))
        .await?;
    let device = Uuid::new_v4().to_string();
    let id = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let deadline = input.deadline.min(now + 300);
    let password = input.password.digest(&tenant, &device)?;
    let hash = digest(&(
        input.operation,
        input.attempt,
        p.registration(),
        p.generation(),
        input.source,
        &password,
    ));
    let actor = input.authority.actor();
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,'enrollment','consumed',clock_timestamp(),to_timestamp($6))")
        .bind(&tenant).bind(grant).bind(actor.subject()).bind(actor.instance_id()).bind(&device).bind(deadline as f64).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,state,source,expected_generation,password_digest,password_version,expires_at,issuance_operation,windows_profile,self_service,authority_kind) VALUES($1::uuid,$2,$3,'pending',$4,0,$5,1,to_timestamp($6),$7,$8,false,'agent_policy')")
        .bind(&tenant).bind(id).bind(grant).bind(input.source.as_str()).bind(password).bind(deadline as f64).bind(Uuid::new_v4()).bind(if input.source==ReportSource::MdmWindows {Some("Full")} else {None}).execute(&mut *c).await.map_err(db)?;
    sqlx::query(
        "INSERT INTO mdm_access.agent_native_enrollments VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(&tenant)
    .bind(input.task)
    .bind(input.attempt)
    .bind(input.operation)
    .bind(p.registration())
    .bind(p.generation())
    .bind(id)
    .bind(hash)
    .bind(serde_json::to_value(input.authority).map_err(|_| Error::Malformed)?)
    .execute(c)
    .await
    .map_err(db)?;
    Ok((
        Receipt {
            operation_id: input.operation,
            enrollment_id: id,
            status: "pending".into(),
            expires_at: deadline,
            registration: None,
            source: input.source,
        },
        false,
    ))
}

/// The originating Agent must still hold a currently trusted, unrevoked credential.
pub async fn current_source_in(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    request: Uuid,
) -> Result<(), Error> {
    let fingerprint: Vec<u8> = sqlx::query_scalar("SELECT decode(k.locator,'hex') FROM mdm_access.agent_native_enrollments l JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(l.tenant_id,l.source_registration,l.source_generation) JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE l.tenant_id=$1::uuid AND l.request=$2 AND r.state='active' AND r.channel='agent' AND k.state='active' AND k.channel='agent'")
        .bind(tenant.to_string()).bind(request).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Forbidden)?;
    rss_mdm_pki_service::registry::current_certificate_in(
        c,
        tenant,
        rss_mdm_agent_wire::pki::Purpose::Agent,
        &fingerprint,
    )
    .await
    .map_err(|e| match e {
        rss_mdm_pki_service::Error::Storage => Error::Storage,
        _ => Error::Forbidden,
    })
}
