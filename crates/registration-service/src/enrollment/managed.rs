//! A native install authorizes one independent Agent enrollment in the caller's transaction.
use crate::{
    Error,
    database::db,
    device::{BindRegistration, DevicePrincipal, RegistrationReceipt, VerifiedChannelCredential},
};
use rss_mdm_authorization_service::{Permission, UserGrant};
use rss_mdm_inventory::ReportSource;
use sqlx::PgConnection;
use uuid::Uuid;
/// Sealed enrollment admission. Only live native source and actual Enrollment grants construct it.
pub struct Authority {
    principal: DevicePrincipal,
    installation: Uuid,
    deadline: i64,
}
impl Authority {
    pub fn principal(&self) -> &DevicePrincipal {
        &self.principal
    }
    pub fn installation(&self) -> Uuid {
        self.installation
    }
}
pub async fn authorize_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    source: ReportSource,
    installation: Uuid,
    deadline: i64,
    grant: &UserGrant,
) -> Result<Authority, Error> {
    if source == ReportSource::AgentBuiltin || installation.is_nil() {
        return Err(Error::Forbidden);
    }
    crate::device::store::revalidate_source(c, p, source).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if now >= deadline || !grant.valid(c, Permission::Enrollment, now).await? {
        return Err(Error::Forbidden);
    }
    Ok(Authority {
        principal: p.clone(),
        installation,
        deadline,
    })
}
pub async fn bind_in(
    c: &mut PgConnection,
    authority: Authority,
    credential: &VerifiedChannelCredential,
    operation: Uuid,
) -> Result<RegistrationReceipt, Error> {
    let tenant = authority.principal.tenant().to_string();
    let actor = format!("device:{}", authority.principal.registration());
    let id = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let device = Uuid::new_v4().to_string();
    // The short-lived grant is created and consumed atomically; it is never an exchangeable bearer.
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) VALUES($1::uuid,$2,$3,'native-mdm',$4,'enrollment','consumed',statement_timestamp(),least(to_timestamp($5),statement_timestamp()+interval '5 minutes'))")
        .bind(&tenant).bind(grant).bind(actor).bind(&device).bind(authority.deadline as f64).execute(&mut *c).await.map_err(db)?;
    let n=sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,state,expected_generation,expires_at,issuance_operation,source,authority_kind) VALUES($1::uuid,$2,$3,'pending',0,least(to_timestamp($4),clock_timestamp()+interval '5 minutes'),$5,'agent.builtin','managed_installation') ON CONFLICT DO NOTHING")
        .bind(&tenant).bind(id).bind(grant).bind(authority.deadline as f64).bind(authority.installation).execute(&mut *c).await.map_err(db)?.rows_affected();
    if n != 1 {
        return Err(Error::Conflict);
    }
    let receipt = crate::device::store::bind_authorized_in(
        c,
        &tenant,
        credential,
        &BindRegistration {
            operation_id: operation,
            request_id: id,
            expected_generation: 0,
            source: ReportSource::AgentBuiltin,
        },
        device,
        [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
        &mut vec![],
        None,
    )
    .await?;
    sqlx::query("UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2 AND state='pending'").bind(tenant).bind(id).execute(c).await.map_err(db)?;
    Ok(receipt)
}
