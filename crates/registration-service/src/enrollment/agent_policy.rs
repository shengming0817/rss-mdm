//! A started Agent enrollment task authorizes one short native handoff.
use super::*;
use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_authorization_service::Actor;
use sqlx::{PgConnection, Row};
pub struct Create<'a> {
    pub principal: &'a DevicePrincipal,
    pub task: Uuid,
    pub attempt: Uuid,
    pub operation: Uuid,
    pub password: &'a Password,
    pub actor: &'a Actor,
    pub source: ReportSource,
    pub deadline: i64,
}
pub async fn create_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    input: Create<'_>,
) -> Result<(Receipt, bool), Error> {
    let p = input.principal;
    crate::admission::lock_in(profile, c, &p.tenant().to_string()).await?;
    crate::device::store::revalidate_source(profile, c, p, ReportSource::AgentBuiltin).await?;
    crate::lifecycle::require_work_in(profile, c, &p.tenant().to_string(), p.device()).await?;
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
        || input.actor.tenant_id() != p.tenant().to_string()
    {
        return Err(Error::Forbidden);
    }
    let tenant = p.tenant().to_string();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2636))")
        .bind(format!("{tenant}:{}", input.task))
        .execute(&mut *c)
        .await
        .map_err(db)?;
    if let Some(row) =
        sqlx::query(crate::storage_profile::sql(profile).enrollment_agent_policy_create_in_1)
            .bind(&tenant)
            .bind(input.task)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
    {
        let device: String = row.try_get("device").map_err(db)?;
        let hash = digest(&(
            input.operation,
            input.attempt,
            p.registration(),
            p.generation(),
            input.source,
            input.password.digest(&tenant, &device)?,
        ));
        if row.try_get::<String, _>("request_digest").map_err(db)? != hash {
            return Err(Error::Conflict);
        }
        return Ok((
            Receipt {
                operation_id: input.operation,
                enrollment_id: row.try_get("request").map_err(db)?,
                status: row.try_get("state").map_err(db)?,
                expires_at: row.try_get("expiry").map_err(db)?,
                registration: None,
                source: input.source,
            },
            true,
        ));
    }
    crate::admission::require_new_in(
        profile,
        c,
        &tenant,
        crate::quotas::Channel::source(input.source),
    )
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
    let actor = input.actor;
    sqlx::query(crate::storage_profile::sql(profile).enrollment_agent_policy_create_in_2)
        .bind(&tenant)
        .bind(grant)
        .bind(actor.subject())
        .bind(actor.instance_id())
        .bind(&device)
        .bind(deadline as f64)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).enrollment_agent_policy_create_in_3)
        .bind(&tenant)
        .bind(id)
        .bind(grant)
        .bind(input.source.as_str())
        .bind(password)
        .bind(deadline as f64)
        .bind(Uuid::new_v4())
        .bind(if input.source == ReportSource::MdmWindows {
            Some("Full")
        } else {
            None
        })
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).enrollment_agent_policy_create_in_4)
        .bind(&tenant)
        .bind(input.task)
        .bind(input.attempt)
        .bind(input.operation)
        .bind(p.registration())
        .bind(p.generation())
        .bind(id)
        .bind(hash)
        .bind(serde_json::to_value(input.actor).map_err(|_| Error::Malformed)?)
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
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    request: Uuid,
) -> Result<(), Error> {
    let fingerprint: Vec<u8> = sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_agent_policy_current_source_in_1,
    )
    .bind(tenant.to_string())
    .bind(request)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .ok_or(Error::Forbidden)?;
    rss_mdm_pki_service::registry::current_certificate_in(
        profile,
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
