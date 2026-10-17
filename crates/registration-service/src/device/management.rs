//! Purpose-bound management authentication, independent of observation report sources.
//! ref: Microsoft declared-configuration-enrollment; sqlx src/transaction.rs.
use super::*;
use crate::database::db;
use sqlx::Row;

/// Mutating consumers retain the channel fence through their transaction.
pub(super) async fn authenticate(
    c: &mut sqlx::PgConnection,
    credential: &VerifiedChannelCredential,
) -> Result<DevicePrincipal, Error> {
    let principal = read(c, credential).await?;
    revalidate(c, &principal).await?;
    Ok(principal)
}

/// Read identity from the caller's consistent snapshot without joining a writer queue.
/// A principal is descriptive; each consuming mutation must revalidate under its fence.
pub(super) async fn read(
    c: &mut sqlx::PgConnection,
    credential: &VerifiedChannelCredential,
) -> Result<DevicePrincipal, Error> {
    let tenant = credential.tenant.to_string();
    let locator: String = credential
        .locator
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    let row = sqlx::query("SELECT r.id,r.device,r.generation,r.purpose,r.epoch,r.parent_id,r.parent_generation,q.windows_profile,k.id AS credential FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.channel=$2 AND r.purpose=$3 AND r.state='active' AND q.source=$4 AND k.channel=$2 AND k.state='active' AND k.locator=$5")
        .bind(&tenant).bind(credential.channel.as_str()).bind(credential.purpose.as_str()).bind(credential.source.as_str()).bind(locator)
        .fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let registration: Uuid = row.try_get("id").map_err(db)?;
    let parent = row
        .try_get::<Option<Uuid>, _>("parent_id")
        .map_err(db)?
        .zip(
            row.try_get::<Option<i64>, _>("parent_generation")
                .map_err(db)?,
        );
    let p = DevicePrincipal {
        tenant: credential.tenant,
        device: row.try_get("device").map_err(db)?,
        registration,
        generation: row.try_get("generation").map_err(db)?,
        channel: credential.channel,
        credential: row.try_get("credential").map_err(db)?,
        purpose: Purpose::parse(&row.try_get::<String, _>("purpose").map_err(db)?)?,
        epoch: row.try_get("epoch").map_err(db)?,
        parent,
        user_context: (row
            .try_get::<Option<String>, _>("windows_profile")
            .map_err(db)?
            .as_deref()
            == Some("Full"))
        .then_some(parent.map_or(registration, |p| p.0)),
    };
    validate(c, &p).await?;
    Ok(p)
}
pub(super) async fn revalidate(
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<(), Error> {
    let tenant = p.tenant().to_string();
    store::lock_channel(c, &tenant, p.device(), p.channel()).await?;
    validate(c, p).await
}

async fn validate(c: &mut sqlx::PgConnection, p: &DevicePrincipal) -> Result<(), Error> {
    let tenant = p.tenant().to_string();
    if let Some((parent, generation)) = p.parent() {
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.generation=$3 AND r.device=$4 AND r.purpose='primary' AND r.state='active' AND q.source='mdm.windows' AND EXISTS(SELECT 1 FROM mdm_access.credentials k WHERE k.tenant_id=r.tenant_id AND k.registration=r.id AND k.state='active'))")
            .bind(&tenant).bind(parent).bind(generation).bind(p.device()).fetch_one(&mut *c).await.map_err(db)?;
        if !live {
            return Err(Error::Unauthorized);
        }
    }
    if p.channel() == Channel::Agent {
        let row=sqlx::query("SELECT k.state,r.state AS registration_state,i.not_after FROM mdm_access.credentials k JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(k.tenant_id,k.registration) JOIN mdm_access.agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE k.tenant_id=$1::uuid AND k.id=$2")
            .bind(p.tenant().to_string()).bind(p.credential()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
        use rss_mdm_agent_wire::enroll::ErrorCode as C;
        match row.try_get::<String, _>("state").map_err(db)?.as_str() {
            "revoked" => return Err(Error::Agent(C::CredentialRevoked)),
            "superseded" => return Err(Error::Agent(C::CredentialRetired)),
            _ => {}
        }
        if row.try_get::<String, _>("registration_state").map_err(db)? != "active" {
            return Err(Error::Agent(C::CredentialRevoked));
        }
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        if row.try_get::<i64, _>("not_after").map_err(db)? <= now {
            return Err(Error::Agent(
                rss_mdm_agent_wire::enroll::ErrorCode::CertificateExpired,
            ));
        }
    }
    let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.generation=$3 AND r.device=$4 AND r.purpose=$5 AND r.epoch=$6 AND r.state='active' AND k.id=$7 AND k.state='active' AND r.parent_id IS NOT DISTINCT FROM $8 AND r.parent_generation IS NOT DISTINCT FROM $9)")
        .bind(tenant).bind(p.registration()).bind(p.generation()).bind(p.device()).bind(p.purpose().as_str()).bind(p.epoch()).bind(p.credential()).bind(p.parent().map(|p|p.0)).bind(p.parent().map(|p|p.1))
        .fetch_one(&mut *c).await.map_err(db)?;
    if !live {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
