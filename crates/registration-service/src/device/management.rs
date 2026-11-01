//! Purpose-bound management authentication, independent of observation report sources.
//! ref: Microsoft declared-configuration-enrollment; sqlx src/transaction.rs.
use super::*;
use crate::database::db;
use sqlx::Row;

/// Mutating consumers retain the channel fence through their transaction.
pub(super) async fn authenticate(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    credential: &VerifiedChannelCredential,
) -> Result<DevicePrincipal, Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    let principal = read(profile, c, credential).await?;
    revalidate(profile, c, &principal).await?;
    Ok(principal)
}

/// Read identity from the caller's consistent snapshot without joining a writer queue.
/// A principal is descriptive; each consuming mutation must revalidate under its fence.
pub(super) async fn read(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    credential: &VerifiedChannelCredential,
) -> Result<DevicePrincipal, Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    let tenant = credential.tenant.to_string();
    let locator: String = credential
        .locator
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    let row = sqlx::query(crate::storage_profile::sql(profile).device_management_read_1)
        .bind(&tenant)
        .bind(credential.channel.as_str())
        .bind(credential.purpose.as_str())
        .bind(credential.source.as_str())
        .bind(locator)
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    let registration: Uuid = row.try_get("id").map_err(db)?;
    let parent = row
        .try_get::<Option<Uuid>, _>("parent_id")
        .map_err(db)?
        .zip(
            row.try_get::<Option<i64>, _>("parent_generation")
                .map_err(db)?,
        );
    let p = DevicePrincipal {
        profile,
        tenant: credential.tenant,
        device: row.try_get("device").map_err(db)?,
        registration,
        generation: row.try_get("generation").map_err(db)?,
        kind: RegistrationKind::from_channel(credential.channel),
        installation: installation_in(profile, c).await?,
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
    validate(profile, c, &p).await?;
    Ok(p)
}
pub(super) async fn revalidate(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    let tenant = p.tenant().to_string();
    store::lock_registration(profile, c, &tenant, p.device(), p.kind()).await?;
    validate(profile, c, p).await
}

pub(super) async fn validate(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    let tenant = p.tenant().to_string();
    if let Some((parent, generation)) = p.parent() {
        let live: bool =
            sqlx::query_scalar(crate::storage_profile::sql(profile).device_management_validate_1)
                .bind(&tenant)
                .bind(parent)
                .bind(generation)
                .bind(p.device())
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        if !live {
            return Err(Error::Unauthorized);
        }
    }
    if matches!(
        p.kind(),
        RegistrationKind::Agent | RegistrationKind::DaDevice
    ) {
        let row = sqlx::query(crate::storage_profile::sql(profile).device_management_validate_2)
            .bind(p.tenant().to_string())
            .bind(p.credential())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
            .ok_or(Error::Unauthorized)?;
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
    let live: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_management_validate_3)
            .bind(tenant)
            .bind(p.registration())
            .bind(p.generation())
            .bind(p.device())
            .bind(p.purpose().as_str())
            .bind(p.epoch())
            .bind(p.credential())
            .bind(p.parent().map(|p| p.0))
            .bind(p.parent().map(|p| p.1))
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !live {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
