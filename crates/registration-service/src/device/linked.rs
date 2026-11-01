//! Parent certificate authority for independent WinDC registration lifecycle.
//! ref: Microsoft declared-configuration-enrollment; sqlx src/transaction.rs.
use super::*;
use crate::database::db;
use sqlx::Row;

/// Create an enrollment request from a real current parent, without a browser grant.
pub async fn request_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    parent: &DevicePrincipal,
    id: Uuid,
    operation: Uuid,
) -> Result<(), Error> {
    if profile != parent.profile() {
        return Err(crate::Error::Forbidden);
    }

    if parent.purpose() != Purpose::Primary
        || parent.channel() != Channel::Mdm
        || id.is_nil()
        || operation.is_nil()
    {
        return Err(Error::Forbidden);
    }
    crate::lifecycle::require_work_in(profile, c, &parent.tenant().to_string(), parent.device())
        .await?;
    store::revalidate_management(profile, c, parent).await?;
    let tenant = parent.tenant().to_string();
    let windows_profile: String =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_linked_request_in_1)
            .bind(&tenant)
            .bind(parent.registration())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    let expected: i64 =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_linked_request_in_2)
            .bind(&tenant)
            .bind(parent.device())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_linked_request_in_3)
        .bind(tenant)
        .bind(id)
        .bind(parent.registration())
        .bind(parent.generation())
        .bind(parent.credential())
        .bind(expected)
        .bind(operation)
        .bind(windows_profile)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
/// Bind certificate and child registration in the caller's audit transaction; no report source.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit parent proof and certificate receipt identities in one borrowed transaction"
)]
pub async fn bind_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    parent: &DevicePrincipal,
    credential: &VerifiedChannelCredential,
    request: Uuid,
    ids: [Uuid; 3],
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    retirement: &dyn crate::Retirement,
) -> Result<RegistrationReceipt, Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    if profile != parent.profile() {
        return Err(crate::Error::Forbidden);
    }

    if credential.tenant != parent.tenant()
        || credential.purpose != Purpose::WindowsDeclared
        || credential.source != ReportSource::MdmWindows
    {
        return Err(Error::Forbidden);
    }
    crate::lifecycle::require_work_in(profile, c, &parent.tenant().to_string(), parent.device())
        .await?;
    store::revalidate_management(profile, c, parent).await?;
    let tenant = parent.tenant().to_string();
    let row = sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_1)
        .bind(&tenant)
        .bind(request)
        .bind(parent.registration())
        .bind(parent.generation())
        .bind(parent.credential())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    let current: i64 =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_linked_bind_in_2)
            .bind(&tenant)
            .bind(parent.device())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if current != row.try_get::<i64, _>("expected_generation").map_err(db)? {
        return Err(Error::Conflict);
    }
    let old =
        sqlx::query_scalar::<_, Uuid>(crate::storage_profile::sql(profile).device_linked_bind_in_3)
            .bind(&tenant)
            .bind(parent.device())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?;
    if let Some(old) = old {
        crate::lifecycle::retire(profile, c, facts, &tenant, old, "superseded", retirement).await?;
    }
    let generation = current.checked_add(1).ok_or(Error::Conflict)?;
    sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_4)
        .bind(&tenant)
        .bind(ids[0])
        .bind(parent.device())
        .bind(generation)
        .bind(request)
        .bind(ids[2])
        .bind(parent.registration())
        .bind(parent.generation())
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let locator: String = credential
        .locator
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_5)
        .bind(&tenant)
        .bind(ids[1])
        .bind(ids[0])
        .bind(locator)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_6)
        .bind(&tenant)
        .bind(request)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    crate::webhook::registration(
        Some(&crate::WebhookEvents),
        c,
        &tenant,
        parent.device(),
        ids[0],
        generation,
        "mdm",
        "active",
    )
    .await?;
    Ok(RegistrationReceipt {
        operation_id: row.try_get("issuance_operation").map_err(db)?,
        request_id: request,
        device: parent.device().into(),
        registration: ids[0],
        generation,
        channel: Channel::Mdm,
        credential: ids[1],
        epoch: ids[2],
    })
}
/// Publish readiness only after a real authenticated SyncML exchange.
pub async fn ready_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<bool, Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    store::revalidate_management(profile, c, p).await?;
    if p.purpose() == Purpose::WindowsDeclared {
        return Ok(
            sqlx::query(crate::storage_profile::sql(profile).device_linked_ready_in_1)
                .bind(p.tenant().to_string())
                .bind(p.registration())
                .execute(c)
                .await
                .map_err(db)?
                .rows_affected()
                == 1,
        );
    }
    Ok(false)
}
