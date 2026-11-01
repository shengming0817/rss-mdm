use super::*;
use crate::{
    authorization::context::EnrollmentPermission, database::db, device::store::lock_channel,
    operations::Actor, operations::Operation,
};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_inventory::ReportSource;
use sqlx::{Row, postgres::PgRow};

pub fn uuid(row: &PgRow, name: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(&row.try_get::<String, _>(name).map_err(db)?).map_err(|_| Error::Storage)
}
pub fn authorization(row: PgRow) -> Result<Authorization, Error> {
    if row.try_get::<String, _>("authority_kind").map_err(db)? != "password" {
        return Err(Error::Unauthorized);
    }
    Ok(Authorization {
        self_service: row.try_get("self_service").map_err(db)?,
        id: uuid(&row, "id")?,
        device: row.try_get("device").map_err(db)?,
        actor: row.try_get("actor").map_err(db)?,
        instance: row.try_get("instance").map_err(db)?,
        credential_ref: uuid(&row, "credential_ref")?,
        version: row.try_get("password_version").map_err(db)?,
        expected_generation: row.try_get("expected_generation").map_err(db)?,
        operation: uuid(&row, "issuance_operation")?,
        state: row.try_get("state").map_err(db)?,
        windows_profile: WindowsProfile::parse(
            row.try_get::<Option<String>, _>("windows_profile")
                .map_err(db)?
                .as_deref(),
        )?,
        source: ReportSource::parse(&row.try_get::<String, _>("source").map_err(db)?)
            .map_err(|_| Error::Storage)?,
    })
}
pub async fn request(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<PgRow, Error> {
    // Cancelled rows cannot supply enrollment authority.
    sqlx::query(crate::storage_profile::sql(profile).enrollment_store_request_1)
        .bind(tenant)
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::Forbidden)
}

#[allow(
    clippy::too_many_arguments,
    reason = "borrowed audit transaction retains explicit authorization, enrollment identity, source/profile and credential inputs"
)]
pub async fn create_enrollment(
    profile: rss_mdm_install_support::StorageProfile,
    store: &rss_mdm_audit_integration::AuditStore,
    permission: EnrollmentPermission<'_>,
    password: &Password,
    source: ReportSource,
    windows_profile: Option<WindowsProfile>,
    session: Uuid,
    key: Uuid,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    let proof = permission.proof;
    permission.check()?;
    let device = permission.device();
    let password_digest = password.digest(proof.tenant_id(), device)?;
    if source == ReportSource::AgentBuiltin {
        return Err(Error::Malformed);
    }
    if (source == ReportSource::MdmWindows) != windows_profile.is_some() {
        return Err(Error::Malformed);
    }
    let digest = digest(&(
        "enrollment_create.v1",
        device,
        source,
        windows_profile,
        &password_digest,
        permission.self_service(),
    ));
    let op = Operation {
        actor: Actor::from_authorized(proof),
        key,
        digest: &digest,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &budget.source_control(),
            (
                store,
                CreateInputs {
                    permission,
                    password_digest,
                    source,
                    windows_profile,
                    session,
                    key,
                },
                &op,
                audit,
            ),
            |(store, inputs, op, audit), tx| {
                Box::pin(async move {
                    let (receipt, replayed) = tx
                        .with_connection_context(
                            &mut (&*inputs, *op, *audit),
                            |(inputs, op, audit), c| {
                                Box::pin(create_enrollment_on(profile, c, inputs, op, audit))
                            },
                        )
                        .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!(
                            "enrollment_create:{}:{}",
                            inputs.permission.proof.principal_id(),
                            op.key
                        ),
                        200,
                        "success",
                        Some(receipt.enrollment_id),
                    )
                    .map_err(Error::from)?;
                    (if replayed {
                        Ok(())
                    } else {
                        store.append(tx, &fact).await
                    })
                    .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    audit.mark_commit_started();
                    Ok(receipt)
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
struct CreateInputs<'a> {
    permission: EnrollmentPermission<'a>,
    password_digest: String,
    source: ReportSource,
    windows_profile: Option<WindowsProfile>,
    session: Uuid,
    key: Uuid,
}
async fn create_enrollment_on(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    CreateInputs {
        permission,
        password_digest,
        source,
        windows_profile,
        session,
        key,
    }: &CreateInputs<'_>,
    op: &Operation<'_>,
    audit: &RequestAudit,
) -> Result<(Receipt, bool), Error> {
    let proof = permission.proof();
    let device = permission.device();
    let source = *source;
    let session = *session;
    let key = *key;
    crate::admission::lock_in(profile, tx, proof.tenant_id()).await?;
    if let Some(old) = crate::operations::replay(profile, tx, op).await? {
        permission.check()?;
        return serde_json::from_str(&old)
            .map(|receipt| (receipt, true))
            .map_err(|_| Error::Storage);
    }
    crate::admission::require_new_in(
        profile,
        tx,
        proof.tenant_id(),
        crate::quotas::Channel::source(source),
    )
    .await?;
    if permission.self_service() {
        let expected = format!(
            "self:{}:{}:{}",
            proof.instance_id(),
            proof.principal_id(),
            key
        );
        if device != expected {
            return Err(Error::Forbidden);
        }
        crate::quotas::admit_on(
            profile,
            tx,
            proof.tenant_id(),
            proof.instance_id(),
            proof.principal_id(),
            crate::quotas::Channel::source(source),
        )
        .await?;
    }
    if !permission.self_service() {
        crate::lifecycle::authorize_reenrollment_in(profile, tx, proof, device).await?;
    }
    lock_channel(profile, tx, proof.tenant_id(), device, source.channel()).await?;
    crate::lifecycle::require_work_in(profile, tx, proof.tenant_id(), device).await?;
    let generation: i64 = sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_store_create_enrollment_on_1,
    )
    .bind(proof.tenant_id())
    .bind(device)
    .bind(source.channel().as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    let id = Uuid::new_v4();
    let grant = Uuid::new_v4();
    sqlx::query(crate::storage_profile::sql(profile).enrollment_store_create_enrollment_on_2)
        .bind(proof.tenant_id())
        .bind(grant.to_string())
        .bind(proof.principal_id())
        .bind(proof.instance_id())
        .bind(device)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let expires: i64 = sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_store_create_enrollment_on_3,
    )
    .bind(proof.tenant_id())
    .bind(id.to_string())
    .bind(grant.to_string())
    .bind(source.as_str())
    .bind(generation)
    .bind(password_digest)
    .bind(session.to_string())
    .bind(Uuid::new_v4().to_string())
    .bind(windows_profile.map(WindowsProfile::as_str))
    .bind(permission.self_service())
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    if permission.self_service() {
        crate::device::registration_user::initialize_on(profile, tx, device, &proof.user()?)
            .await?;
    }
    let receipt = Receipt {
        operation_id: key,
        enrollment_id: id,
        status: "pending".into(),
        expires_at: expires,
        registration: None,
        source,
    };
    permission.check()?;
    crate::operations::save(
        profile,
        tx,
        op,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((receipt, false))
}
pub async fn enrollment_target(
    profile: rss_mdm_install_support::StorageProfile,
    database: &crate::Store,
    proof: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<String, Error> {
    if profile != proof.profile() {
        return Err(crate::Error::Forbidden);
    }

    let mut tx = database.begin(proof.tenant_id()).await?;
    let row = request(profile, &mut tx, proof.tenant_id(), id).await?;
    same_actor(&row, proof)?;
    row.try_get("device").map_err(db)
}
pub async fn change_enrollment(
    profile: rss_mdm_install_support::StorageProfile,
    store: &rss_mdm_audit_integration::AuditStore,
    permission: EnrollmentPermission<'_>,
    id: Uuid,
    resume: Option<(&Password, Uuid)>,
    key: Uuid,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    let proof = permission.proof;
    permission.check()?;
    let password_digest = resume
        .map(|(p, _)| p.digest(proof.tenant_id(), permission.device()))
        .transpose()?;
    let action = if resume.is_some() {
        "enrollment_resume"
    } else {
        "enrollment_cancel"
    };
    let digest = digest(&("enrollment_change.v1", action, id, &password_digest));
    let op = Operation {
        actor: Actor::from_authorized(proof),
        key,
        digest: &digest,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &budget.source_control(),
            (
                store,
                ChangeInputs {
                    permission,
                    password_digest,
                    id,
                    resume,
                    key,
                },
                &op,
                audit,
            ),
            |(store, inputs, op, audit), tx| {
                Box::pin(async move {
                    let (receipt, replayed) = tx
                        .with_connection_context(
                            &mut (&*inputs, *op, *audit),
                            |(inputs, op, audit), c| {
                                Box::pin(change_enrollment_on(profile, c, inputs, op, audit))
                            },
                        )
                        .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!(
                            "enrollment_change:{}:{}",
                            inputs.permission.proof.principal_id(),
                            op.key
                        ),
                        200,
                        "success",
                        Some(receipt.enrollment_id),
                    )
                    .map_err(Error::from)?;
                    (if replayed {
                        Ok(())
                    } else {
                        store.append(tx, &fact).await
                    })
                    .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    audit.mark_commit_started();
                    Ok(receipt)
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
struct ChangeInputs<'a> {
    permission: EnrollmentPermission<'a>,
    password_digest: Option<String>,
    id: Uuid,
    resume: Option<(&'a Password, Uuid)>,
    key: Uuid,
}
async fn change_enrollment_on(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    ChangeInputs {
        permission,
        password_digest,
        id,
        resume,
        key,
    }: &ChangeInputs<'_>,
    op: &Operation<'_>,
    audit: &RequestAudit,
) -> Result<(Receipt, bool), Error> {
    let proof = permission.proof();
    let id = *id;
    let key = *key;
    crate::admission::lock_in(profile, tx, proof.tenant_id()).await?;
    if let Some(old) = crate::operations::replay(profile, tx, op).await? {
        permission.check()?;
        return serde_json::from_str(&old)
            .map(|receipt| (receipt, true))
            .map_err(|_| Error::Storage);
    }
    let row = request(profile, tx, proof.tenant_id(), id).await?;
    if resume.is_some() && row.try_get::<String, _>("authority_kind").map_err(db)? != "password" {
        return Err(Error::Forbidden);
    }
    same_actor(&row, proof)?;
    if row.try_get::<bool, _>("self_service").map_err(db)? != permission.self_service() {
        return Err(Error::Forbidden);
    }
    if row.try_get::<String, _>("device").map_err(db)? != permission.device() {
        return Err(Error::Forbidden);
    }
    if resume.is_some() {
        let source = ReportSource::parse(&row.try_get::<String, _>("source").map_err(db)?)
            .map_err(|_| Error::Corrupt)?;
        crate::admission::require_request_in(
            profile,
            tx,
            proof.tenant_id(),
            id,
            crate::quotas::Channel::source(source),
        )
        .await?;
    }
    let state: String = row.try_get("state").map_err(db)?;
    if state == "cancelled" || state == "bound" && resume.is_none() {
        return Err(Error::Conflict);
    }
    let registration = if state == "bound" {
        Some(
            crate::enrollment::store::active_registration(profile, tx, proof.tenant_id(), id)
                .await?,
        )
    } else {
        None
    };
    if resume.is_some()
        && state == "pending"
        && permission.self_service()
        && !row.try_get::<bool, _>("live").map_err(db)?
    {
        let source = ReportSource::parse(&row.try_get::<String, _>("source").map_err(db)?)
            .map_err(|_| Error::Corrupt)?;
        crate::quotas::admit_on(
            profile,
            tx,
            proof.tenant_id(),
            proof.instance_id(),
            proof.principal_id(),
            crate::quotas::Channel::source(source),
        )
        .await?;
    }
    let expires = if let Some((_, reference)) = resume {
        if password_digest.as_deref()
            == Some(
                row.try_get::<String, _>("password_digest")
                    .map_err(db)?
                    .as_str(),
            )
        {
            return Err(Error::Conflict);
        }
        sqlx::query_scalar(
            crate::storage_profile::sql(profile).enrollment_store_change_enrollment_on_1,
        )
        .bind(proof.tenant_id())
        .bind(id.to_string())
        .bind(password_digest)
        .bind(reference.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?
    } else {
        sqlx::query(crate::storage_profile::sql(profile).enrollment_store_change_enrollment_on_2)
            .bind(proof.tenant_id())
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        row.try_get("expiry").map_err(db)?
    };
    let receipt = Receipt {
        operation_id: key,
        enrollment_id: id,
        status: if resume.is_some() {
            state
        } else {
            "cancelled".into()
        },
        expires_at: expires,
        registration,
        source: ReportSource::parse(&row.try_get::<String, _>("source").map_err(db)?)
            .map_err(|_| Error::Storage)?,
    };
    permission.check()?;
    crate::operations::save(
        profile,
        tx,
        op,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((receipt, false))
}
pub async fn enrollment_authorization(
    profile: rss_mdm_install_support::StorageProfile,
    database: &crate::Store,
    tenant: &str,
    id: Uuid,
    password: &Password,
) -> Result<Authorization, Error> {
    let mut tx = database.begin(tenant).await?;
    let row = request(profile, &mut tx, tenant, id).await?;
    let device: String = row.try_get("device").map_err(db)?;
    let state: String = row.try_get("state").map_err(db)?;
    if state == "cancelled"
        || state != "bound" && !row.try_get::<bool, _>("live").map_err(db)?
        || !super::equal(
            &password.digest(tenant, &device)?,
            &row.try_get::<String, _>("password_digest").map_err(db)?,
        )
    {
        return Err(Error::Unauthorized);
    }
    authorization(row)
}
pub async fn active_registration(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Uuid, Error> {
    let row =
        sqlx::query(crate::storage_profile::sql(profile).enrollment_store_active_registration_1)
            .bind(tenant)
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::Conflict)?;
    uuid(&row, "id")
}
pub async fn mark_bound_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    auth: &Authorization,
) -> Result<(), Error> {
    if sqlx::query(crate::storage_profile::sql(profile).enrollment_store_mark_bound_in_1)
        .bind(tenant)
        .bind(auth.id)
        .bind(auth.version)
        .bind(auth.self_service)
        .execute(tx)
        .await
        .map_err(db)?
        .rows_affected()
        != 1
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

use rss_mdm_audit_integration::RequestAudit;

fn same_actor(row: &PgRow, proof: &AuthorizedPrincipal) -> Result<(), Error> {
    if row.try_get::<String, _>("actor").map_err(db)? != proof.principal_id()
        || row.try_get::<String, _>("instance").map_err(db)? != proof.instance_id()
    {
        return Err(Error::Forbidden);
    }
    Ok(())
}

/// Choose authority only from the persisted request and the authenticated original user.
pub async fn owned_permission<'a>(
    profile: rss_mdm_install_support::StorageProfile,
    database: &crate::Store,
    proof: &'a AuthorizedPrincipal,
    id: Uuid,
) -> Result<EnrollmentPermission<'a>, Error> {
    if profile != proof.profile() {
        return Err(crate::Error::Forbidden);
    }

    proof.check_live()?;
    let mut tx = database.begin(proof.tenant_id()).await?;
    let row = request(profile, &mut tx, proof.tenant_id(), id).await?;
    same_actor(&row, proof)?;
    let device: String = row.try_get("device").map_err(db)?;
    if row.try_get::<bool, _>("self_service").map_err(db)? {
        proof.self_enrollment(&device).map_err(Into::into)
    } else {
        proof.enrollment(&device).map_err(Into::into)
    }
}
