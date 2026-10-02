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
    Ok(Authorization {
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
pub async fn request(tx: &mut sqlx::PgConnection, tenant: &str, id: Uuid) -> Result<PgRow, Error> {
    // Cancelled rows cannot supply enrollment authority.
    sqlx::query("SELECT r.id::text,r.state,r.source,r.windows_profile,r.password_digest,r.password_version,r.expected_generation,r.credential_ref::text,r.issuance_operation::text,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.expires_at::text AS deadline,r.expires_at>clock_timestamp() AS live,g.actor,g.instance,g.device FROM mdm_access.requests r JOIN mdm_access.grants g ON (g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.issuance_operation IS NOT NULL AND r.authority_kind='password' FOR UPDATE OF r")
        .bind(tenant).bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)
}

#[allow(
    clippy::too_many_arguments,
    reason = "borrowed audit transaction retains explicit authorization, enrollment identity, source/profile and credential inputs"
)]
pub async fn create_enrollment(
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
    proof.enrollment(permission.device())?;
    let device = permission.device();
    let password_digest = password.digest(proof.tenant_id(), device)?;
    if (source == ReportSource::MdmWindows) != windows_profile.is_some() {
        return Err(Error::Malformed);
    }
    let digest = digest(&(
        "enrollment_create.v4",
        device,
        source,
        windows_profile,
        &password_digest,
    ));
    let op = Operation {
        actor: Actor::from_authorized(proof),
        key,
        digest: &digest,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &control,
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
                                Box::pin(create_enrollment_on(c, inputs, op, audit))
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
                        op.digest.as_bytes(),
                        200,
                        "success",
                        Some(receipt.enrollment_id),
                    )
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
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
    if let Some(old) = crate::operations::replay(tx, op).await? {
        proof.enrollment(permission.device())?;
        return serde_json::from_str(&old)
            .map(|receipt| (receipt, true))
            .map_err(|_| Error::Storage);
    }
    lock_channel(tx, proof.tenant_id(), device, source.channel()).await?;
    let generation: i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3")
            .bind(proof.tenant_id()).bind(device).bind(source.channel().as_str()).fetch_one(&mut *tx).await.map_err(db)?;
    let id = Uuid::new_v4();
    let grant = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2::uuid,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t")
            .bind(proof.tenant_id()).bind(grant.to_string()).bind(proof.principal_id()).bind(proof.instance_id()).bind(device).execute(&mut *tx).await.map_err(db)?;
    let expires: i64 = sqlx::query_scalar("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,state,source,expected_generation,password_digest,password_version,credential_ref,expires_at,issuance_operation,windows_profile) VALUES($1::uuid,$2::uuid,$3::uuid,'pending',$4,$5,$6,1,$7::uuid,clock_timestamp()+interval '300 seconds',$8::uuid,$9) RETURNING floor(extract(epoch FROM expires_at))::bigint")
            .bind(proof.tenant_id()).bind(id.to_string()).bind(grant.to_string()).bind(source.as_str()).bind(generation).bind(password_digest).bind(session.to_string()).bind(Uuid::new_v4().to_string()).bind(windows_profile.map(WindowsProfile::as_str)).fetch_one(&mut *tx).await.map_err(db)?;
    let receipt = Receipt {
        operation_id: key,
        enrollment_id: id,
        status: "pending".into(),
        expires_at: expires,
        registration: None,
        source,
    };
    proof.enrollment(permission.device())?;
    crate::operations::save(
        tx,
        op,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((receipt, false))
}
pub async fn enrollment_target(
    database: &crate::Store,
    proof: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<String, Error> {
    let mut tx = database.begin(proof.tenant_id()).await?;
    let row = request(&mut tx, proof.tenant_id(), id).await?;
    same_actor(&row, proof)?;
    row.try_get("device").map_err(db)
}
pub async fn change_enrollment(
    store: &rss_mdm_audit_integration::AuditStore,
    permission: EnrollmentPermission<'_>,
    id: Uuid,
    resume: Option<(&Password, Uuid)>,
    key: Uuid,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    let proof = permission.proof;
    proof.enrollment(permission.device())?;
    let password_digest = resume
        .map(|(p, _)| p.digest(proof.tenant_id(), permission.device()))
        .transpose()?;
    let action = if resume.is_some() {
        "enrollment_resume"
    } else {
        "enrollment_cancel"
    };
    let digest = digest(&("enrollment_change.v3", action, id, &password_digest));
    let op = Operation {
        actor: Actor::from_authorized(proof),
        key,
        digest: &digest,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &control,
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
                                Box::pin(change_enrollment_on(c, inputs, op, audit))
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
                        op.digest.as_bytes(),
                        200,
                        "success",
                        Some(receipt.enrollment_id),
                    )
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
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
    if let Some(old) = crate::operations::replay(tx, op).await? {
        proof.enrollment(permission.device())?;
        return serde_json::from_str(&old)
            .map(|receipt| (receipt, true))
            .map_err(|_| Error::Storage);
    }
    let row = request(tx, proof.tenant_id(), id).await?;
    same_actor(&row, proof)?;
    if row.try_get::<String, _>("device").map_err(db)? != permission.device() {
        return Err(Error::Forbidden);
    }
    let state: String = row.try_get("state").map_err(db)?;
    if state == "cancelled" || state == "bound" && resume.is_none() {
        return Err(Error::Conflict);
    }
    let registration = if state == "bound" {
        Some(crate::enrollment::store::active_registration(tx, proof.tenant_id(), id).await?)
    } else {
        None
    };
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
        sqlx::query_scalar("UPDATE mdm_access.requests SET password_digest=$3,password_version=password_version+1,credential_ref=$4::uuid,expires_at=clock_timestamp()+interval '300 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid RETURNING floor(extract(epoch FROM expires_at))::bigint")
                .bind(proof.tenant_id()).bind(id.to_string()).bind(password_digest).bind(reference.to_string()).fetch_one(&mut *tx).await.map_err(db)?
    } else {
        sqlx::query("UPDATE mdm_access.requests SET state='cancelled' WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(proof.tenant_id()).bind(id.to_string()).execute(&mut *tx).await.map_err(db)?;
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
    proof.enrollment(permission.device())?;
    crate::operations::save(
        tx,
        op,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((receipt, false))
}
pub async fn enrollment_authorization(
    database: &crate::Store,
    tenant: &str,
    id: Uuid,
    password: &Password,
) -> Result<Authorization, Error> {
    let mut tx = database.begin(tenant).await?;
    let row = request(&mut tx, tenant, id).await?;
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
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Uuid, Error> {
    let row = sqlx::query("SELECT r.id::text FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.request_id=$2::uuid AND r.state='active' AND c.state='active' FOR SHARE OF r,c")
            .bind(tenant).bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Conflict)?;
    uuid(&row, "id")
}
pub async fn mark_bound_in(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    auth: &Authorization,
    agent: bool,
) -> Result<(), Error> {
    let query = if agent {
        "UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND source='agent.builtin' AND password_version=$3 AND credential_ref=$4::uuid AND expires_at>clock_timestamp()"
    } else {
        "UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND password_version=$3 AND expires_at>clock_timestamp()"
    };
    let mut statement = sqlx::query(sqlx::AssertSqlSafe(query))
        .bind(tenant)
        .bind(auth.id.to_string())
        .bind(auth.version);
    if agent {
        statement = statement.bind(auth.credential_ref.to_string());
    }
    if statement
        .execute(&mut *tx)
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
