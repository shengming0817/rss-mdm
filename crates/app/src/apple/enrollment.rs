//! A consumed challenge is never re-authorized, including identical CA transport retries.
use super::{Apple, certificate, profile, webhook};
use crate::{
    Error,
    access_store::db,
    api::{App, authenticate},
    audit::Audit,
    enrollment::{
        Authorization, Password, Resume,
        store::{request, uuid},
    },
    identity::Principal,
};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use sqlx::{Row, postgres::PgRow};
use std::sync::Arc;
use uuid::Uuid;

fn current(row: &PgRow, auth: &Authorization, proof: &Principal) -> Result<(), Error> {
    proof.enrollment(&auth.device)?;
    if auth.source != rss_mdm_inventory::ReportSource::MdmApple
        || auth.actor != proof.principal_id()
        || auth.instance != proof.instance_id()
        || row.try_get::<String, _>("state").map_err(db)? != "pending"
        || !row.try_get::<bool, _>("live").map_err(db)?
        || row.try_get::<i64, _>("password_version").map_err(db)? != auth.version
        || uuid(row, "credential_ref")? != auth.credential_ref
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
async fn authorized(
    app: &App,
    id: Uuid,
    password: &Password,
    audit: &Audit,
) -> Result<(Authorization, Principal), Error> {
    let auth = app
        .access
        .enrollment_authorization(&app.identity.tenant.to_string(), id, password)
        .await?;
    let proof = authenticate(app, app.credentials.get(auth.credential_ref)?).await?;
    if auth.source != rss_mdm_inventory::ReportSource::MdmApple
        || auth.actor != proof.principal_id()
        || auth.instance != proof.instance_id()
    {
        return Err(Error::Unauthorized);
    }
    proof.enrollment(&auth.device)?;
    audit.identify(&proof);
    audit.target(&auth.device);
    Ok((auth, proof))
}
pub(super) async fn download(
    State(app): State<Arc<App>>,
    Path(id): Path<Uuid>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    let input = input.map_err(|_| Error::Malformed)?.0;
    let apple = app.apple()?;
    let (auth, proof) = authorized(&app, id, &input.password, &audit).await?;
    let mut tx = app.access.begin(proof.tenant_id()).await?;
    current(
        &request(&mut tx, proof.tenant_id(), id).await?,
        &auth,
        &proof,
    )?;
    // Password rotation can prepare a new attempt; any previous issuance is permanently fenced.
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND enrollment=$2::uuid AND password_version<>$3 AND state<>'superseded'")
        .bind(proof.tenant_id()).bind(id.to_string()).bind(auth.version).execute(&mut *tx).await.map_err(db)?;
    let attempt = prepared(&mut tx, apple, &auth, proof.tenant_id()).await?;
    let bytes = apple.signer.sign(
        &profile::enrollment(&apple.config, id, attempt, input.password.expose())?,
        app.clock.unix_seconds()?,
    )?;
    app.access
        .commit_audited_status(tx, &audit, Some(id), 200)
        .await?;
    Ok((
        [
            ("content-type", "application/x-apple-aspen-config"),
            ("cache-control", "no-store"),
            (
                "content-disposition",
                "attachment; filename=RSS-MDM.mobileconfig",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn prepared(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    apple: &Apple,
    auth: &Authorization,
    tenant: &str,
) -> Result<Uuid, Error> {
    let old=sqlx::query("SELECT id::text,state,configuration FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2::uuid AND password_version=$3 FOR UPDATE")
        .bind(tenant).bind(auth.id.to_string()).bind(auth.version).fetch_optional(&mut **tx).await.map_err(db)?;
    if let Some(row) = old {
        if row.try_get::<String, _>("state").map_err(db)? != "prepared"
            || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != apple.configuration
        {
            return Err(Error::Conflict);
        }
        return uuid(&row, "id");
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(tenant_id,id,enrollment,password_version,configuration,state,issuer,expires_at) SELECT tenant_id,$3::uuid,id,password_version,$4,'prepared',$5,expires_at FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(tenant).bind(auth.id.to_string()).bind(id.to_string()).bind(apple.configuration.as_slice()).bind(apple.authority.issuer_fingerprint.as_slice()).execute(&mut **tx).await.map_err(db)?;
    Ok(id)
}
pub(super) async fn challenge(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(audit): Extension<Audit>,
    bytes: Bytes,
) -> Result<Json<serde_json::Value>, Error> {
    let apple = app.apple()?;
    let input = webhook::decode(
        &apple.challenge_key,
        &apple.config.challenge_webhook.id,
        &headers,
        &bytes,
        app.clock.unix_seconds()?,
    )?;
    if input.provisioner_name.as_deref() != Some(apple.config.scep_provisioner.as_str())
        || input.x509_certificate.is_some()
        || input.scep_error_code.is_some()
    {
        return Err(Error::Unauthorized);
    }
    let csr = certificate::csr(&input.x509_certificate_request.der()?)?;
    let password = Password::new(input.scep_challenge.ok_or(Error::Unauthorized)?)?;
    let (auth, proof) = authorized(&app, csr.enrollment, &password, &audit).await?;
    let mut tx = app.access.begin(proof.tenant_id()).await?;
    current(
        &request(&mut tx, proof.tenant_id(), auth.id).await?,
        &auth,
        &proof,
    )?;
    let consumed=sqlx::query("UPDATE mdm_apple.scep_attempts SET state='consumed',transaction_id=$4,csr_digest=$5,spki=$6 WHERE tenant_id=$1::uuid AND id=$2::uuid AND enrollment=$3::uuid AND state='prepared' AND configuration=$7 AND password_version=$8 AND expires_at>clock_timestamp()")
        .bind(proof.tenant_id()).bind(csr.attempt.to_string()).bind(csr.enrollment.to_string()).bind(&input.transaction).bind(csr.digest.as_slice()).bind(csr.spki.as_slice()).bind(apple.configuration.as_slice()).bind(auth.version).execute(&mut *tx).await.map_err(db)?;
    if consumed.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    app.access
        .commit_audited_status(tx, &audit, Some(auth.id), 200)
        .await?;
    Ok(Json(
        serde_json::json!({"allow":true,"data":{"subject":certificate::subject(csr.enrollment,csr.attempt)}}),
    ))
}

pub(super) async fn notify(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(audit): Extension<Audit>,
    bytes: Bytes,
) -> Result<Json<serde_json::Value>, Error> {
    let apple = app.apple()?;
    let input = webhook::decode(
        &apple.notify_key,
        &apple.config.notify_webhook.id,
        &headers,
        &bytes,
        app.clock.unix_seconds()?,
    )?;
    let csr = certificate::csr(&input.x509_certificate_request.der()?)?;
    if input.scep_error_code.is_some() {
        return Err(Error::CertificateRequest);
    }
    let der = input.x509_certificate.ok_or(Error::Malformed)?.der()?;
    let leaf = apple.authority.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(der)],
        app.clock.unix_seconds()?,
    )?;
    if leaf.enrollment != csr.enrollment || leaf.attempt != csr.attempt || leaf.spki != csr.spki {
        return Err(Error::Unauthorized);
    }
    let tenant = app.identity.tenant.to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = request(&mut tx, &tenant, leaf.enrollment).await?;
    let pending = row.try_get::<String, _>("state").map_err(db)? == "pending"
        && row.try_get::<bool, _>("live").map_err(db)?;
    if !pending {
        return Err(Error::Unauthorized);
    }
    let attempt = attempt(&mut tx, &tenant, apple, &leaf).await?;
    if attempt.try_get::<String, _>("transaction_id").map_err(db)? != input.transaction
        || attempt.try_get::<Vec<u8>, _>("csr_digest").map_err(db)? != csr.digest
        || attempt.try_get::<i64, _>("password_version").map_err(db)?
            != row.try_get::<i64, _>("password_version").map_err(db)?
    {
        return Err(Error::Unauthorized);
    }
    persist_leaf(&mut tx, &tenant, &leaf).await?;
    app.access
        .commit_audited_status(tx, &audit, Some(leaf.enrollment), 200)
        .await?;
    Ok(Json(serde_json::json!({"allow":true})))
}
pub(super) async fn attempt(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    apple: &Apple,
    leaf: &certificate::CheckedLeaf,
) -> Result<PgRow, Error> {
    let row=sqlx::query("SELECT state,configuration,spki,fingerprint,password_version,transaction_id,csr_digest,registration::text FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND enrollment=$3::uuid AND issuer=$4 FOR UPDATE")
        .bind(tenant).bind(leaf.attempt.to_string()).bind(leaf.enrollment.to_string()).bind(apple.authority.issuer_fingerprint.as_slice()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if !matches!(
        row.try_get::<String, _>("state").map_err(db)?.as_str(),
        "consumed" | "bound"
    ) || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != apple.configuration
        || row.try_get::<Vec<u8>, _>("spki").map_err(db)? != leaf.spki
        || row
            .try_get::<Option<Vec<u8>>, _>("fingerprint")
            .map_err(db)?
            .is_some_and(|v| v != leaf.fingerprint)
    {
        return Err(Error::Unauthorized);
    }
    Ok(row)
}
pub(super) async fn persist_leaf(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    leaf: &certificate::CheckedLeaf,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_apple.scep_attempts SET fingerprint=$3,serial=$4,certificate=$5 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(tenant).bind(leaf.attempt.to_string()).bind(leaf.fingerprint.as_slice()).bind(&leaf.serial).bind(&leaf.certificate).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}

pub(super) async fn bind(
    app: &App,
    leaf: &certificate::CheckedLeaf,
    udid: &str,
    audit: &Audit,
) -> Result<(), Error> {
    let tenant = app.identity.tenant.to_string();
    // Never keep a PG lock while refreshing the frozen browser authorization.
    let mut tx = app.access.begin(&tenant).await?;
    let row = request(&mut tx, &tenant, leaf.enrollment).await?;
    let auth = crate::enrollment::store::authorization(row)?;
    tx.rollback().await.map_err(db)?;
    let proof = authenticate(app, app.credentials.get(auth.credential_ref)?).await?;
    let mut tx = app.access.begin(&tenant).await?;
    current(&request(&mut tx, &tenant, auth.id).await?, &auth, &proof)?;
    let attempt = attempt(&mut tx, &tenant, app.apple()?, leaf).await?;
    if attempt.try_get::<String, _>("state").map_err(db)? != "consumed"
        || attempt.try_get::<i64, _>("password_version").map_err(db)? != auth.version
    {
        return Err(Error::Unauthorized);
    }
    let credential = crate::device::VerifiedChannelCredential::apple(app.identity.tenant, leaf);
    let receipt = crate::device::store::bind_in(
        &mut tx,
        &proof,
        &credential,
        &crate::device::BindRegistration {
            operation_id: auth.operation,
            request_id: auth.id,
            expected_generation: auth.expected_generation,
            source: rss_mdm_inventory::ReportSource::MdmApple,
        },
        auth.device.clone(),
        [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
    )
    .await?;
    persist_leaf(&mut tx, &tenant, leaf).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='bound',registration=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(leaf.attempt.to_string()).bind(receipt.registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.devices(tenant_id,registration,udid,state) VALUES($1::uuid,$2::uuid,$3,'pending_token')")
        .bind(&tenant).bind(receipt.registration.to_string()).bind(udid).execute(&mut *tx).await.map_err(db)?;
    let updated=sqlx::query("UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND password_version=$3 AND expires_at>clock_timestamp()")
        .bind(&tenant).bind(auth.id.to_string()).bind(auth.version).execute(&mut *tx).await.map_err(db)?;
    if updated.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    audit.identify(&proof);
    audit.target(&auth.device);
    audit.registration(receipt.registration);
    app.access
        .commit_audited_status(tx, audit, Some(auth.id), 200)
        .await
}
