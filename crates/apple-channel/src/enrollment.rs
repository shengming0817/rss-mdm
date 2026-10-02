//! A consumed challenge is never re-authorized, including identical CA transport retries.
use super::{Apple, certificate, profile, webhook};
use crate::Failure;
use crate::HttpState;
use crate::{
    Error,
    authorization::context::AuthorizedPrincipal,
    database::db,
    registration_enrollment::{
        Authorization, Password, Resume,
        store::{request, uuid},
    },
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

fn current(row: &PgRow, auth: &Authorization, proof: &AuthorizedPrincipal) -> Result<(), Error> {
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
    app: &HttpState,
    id: Uuid,
    password: &Password,
    audit: &RequestAudit,
) -> Result<(Authorization, AuthorizedPrincipal), Error> {
    let auth = rss_mdm_registration_service::enrollment::store::enrollment_authorization(
        &app.access.registration(),
        &app.identity.tenant().to_string(),
        id,
        password,
    )
    .await?;
    let proof = app
        .identity
        .authenticate(
            &app.access.authorization,
            app.credentials.get(auth.credential_ref)?,
        )
        .await?;
    if auth.source != rss_mdm_inventory::ReportSource::MdmApple
        || auth.actor != proof.principal_id()
        || auth.instance != proof.instance_id()
    {
        return Err(Error::Unauthorized);
    }
    proof.enrollment(&auth.device)?;
    proof.bind_audit(audit)?;
    audit.target(&auth.device);
    Ok((auth, proof))
}
pub async fn download(
    State(app): State<Arc<HttpState>>,
    Path(id): Path<Uuid>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    let input = input.map_err(|_| Error::Malformed)?.0;
    let apple = app.apple()?;
    let (auth, proof) = authorized(&app, id, &input.password, &audit).await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control,
        (&app, apple, &auth, &proof, &input, &audit, id),
        |(app, apple, auth, proof, input, audit, id), tx| Box::pin(async move {
            let (attempt, replayed, bytes) = tx.with_connection_context(&mut (*app, *apple, *auth, *proof, *input, *id),
                |(app, apple, auth, proof, input, id), c| Box::pin(async move {
                    let app = *app; let apple = *apple; let auth = *auth; let proof = *proof; let input = *input; let id = *id;
    let enrollment=request(c,proof.tenant_id(),id).await?;
    current(&enrollment,auth,proof)?;
    let deadline:String=enrollment.try_get("deadline").map_err(db)?;
    // Password rotation can prepare a new attempt; any previous issuance is permanently fenced.
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND enrollment=$2::uuid AND password_version<>$3 AND state<>'superseded'")
        .bind(proof.tenant_id()).bind(id.to_string()).bind(auth.version).execute(&mut *c).await.map_err(db)?;
    let (attempt, replayed) = prepared(c, apple, auth, proof.tenant_id(), &deadline).await?;
    let bytes = apple.signer.sign(
        &profile::enrollment(&profile::EnrollmentProfile {
                access_rights: apple.access_rights() as u16,
            scep_url: &apple.config.scep_url,
            scep_provisioner: &apple.config.scep_provisioner,
            apns_topic: &apple.config.apns_topic,
            management_origin: &apple.config.management.origin,
            subject: &certificate::subject(id, attempt),
        }, id, attempt, input.password.expose())?,
        app.clock.unix_seconds().ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    Ok::<_, Error>((attempt, replayed, bytes))

                })).await?;
            let fingerprint = rss_mdm_registration_service::enrollment::digest(&(auth.id, auth.version, attempt, &apple.configuration, apple.access_rights()));
            let fact = rss_mdm_audit_integration::Fact::business(audit, &format!("apple-profile:{attempt}"),
                fingerprint.as_bytes(), 200, "success", Some(auth.id)).map_err(Error::from)?;
            app.audit_store.append(tx, &fact, replayed).await.map_err(Error::from)?;
            if replayed { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(bytes)
        }),
    ).await;
    let bytes = crate::operations::settle(outcome, &audit)?;
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
    tx: &mut sqlx::PgConnection,
    apple: &Apple,
    auth: &Authorization,
    tenant: &str,
    deadline: &str,
) -> Result<(Uuid, bool), Error> {
    let old=sqlx::query("SELECT id::text,state,configuration,access_rights FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2::uuid AND password_version=$3 FOR UPDATE")
        .bind(tenant).bind(auth.id.to_string()).bind(auth.version).fetch_optional(&mut *tx).await.map_err(db)?;
    if let Some(row) = old {
        if row.try_get::<String, _>("state").map_err(db)? != "prepared"
            || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != apple.configuration
            || row.try_get::<i32, _>("access_rights").map_err(db)? != apple.access_rights()
        {
            return Err(Error::Conflict);
        }
        return uuid(&row, "id").map(|id| (id, true)).map_err(Error::from);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(tenant_id,id,enrollment,password_version,configuration,state,issuer,expires_at,access_rights) VALUES($1::uuid,$3::uuid,$2::uuid,$6,$4,'prepared',$5,$7::timestamptz,$8)")
        .bind(tenant).bind(auth.id.to_string()).bind(id.to_string()).bind(apple.configuration.as_slice()).bind(apple.authority.issuer_fingerprint().as_slice()).bind(auth.version).bind(deadline).bind(apple.access_rights()).execute(&mut *tx).await.map_err(db)?;
    Ok((id, false))
}
pub async fn challenge(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<Json<serde_json::Value>, Error> {
    let apple = app.apple()?;
    let input = webhook::decode(
        &apple.challenge_key,
        &apple.config.challenge_webhook.id,
        &headers,
        &bytes,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    if input.provisioner_name.as_deref() != Some(apple.config.scep_provisioner.as_str())
        || input.x509_certificate.is_some()
        || input.scep_error_code.is_some()
    {
        return Err(Error::Unauthorized);
    }
    let csr = certificate::csr(&input.x509_certificate_request.der()?)?;
    let password = Password::new(input.scep_challenge.ok_or(Error::Unauthorized)?)?;
    if super::renewal::challenge(&app, &csr, password.expose(), &input.transaction, &audit).await? {
        return Ok(Json(
            serde_json::json!({"allow":true,"data":{"subject":certificate::subject(csr.enrollment(),csr.attempt())}}),
        ));
    }
    let (auth, proof) = authorized(&app, csr.enrollment(), &password, &audit).await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control,
        (&app.audit_store, apple, &auth, &proof, &csr, input.transaction.as_str(), &audit),
        |(store, apple, auth, proof, csr, transaction, audit), tx| Box::pin(async move {
            tx.with_connection_context(&mut (*apple, *auth, *proof, *csr, *transaction),
                |(apple, auth, proof, csr, transaction), c| Box::pin(async move {
                    let apple = *apple; let auth = *auth; let proof = *proof; let csr = *csr; let transaction = *transaction;
    current(
        &request(c, proof.tenant_id(), auth.id).await?,
        auth,
        proof,
    )?;
    let consumed=sqlx::query("UPDATE mdm_apple.scep_attempts SET state='consumed',transaction_id=$4,csr_digest=$5,spki=$6 WHERE tenant_id=$1::uuid AND id=$2::uuid AND enrollment=$3::uuid AND state='prepared' AND configuration=$7 AND password_version=$8 AND expires_at>clock_timestamp()")
        .bind(proof.tenant_id()).bind(csr.attempt().to_string()).bind(csr.enrollment().to_string()).bind(transaction).bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).bind(apple.configuration.as_slice()).bind(auth.version).execute(&mut *c).await.map_err(db)?;
    if consumed.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    Ok::<_, Error>(())

                })).await?;
            let fingerprint = rss_mdm_registration_service::enrollment::digest(&(auth.id, auth.version, transaction, csr.digest(), csr.spki()));
            let fact = rss_mdm_audit_integration::Fact::business(audit, &format!("apple-scep:{}:consume", csr.attempt()),
                fingerprint.as_bytes(), 200, "success", Some(auth.id)).map_err(Error::from)?;
            store.append(tx, &fact, false).await.map_err(Error::from)?;
            audit.mark_commit_started();
            Ok(())
        }),
    ).await;
    crate::operations::settle(outcome, &audit)?;
    Ok(Json(
        serde_json::json!({"allow":true,"data":{"subject":certificate::subject(csr.enrollment(),csr.attempt())}}),
    ))
}

pub async fn notify(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<Json<serde_json::Value>, Error> {
    let apple = app.apple()?;
    let input = webhook::decode(
        &apple.notify_key,
        &apple.config.notify_webhook.id,
        &headers,
        &bytes,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let csr = certificate::csr(&input.x509_certificate_request.der()?)?;
    if input.scep_error_code.is_some() {
        return Err(Error::CertificateRequest);
    }
    let der = input.x509_certificate.ok_or(Error::Malformed)?.der()?;
    let leaf = apple.authority.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(der)],
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    if leaf.enrollment() != csr.enrollment()
        || leaf.attempt() != csr.attempt()
        || leaf.spki() != csr.spki()
    {
        return Err(Error::Unauthorized);
    }
    if super::renewal::notify(&app, &leaf, &csr, &input.transaction, &audit).await? {
        return Ok(Json(serde_json::json!({"allow":true})));
    }
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &control,
            (&app, apple, &leaf, &csr, input.transaction.as_str(), &audit),
            |(app, apple, leaf, csr, transaction, audit), tx| {
                Box::pin(async move {
                    let replayed = tx
                        .with_connection_context(
                            &mut (*app, *apple, *leaf, *csr, *transaction, *audit),
                            |(app, apple, leaf, csr, transaction, audit), c| {
                                Box::pin(async move {
                                    let app = *app;
                                    let apple = *apple;
                                    let leaf = *leaf;
                                    let csr = *csr;
                                    let transaction = *transaction;
                                    let audit = *audit;
                                    let tenant = app.identity.tenant().to_string();
                                    let row = request(c, &tenant, leaf.enrollment()).await?;
                                    let pending = row.try_get::<String, _>("state").map_err(db)?
                                        == "pending"
                                        && row.try_get::<bool, _>("live").map_err(db)?;
                                    if !pending {
                                        return Err(Error::Unauthorized);
                                    }
                                    let attempt = attempt(c, &tenant, apple, leaf).await?;
                                    if attempt.try_get::<String, _>("transaction_id").map_err(db)?
                                        != transaction
                                        || attempt
                                            .try_get::<Vec<u8>, _>("csr_digest")
                                            .map_err(db)?
                                            != csr.digest()
                                        || attempt
                                            .try_get::<i64, _>("password_version")
                                            .map_err(db)?
                                            != row
                                                .try_get::<i64, _>("password_version")
                                                .map_err(db)?
                                    {
                                        return Err(Error::Unauthorized);
                                    }
                                    let replayed = attempt
                                        .try_get::<Option<Vec<u8>>, _>("fingerprint")
                                        .map_err(db)?
                                        .is_some();
                                    audit.identify_service("service:scep-notify");
                                    audit.target(&row.try_get::<String, _>("device").map_err(db)?);
                                    persist_leaf(c, &tenant, leaf).await?;
                                    Ok::<_, Error>(replayed)
                                })
                            },
                        )
                        .await?;
                    let fingerprint = rss_mdm_registration_service::enrollment::digest(&(
                        leaf.attempt(),
                        leaf.fingerprint(),
                        csr.digest(),
                        transaction,
                    ));
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-scep:{}:notify", leaf.attempt()),
                        fingerprint.as_bytes(),
                        200,
                        "success",
                        Some(leaf.enrollment()),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    audit.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(outcome, &audit)?;
    Ok(Json(serde_json::json!({"allow":true})))
}
pub async fn attempt(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    apple: &Apple,
    leaf: &certificate::CheckedLeaf,
) -> Result<PgRow, Error> {
    let row=sqlx::query("SELECT state,configuration,spki,fingerprint,password_version,transaction_id,csr_digest,registration::text FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND enrollment=$3::uuid AND issuer=$4 FOR UPDATE")
        .bind(tenant).bind(leaf.attempt().to_string()).bind(leaf.enrollment().to_string()).bind(apple.authority.issuer_fingerprint().as_slice()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if !matches!(
        row.try_get::<String, _>("state").map_err(db)?.as_str(),
        "consumed" | "bound"
    ) || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != apple.configuration
        || row.try_get::<Vec<u8>, _>("spki").map_err(db)? != leaf.spki()
        || row
            .try_get::<Option<Vec<u8>>, _>("fingerprint")
            .map_err(db)?
            .is_some_and(|v| v != leaf.fingerprint())
    {
        return Err(Error::Unauthorized);
    }
    Ok(row)
}
pub async fn persist_leaf(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    leaf: &certificate::CheckedLeaf,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_apple.scep_attempts SET fingerprint=$3,serial=$4,certificate=$5,not_before=$6,not_after=$7 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(tenant).bind(leaf.attempt().to_string()).bind(leaf.fingerprint().as_slice()).bind(leaf.serial()).bind(leaf.certificate()).bind(leaf.not_before()).bind(leaf.not_after()).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

pub async fn bind(
    app: &HttpState,
    leaf: &certificate::CheckedLeaf,
    udid: &str,
    audit: &RequestAudit,
) -> Result<(), Error> {
    let tenant = app.identity.tenant().to_string();
    // Never keep a PG lock while refreshing the frozen browser authorization.
    let mut tx = app.access.begin(&tenant).await?;
    let row = request(&mut tx, &tenant, leaf.enrollment()).await?;
    let auth = rss_mdm_registration_service::enrollment::store::authorization(row)?;
    tx.rollback().await.map_err(db)?;
    let proof = app
        .identity
        .authenticate(
            &app.access.authorization,
            app.credentials.get(auth.credential_ref)?,
        )
        .await?;
    let fingerprint = rss_mdm_registration_service::enrollment::digest(&(
        leaf.attempt(),
        leaf.fingerprint(),
        udid,
        auth.operation,
    ));
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let attempt = app
        .audit_store
        .write(
            app.identity.tenant(),
            &control,
            (
                app,
                &fingerprint,
                BindInputs {
                    app,
                    leaf,
                    udid,
                    auth: &auth,
                    proof: &proof,
                    audit,
                    facts: Vec::new(),
                },
            ),
            |(app, fingerprint, inputs), tx| {
                Box::pin(async move {
                    tx.with_connection_context(inputs, |inputs, c| Box::pin(bind_on(c, inputs)))
                        .await?;
                    for fact in &inputs.facts {
                        app.audit_store
                            .append(tx, fact, false)
                            .await
                            .map_err(Error::from)?;
                    }
                    let fact = rss_mdm_audit_integration::Fact::business(
                        inputs.audit,
                        &format!("apple-bind:{}", inputs.leaf.attempt()),
                        fingerprint.as_bytes(),
                        200,
                        "success",
                        Some(inputs.auth.id),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, false)
                        .await
                        .map_err(Error::from)?;
                    inputs.audit.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
struct BindInputs<'a> {
    app: &'a HttpState,
    leaf: &'a certificate::CheckedLeaf,
    udid: &'a str,
    auth: &'a rss_mdm_registration_service::enrollment::Authorization,
    proof: &'a crate::authorization::context::AuthorizedPrincipal,
    audit: &'a RequestAudit,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn bind_on(tx: &mut sqlx::PgConnection, inputs: &mut BindInputs<'_>) -> Result<(), Error> {
    let BindInputs {
        app,
        leaf,
        udid,
        auth,
        proof,
        audit,
        facts,
    } = inputs;
    let app = *app;
    let leaf = *leaf;
    let udid = *udid;
    let auth = *auth;
    let proof = *proof;
    let audit = *audit;
    let tenant = app.identity.tenant().to_string();
    current(&request(tx, &tenant, auth.id).await?, auth, proof)?;
    let attempt = attempt(tx, &tenant, app.apple()?, leaf).await?;
    if attempt.try_get::<String, _>("state").map_err(db)? != "consumed"
        || attempt.try_get::<i64, _>("password_version").map_err(db)? != auth.version
    {
        return Err(Error::Unauthorized);
    }
    let credential = app.mount.credential(leaf.fingerprint());
    let receipt = app
        .devices
        .bind_in(
            tx,
            proof,
            &credential,
            &crate::device::BindRegistration {
                operation_id: auth.operation,
                request_id: auth.id,
                expected_generation: auth.expected_generation,
                source: rss_mdm_inventory::ReportSource::MdmApple,
            },
            auth.device.clone(),
            [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            facts,
        )
        .await?;
    persist_leaf(tx, &tenant, leaf).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='bound',registration=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(leaf.attempt().to_string()).bind(receipt.registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.devices(tenant_id,registration,udid,state,access_rights) SELECT $1::uuid,$2::uuid,$3,'pending_token',access_rights FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$4")
        .bind(&tenant).bind(receipt.registration.to_string()).bind(udid).bind(leaf.attempt()).execute(&mut *tx).await.map_err(db)?;
    crate::notify(tx, "apple").await.map_err(db)?;
    rss_mdm_registration_service::enrollment::store::mark_bound_in(tx, &tenant, auth, false)
        .await?;
    proof.bind_audit(audit)?;
    audit.target(&auth.device);
    audit.registration(receipt.registration);
    Ok(())
}

use rss_mdm_audit_integration::RequestAudit;
