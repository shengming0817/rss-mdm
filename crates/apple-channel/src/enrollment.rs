//! A consumed challenge is never re-authorized, including identical CA transport retries.
use super::{Apple, certificate, profile, webhook};
use crate::Failure;
use crate::HttpState;
use crate::{
    Error,
    database::db,
    registration_enrollment::{
        Password, Resume,
        native::{Admission, Coordinates},
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

async fn admitted(c: &mut sqlx::PgConnection, proof: &Admission) -> Result<PgRow, Error> {
    proof.lock_authority_in(c).await?;
    let d = proof.coordinates();
    rss_mdm_registration_service::admission::require_request_in(
        c,
        &d.tenant,
        d.id,
        rss_mdm_registration_service::quotas::Channel::MacosMdm,
    )
    .await?;
    let row = proof.current(c).await?;
    if proof.is_account() {
        crate::account_enrollment::require_binding_in(
            c,
            &proof.coordinates().tenant,
            proof.coordinates().id,
        )
        .await?;
    }
    Ok(row)
}
async fn authorized(
    app: &HttpState,
    id: Uuid,
    secret: Option<&str>,
    audit: &RequestAudit,
) -> Result<(Coordinates, Admission), Error> {
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = request(&mut tx, &tenant, id).await?;
    let kind: String = row.try_get("authority_kind").map_err(db)?;
    tx.rollback().await.map_err(db)?;
    let proof = if kind == "agent_policy" {
        rss_mdm_registration_service::enrollment::native::agent_policy(
            &app.access.registration(),
            &tenant,
            id,
            secret,
            app.execution.clone(),
        )
        .await?
    } else if kind == "apple_ade" {
        rss_mdm_registration_service::enrollment::native::organization(
            &app.access.registration(),
            &tenant,
            id,
            crate::ade::authority::authority(),
            secret,
        )
        .await?
    } else if kind == "apple_account" {
        crate::account_enrollment::require_binding(app, id).await?;
        rss_mdm_registration_service::enrollment::native::account(
            &app.access.registration(),
            &app.identity,
            id,
            app.account_authority.clone(),
            secret,
        )
        .await?
    } else {
        let auth = if let Some(secret) = secret {
            let password = Password::new(secret.to_owned())?;
            rss_mdm_registration_service::enrollment::store::enrollment_authorization(
                &app.access.registration(),
                &tenant,
                id,
                &password,
            )
            .await?
        } else {
            rss_mdm_registration_service::enrollment::store::authorization(row)?
        };
        let identity = app
            .identity
            .authenticate(
                &app.access.authorization,
                app.credentials.get(auth.credential_ref)?,
            )
            .await?;
        Admission::password(tenant, auth, identity)?
    };
    if proof.coordinates().source != rss_mdm_inventory::ReportSource::MdmApple {
        return Err(Error::Unauthorized);
    }
    proof.bind_audit(audit)?;
    audit.target_device(&proof.coordinates().device);
    Ok((proof.coordinates().clone(), proof))
}
pub async fn download(
    State(app): State<Arc<HttpState>>,
    Path(id): Path<Uuid>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    let input = input.map_err(|_| Error::Malformed)?.0;
    let apple = app.apple()?;
    let (auth, proof) = authorized(&app, id, Some(input.password.expose()), &audit).await?;
    if proof.is_account() || proof.is_organization() {
        return Err(Error::Unauthorized);
    }
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control,
        (&app, apple, &auth, &proof, &input, &audit, id),
        |(app, apple, auth, proof, input, audit, id), tx| Box::pin(async move {
            let (attempt, replayed, bytes) = tx.with_connection_context(&mut (*app, *apple, *auth, *proof, *input, *id),
                |(app, apple, auth, proof, input, id), c| Box::pin(async move {
                    let app = *app; let apple = *apple; let auth = *auth; let proof = *proof; let input = *input; let id = *id;
    let enrollment=admitted(c,proof).await?;
    let deadline:String=enrollment.try_get("deadline").map_err(db)?;
    // Password rotation can prepare a new attempt; any previous issuance is permanently fenced.
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND enrollment=$2::uuid AND authorization_version<>$3 AND state<>'superseded'")
        .bind(proof.coordinates().tenant.as_str()).bind(id.to_string()).bind(auth.version).execute(&mut *c).await.map_err(db)?;
    let (attempt, replayed, scep_url, scep_provisioner) = prepared(c, apple, auth, proof.coordinates().tenant.as_str(), &deadline).await?;
    let bytes = apple.signer.sign(
        &profile::enrollment(&profile::EnrollmentProfile {
            mode: profile::EnrollmentMode::Profile,
                access_rights: apple.access_rights() as u16,
            scep_url: &scep_url,
            scep_provisioner: &scep_provisioner,
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
pub(crate) async fn prepared(
    tx: &mut sqlx::PgConnection,
    apple: &Apple,
    auth: &Coordinates,
    tenant: &str,
    deadline: &str,
) -> Result<(Uuid, bool, String, String), Error> {
    let old=sqlx::query("SELECT id::text,state,configuration,access_rights,scep_url,scep_provisioner FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2::uuid AND authorization_version=$3 FOR UPDATE")
        .bind(tenant).bind(auth.id.to_string()).bind(auth.version).fetch_optional(&mut *tx).await.map_err(db)?;
    if let Some(row) = old {
        if row.try_get::<String, _>("state").map_err(db)? != "prepared"
            || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != apple.configuration
            || row.try_get::<i32, _>("access_rights").map_err(db)? != apple.access_rights()
        {
            return Err(Error::Conflict);
        }
        return Ok((
            uuid(&row, "id")?,
            true,
            row.try_get::<Option<String>, _>("scep_url")
                .map_err(db)?
                .ok_or(Error::Conflict)?,
            row.try_get::<Option<String>, _>("scep_provisioner")
                .map_err(db)?
                .ok_or(Error::Conflict)?,
        ));
    }
    let id = Uuid::new_v4();
    let (issuer, scep_url, scep_provisioner) = apple.active_scep(tx, tenant).await?;
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(tenant_id,id,enrollment,authorization_version,configuration,state,issuer,expires_at,access_rights,scep_url,scep_provisioner) VALUES($1::uuid,$3::uuid,$2::uuid,$6,$4,'prepared',$5,$7::timestamptz,$8,$9,$10)")
        .bind(tenant).bind(auth.id.to_string()).bind(id.to_string()).bind(apple.configuration.as_slice()).bind(issuer).bind(auth.version).bind(deadline).bind(apple.access_rights()).bind(&scep_url).bind(&scep_provisioner).execute(&mut *tx).await.map_err(db)?;
    Ok((id, false, scep_url, scep_provisioner))
}
pub async fn challenge(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<Json<serde_json::Value>, Error> {
    let apple = app.apple()?;
    let verified = apple.webhooks.verify(
        webhook::Stage::Challenge,
        &headers,
        &bytes,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let input = verified.request();
    let issuer = verified.issuer();
    if input
        .provisioner_name
        .as_deref()
        .is_none_or(|p| p.is_empty() || p.len() > 128)
        || input.x509_certificate.is_some()
        || input.scep_error_code.is_some()
    {
        return Err(Error::Unauthorized);
    }
    let provisioner = input
        .provisioner_name
        .as_deref()
        .ok_or(Error::Unauthorized)?;
    let csr = certificate::csr(&input.x509_certificate_request.der()?)?;
    let challenge = input.scep_challenge.as_ref().ok_or(Error::Unauthorized)?;
    if super::renewal::challenge(
        &app,
        &csr,
        challenge,
        &input.transaction,
        provisioner,
        issuer,
        &audit,
    )
    .await?
    {
        return Ok(Json(
            serde_json::json!({"allow":true,"data":{"subject":certificate::subject(csr.enrollment(),csr.attempt())}}),
        ));
    }
    let (auth, proof) = authorized(&app, csr.enrollment(), Some(challenge), &audit).await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control,
        (&app, apple, &auth, &proof, &csr, input.transaction.as_str(), provisioner, issuer, &audit),
        |(app, apple, auth, proof, csr, transaction, provisioner, issuer, audit), tx| Box::pin(async move {
            tx.with_connection_context(&mut (*app, *apple, *auth, *proof, *csr, *transaction, *provisioner, *issuer),
                |(_app, apple, auth, proof, csr, transaction, provisioner, issuer), c| Box::pin(async move {
                    let apple = *apple; let auth = *auth; let proof = *proof; let csr = *csr; let transaction = *transaction; let provisioner=*provisioner; let issuer=*issuer;
    admitted(c,proof).await?;
    let consumed=sqlx::query("UPDATE mdm_apple.scep_attempts SET state='consumed',transaction_id=$4,csr_digest=$5,spki=$6 WHERE tenant_id=$1::uuid AND id=$2::uuid AND enrollment=$3::uuid AND state='prepared' AND configuration=$7 AND authorization_version=$8 AND scep_provisioner=$9 AND issuer=decode($10,'hex') AND expires_at>clock_timestamp()")
        .bind(proof.coordinates().tenant.as_str()).bind(csr.attempt().to_string()).bind(csr.enrollment().to_string()).bind(transaction).bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).bind(apple.configuration.as_slice()).bind(auth.version).bind(provisioner).bind(issuer).execute(&mut *c).await.map_err(db)?;
    if consumed.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    Ok::<_, Error>(())

                })).await?;
            let fingerprint = rss_mdm_registration_service::enrollment::digest(&(auth.id, auth.version, transaction, csr.digest(), csr.spki()));
            let fact = rss_mdm_audit_integration::Fact::business(audit, &format!("apple-scep:{}:consume", csr.attempt()),
                fingerprint.as_bytes(), 200, "success", Some(auth.id)).map_err(Error::from)?;
            app.audit_store.append(tx, &fact, false).await.map_err(Error::from)?;
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
    let verified = apple.webhooks.verify(
        webhook::Stage::Notify,
        &headers,
        &bytes,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let input = verified.request();
    let csr = certificate::csr(&input.x509_certificate_request.der()?)?;
    if input.scep_error_code.is_some() {
        return Err(Error::CertificateRequest);
    }
    let der = input
        .x509_certificate
        .as_ref()
        .ok_or(Error::Malformed)?
        .der()?;
    let leaf = apple.authority.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(der)],
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let issuer = leaf
        .issuer()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if issuer != verified.issuer()
        || leaf.enrollment() != csr.enrollment()
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
                                    if row.try_get::<String, _>("authority_kind").map_err(db)?
                                        == "apple_ade"
                                    {
                                        crate::ade::authority::require_in(
                                            c,
                                            &tenant,
                                            leaf.enrollment(),
                                        )
                                        .await?;
                                    }
                                    let attempt = attempt(c, &tenant, apple, leaf).await?;
                                    if attempt.try_get::<String, _>("transaction_id").map_err(db)?
                                        != transaction
                                        || attempt
                                            .try_get::<Vec<u8>, _>("csr_digest")
                                            .map_err(db)?
                                            != csr.digest()
                                        || attempt
                                            .try_get::<i64, _>("authorization_version")
                                            .map_err(db)?
                                            != row
                                                .try_get::<i64, _>("native_version")
                                                .map_err(db)?
                                    {
                                        return Err(Error::Unauthorized);
                                    }
                                    let replayed = attempt
                                        .try_get::<Option<Vec<u8>>, _>("fingerprint")
                                        .map_err(db)?
                                        .is_some();
                                    audit.identify_service("service:scep-notify");
                                    audit.target_device(
                                        &row.try_get::<String, _>("device").map_err(db)?,
                                    );
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
    leaf: &rss_mdm_device_trust::apple::CheckedLeaf,
) -> Result<PgRow, Error> {
    let row=sqlx::query("SELECT state,configuration,spki,fingerprint,authorization_version,transaction_id,csr_digest,registration::text FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND enrollment=$3::uuid AND issuer=$4 FOR UPDATE")
        .bind(tenant).bind(leaf.attempt().to_string()).bind(leaf.enrollment().to_string()).bind(leaf.issuer().as_slice()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
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
    leaf: &rss_mdm_device_trust::apple::CheckedLeaf,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_apple.scep_attempts SET fingerprint=$3,serial=$4,certificate=$5,not_before=$6,not_after=$7 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(tenant).bind(leaf.attempt().to_string()).bind(leaf.fingerprint().as_slice()).bind(leaf.serial()).bind(leaf.certificate()).bind(leaf.not_before()).bind(leaf.not_after()).execute(&mut *tx).await.map_err(db)?;
    let registration: Option<Uuid> = sqlx::query_scalar(
        "SELECT registration FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(leaf.attempt())
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    let issuer = leaf
        .issuer()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    rss_mdm_pki_service::certificates::record_candidate_in(
        tx,
        tenant,
        "apple",
        registration,
        &issuer,
        leaf.certificate(),
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    Ok(())
}

pub async fn bind(
    app: &HttpState,
    leaf: &rss_mdm_device_trust::apple::CheckedLeaf,
    udid: &str,
    audit: &RequestAudit,
) -> Result<(), Error> {
    let (auth, proof) = authorized(app, leaf.enrollment(), None, audit).await?;
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
    leaf: &'a rss_mdm_device_trust::apple::CheckedLeaf,
    udid: &'a str,
    auth: &'a Coordinates,
    proof: &'a Admission,
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
    admitted(tx, proof).await?;
    if proof.is_organization() {
        crate::ade::authority::udid_in(tx, &tenant, leaf.enrollment(), udid).await?;
    }
    let attempt = attempt(tx, &tenant, app.apple()?, leaf).await?;
    if attempt.try_get::<String, _>("state").map_err(db)? != "consumed"
        || attempt
            .try_get::<i64, _>("authorization_version")
            .map_err(db)?
            != auth.version
    {
        return Err(Error::Unauthorized);
    }
    let credential = app.mount.credential(leaf.fingerprint())?;
    let receipt = app
        .devices
        .bind_native_in(
            tx,
            proof,
            &credential,
            [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            facts,
        )
        .await?;
    persist_leaf(tx, &tenant, leaf).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='bound',registration=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(leaf.attempt().to_string()).bind(receipt.registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    let issuer = leaf
        .issuer()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    rss_mdm_pki_service::certificates::record_in(
        tx,
        &tenant,
        "apple",
        receipt.registration,
        &issuer,
        leaf.certificate(),
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    sqlx::query("INSERT INTO mdm_apple.devices(tenant_id,registration,udid,state,access_rights) SELECT $1::uuid,$2::uuid,$3,'pending_token',access_rights FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$4")
        .bind(&tenant).bind(receipt.registration.to_string()).bind(udid).bind(leaf.attempt()).execute(&mut *tx).await.map_err(db)?;
    crate::notify(tx, "apple").await.map_err(db)?;
    proof.mark_bound_in(tx).await?;
    proof.bind_audit(audit)?;
    audit.target_device(&auth.device);
    audit.registration(receipt.registration);
    Ok(())
}

use rss_mdm_audit_integration::RequestAudit;

pub struct ProgressEvidence {
    pub profile_prepared: bool,
    pub certificate_issued: bool,
    pub first_authenticated_check_in: bool,
    pub channel_ready: bool,
}
/// Unbound handoffs use the current password version; bound facts follow the active credential.
pub async fn progress_in(
    c: &mut sqlx::PgConnection,
    context: &rss_mdm_registration_service::enrollment::read::Context,
) -> Result<ProgressEvidence, Error> {
    let attempt = if let Some(registration) = &context.registration {
        let issued: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts s JOIN mdm_access.credentials k ON k.tenant_id=s.tenant_id AND k.registration=s.registration AND k.locator=encode(s.fingerprint,'hex') WHERE s.tenant_id=$1::uuid AND s.enrollment=$2 AND s.registration=$3 AND s.state='bound' AND s.certificate IS NOT NULL AND k.channel='mdm' AND k.state='active')")
            .bind(&context.tenant).bind(context.enrollment).bind(registration.id)
            .fetch_one(&mut *c).await.map_err(db)?;
        (issued, issued)
    } else {
        let attempt: (bool, bool) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2 AND authorization_version=$3 AND state<>'superseded'),EXISTS(SELECT 1 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2 AND authorization_version=$3 AND state<>'superseded' AND certificate IS NOT NULL)")
        .bind(&context.tenant).bind(context.enrollment).bind(context.authorization_version)
        .fetch_one(&mut *c).await.map_err(db)?;
        attempt
    };
    let state = if let Some(registration) = &context.registration {
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2",
        )
        .bind(&context.tenant)
        .bind(registration.id)
        .fetch_optional(c)
        .await
        .map_err(db)?
    } else {
        None
    };
    Ok(ProgressEvidence {
        profile_prepared: attempt.0,
        certificate_issued: attempt.1,
        first_authenticated_check_in: state.is_some(),
        channel_ready: state.as_deref() == Some("active"),
    })
}

/// Current Apple credentials for downstream integration consumers; no profile or SCEP operations.
#[cfg(feature = "integration")]
pub struct CurrentPeer<'a> {
    pub device: &'a str,
    pub udid: &'a str,
    pub csr: &'a [u8],
    pub certificate: &'a [u8],
    pub now: i64,
}
#[cfg(feature = "integration")]
pub async fn seed_current_peer_in(
    c: &mut sqlx::PgConnection,
    apple: &Apple,
    proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    seed: CurrentPeer<'_>,
) -> Result<(), Error> {
    let tenant = proof.tenant_id();
    let csr = certificate::csr(seed.csr)?;
    let leaf = apple
        .authority
        .verify(&[seed.certificate.into()], seed.now)?;
    if leaf.enrollment() != csr.enrollment()
        || leaf.attempt() != csr.attempt()
        || leaf.spki() != csr.spki()
    {
        return Err(Error::Malformed);
    }
    let mount = rss_mdm_registration_service::ChannelMount::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        rss_mdm_inventory::ReportSource::MdmApple,
        rss_mdm_registration_service::Purpose::Primary,
    );
    let credential = mount.credential(leaf.fingerprint())?;
    let registration = Uuid::new_v4();
    rss_mdm_registration_service::device::fixture::native_in(
        c,
        proof,
        &credential,
        rss_mdm_registration_service::device::fixture::NativeSeed {
            device: seed.device,
            request: csr.enrollment(),
            ids: [registration, Uuid::new_v4(), Uuid::new_v4()],
            windows_profile: None,
        },
    )
    .await?;
    let (issuer, scep_url, scep_provisioner) = apple.active_scep(c, tenant).await?;
    if issuer != leaf.issuer() {
        return Err(Error::Conflict);
    }
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(tenant_id,id,enrollment,authorization_version,configuration,state,issuer,expires_at,access_rights,scep_url,scep_provisioner,transaction_id,csr_digest,spki,registration) VALUES($1::uuid,$2,$3,1,$4,'bound',$5,clock_timestamp()+interval '1 hour',$6,$7,$8,$9,$10,$11,$12)")
        .bind(tenant).bind(csr.attempt()).bind(csr.enrollment()).bind(apple.configuration.as_slice()).bind(issuer)
        .bind(apple.access_rights()).bind(scep_url).bind(scep_provisioner).bind(Uuid::new_v4().to_string())
        .bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).bind(registration).execute(&mut *c).await.map_err(db)?;
    persist_leaf(c, tenant, &leaf).await?;
    sqlx::query("INSERT INTO mdm_apple.devices(tenant_id,registration,udid,state,access_rights) VALUES($1::uuid,$2,$3,'pending_token',$4)")
        .bind(tenant).bind(registration).bind(seed.udid).bind(apple.access_rights()).execute(c).await.map_err(db)?;
    Ok(())
}
