use super::{certificate::Csr, *};
use crate::authorization::context::AuthorizedPrincipal;
use crate::{
    database::db,
    device::{BindRegistration, VerifiedChannelCredential, store::bind_in},
    enrollment::{
        Authorization,
        store::{request, uuid},
    },
    operations::Operation,
};
use rss_mdm_inventory::ReportSource;
use rss_mdm_windows_mdm::provisioning::EnrollmentType;
use rss_request_context::TenantId;
use sqlx::Row;
use tokio_rustls::rustls::pki_types::CertificateDer;
use uuid::Uuid;
use x509_cert::der::{Decode, Encode};

pub(super) struct Intent {
    pub enrollment_type: EnrollmentType,
    pub csr: Vec<u8>,
    pub tbs: Vec<u8>,
    pub issuer: Vec<u8>,
    pub configuration: String,
    pub registration: Uuid,
    pub credential: Uuid,
    pub epoch: Uuid,
    pub sealed: Vec<u8>,
}
fn intent(row: sqlx::postgres::PgRow) -> Result<Intent, Error> {
    Ok(Intent {
        enrollment_type: match row
            .try_get::<String, _>("enrollment_type")
            .map_err(db)?
            .as_str()
        {
            "Full" => EnrollmentType::Full,
            "Device" => EnrollmentType::Device,
            _ => return Err(Error::Conflict),
        },
        csr: row.try_get("csr").map_err(db)?,
        tbs: row.try_get("tbs").map_err(db)?,
        issuer: row.try_get("issuer").map_err(db)?,
        configuration: row.try_get("configuration").map_err(db)?,
        registration: uuid(&row, "registration")?,
        credential: uuid(&row, "credential")?,
        epoch: uuid(&row, "epoch")?,
        sealed: row.try_get("secrets").map_err(db)?,
    })
}

pub(super) async fn issuance_intent(
    database: &crate::database::Database,
    windows: &Windows,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
    input: (&[u8], EnrollmentType),
    now: i64,
) -> Result<Intent, Error> {
    let (csr, enrollment_type) = input;
    let verified = Csr::verify(csr)?;
    let mut tx = database.begin(proof.tenant_id()).await?;
    let row = request(&mut tx, proof.tenant_id(), auth.id).await?;
    current(&row, auth, proof)?;
    if let Some(old) =
        crate::enrollment::protocol::intent(&mut tx, proof.tenant_id(), auth.id.to_string())
            .await
            .map_err(db)?
    {
        let old = intent(old)?;
        if old.enrollment_type != enrollment_type
            || old.csr != csr
            || old.issuer != windows.ca.der
            || old.configuration != windows.configuration
        {
            return Err(Error::Conflict);
        }
        return Ok(old);
    }
    if auth.state != "pending" {
        return Err(Error::Conflict);
    }
    let registration = Uuid::new_v4();
    let intent = Intent {
        enrollment_type,
        csr: csr.to_vec(),
        tbs: windows.ca.intent(&verified, registration, now)?,
        issuer: windows.ca.der.clone(),
        configuration: windows.configuration.clone(),
        registration,
        credential: Uuid::new_v4(),
        epoch: Uuid::new_v4(),
        sealed: windows.protection.seal(
            proof.tenant_id(),
            auth.id,
            &protection::Secrets::generate()?,
        )?,
    };
    crate::enrollment::protocol::insert_intent(
        &mut tx,
        proof.tenant_id(),
        crate::enrollment::protocol::NewIntent {
            request: auth.id.to_string(),
            csr: &intent.csr,
            tbs: &intent.tbs,
            issuer: &intent.issuer,
            configuration: &intent.configuration,
            registration: intent.registration.to_string(),
            credential: intent.credential.to_string(),
            epoch: intent.epoch.to_string(),
            secrets: &intent.sealed,
            enrollment_type: enrollment_type.as_str(),
        },
    )
    .await
    .map_err(db)?;
    // An intent is not a completed enrollment. No success receipt/audit is published here.
    tx.commit().await.map_err(|_| Error::CommitUnknown)?;
    Ok(intent)
}
pub(super) async fn issued_certificate(
    database: &crate::database::Database,
    tenant: &str,
    id: Uuid,
) -> Result<Option<Vec<u8>>, Error> {
    let mut tx = database.begin(tenant).await?;
    crate::enrollment::protocol::certificate(&mut tx, tenant, id.to_string())
        .await
        .map_err(db)
}
#[allow(
    clippy::too_many_arguments,
    reason = "explicit authorization, immutable intent and commit audit inputs"
)]
pub(super) async fn complete_issuance(
    store: &rss_mdm_audit_integration::AuditStore,
    windows: &Windows,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
    intent: &Intent,
    certificate: &[u8],
    audit: &RequestAudit,
    now: i64,
) -> Result<(), Error> {
    // The persisted intention is the only authority for the bytes being bound.
    let issued = x509_cert::Certificate::from_der(certificate).map_err(|_| Error::Conflict)?;
    if issued
        .tbs_certificate
        .to_der()
        .map_err(|_| Error::Conflict)?
        != intent.tbs
    {
        return Err(Error::Conflict);
    }
    let checked = windows
        .ca
        .verify(&[CertificateDer::from(certificate)], now)?;
    let credential = VerifiedChannelCredential::windows(
        TenantId::parse(proof.tenant_id()).map_err(|_| Error::Unauthorized)?,
        &checked,
    );
    let digest = crate::enrollment::digest(&(
        "enrollment_issue",
        auth.id,
        &intent.csr,
        &intent.configuration,
    ));
    let operation = Operation {
        actor: crate::operations::Actor::from_authorized(proof),
        key: auth.operation,
        digest: &digest,
    };
    let budget = crate::audit_budget::AuditBudget::retirement(None);
    let operation_control = budget.operation_control();
    let attempt = store
        .execute_with_operation(
            TenantId::parse(proof.tenant_id()).map_err(|_| Error::Malformed)?,
            &operation_control,
            (
                store,
                CompletionInputs {
                    windows,
                    auth,
                    proof,
                    intent,
                    certificate,
                    credential: &credential,
                    operation: &operation,
                    audit,
                    facts: Vec::new(),
                },
            ),
            |(store, inputs), tx| {
                Box::pin(async move {
                    let replayed = tx
                        .with_connection_context(inputs, |inputs, c| {
                            Box::pin(complete_on(c, inputs))
                        })
                        .await?;
                    for fact in &inputs.facts {
                        store.append(tx, fact, false).await.map_err(Error::from)?;
                    }
                    let fact = rss_mdm_audit_integration::Fact::business(
                        inputs.audit,
                        &format!(
                            "enrollment_issue:{}:{}",
                            inputs.proof.principal_id(),
                            inputs.auth.operation
                        ),
                        inputs.operation.digest.as_bytes(),
                        200,
                        "success",
                        Some(inputs.auth.id),
                    )
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        inputs.audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    inputs.audit.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
struct CompletionInputs<'a> {
    windows: &'a Windows,
    auth: &'a Authorization,
    proof: &'a AuthorizedPrincipal,
    intent: &'a Intent,
    certificate: &'a [u8],
    credential: &'a VerifiedChannelCredential,
    operation: &'a Operation<'a>,
    audit: &'a RequestAudit,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn complete_on(
    tx: &mut sqlx::PgConnection,
    inputs: &mut CompletionInputs<'_>,
) -> Result<bool, Error> {
    let CompletionInputs {
        windows,
        auth,
        proof,
        intent,
        certificate,
        credential,
        operation,
        audit,
        facts,
    } = inputs;
    let windows = *windows;
    let auth = *auth;
    let proof = *proof;
    let intent = *intent;
    let certificate = *certificate;
    let credential = *credential;
    let operation = *operation;
    let audit = *audit;
    let old = crate::operations::replay(tx, operation).await?;
    let row = request(tx, proof.tenant_id(), auth.id).await?;
    current(&row, auth, proof)?;
    if old.is_some() {
        crate::enrollment::store::active_windows_enrollment(tx, proof.tenant_id(), auth.id).await?;
        let old: Vec<u8> = crate::enrollment::protocol::required_certificate(
            tx,
            proof.tenant_id(),
            auth.id.to_string(),
        )
        .await
        .map_err(db)?;
        if old != certificate {
            return Err(Error::Conflict);
        }
        audit.registration(intent.registration);
        return Ok(true);
    }
    if row.try_get::<String, _>("state").map_err(db)? != "pending" {
        return Err(Error::Conflict);
    }
    let receipt = bind_in(
        tx,
        proof,
        credential,
        &BindRegistration {
            operation_id: auth.operation,
            request_id: auth.id,
            expected_generation: auth.expected_generation,
            source: ReportSource::MdmWindows,
        },
        auth.device.clone(),
        [intent.registration, intent.credential, intent.epoch],
        facts,
    )
    .await?;
    let secrets = windows
        .protection
        .open(proof.tenant_id(), auth.id, &intent.sealed)?;
    crate::enrollment::protocol::insert_certificate(
        tx,
        proof.tenant_id(),
        auth.id.to_string(),
        certificate,
        secrets.server_nonce.as_slice(),
    )
    .await
    .map_err(db)?;
    // Evaluate again after channel/registration lock waits, immediately before committing.
    crate::enrollment::store::mark_bound_in(tx, proof.tenant_id(), auth, false).await?;
    audit.registration(receipt.registration);
    proof.enrollment(&auth.device)?;
    crate::operations::save(
        tx,
        operation,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok(false)
}

fn current(
    row: &sqlx::postgres::PgRow,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
) -> Result<(), Error> {
    proof.enrollment(&auth.device)?;
    if auth.source != rss_mdm_inventory::ReportSource::MdmWindows
        || row.try_get::<String, _>("state").map_err(db)? == "cancelled"
        || row.try_get::<i64, _>("password_version").map_err(db)? != auth.version
        || uuid(row, "credential_ref")? != auth.credential_ref
        || !row.try_get::<bool, _>("live").map_err(db)?
        || auth.actor != proof.principal_id()
        || auth.instance != proof.instance_id()
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub(super) fn provision(
    w: &Windows,
    intent: &Intent,
    certificate: &[u8],
    auth: &Authorization,
    tenant: &str,
) -> Result<Vec<u8>, Error> {
    let secrets = w.protection.open(tenant, auth.id, &intent.sealed)?;
    let subject = x509_cert::TbsCertificate::from_der(&intent.tbs)
        .map_err(|_| Error::Conflict)?
        .subject
        .to_string();
    // SHA-1 is only the Windows certificate-store address; management authority uses SHA-256.
    let thumbprint = |bytes: &[u8]| -> String {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    };
    rss_mdm_windows_mdm::provisioning::encode(
        &rss_mdm_windows_mdm::provisioning::Provisioning {
            enrollment_type: intent.enrollment_type,
            enterprise_device_id: &intent.registration.to_string(),
            issuer: &intent.issuer,
            certificate,
            issuer_thumbprint: &thumbprint(&intent.issuer),
            certificate_thumbprint: &thumbprint(certificate),
            certificate_subject: &subject,
            management_url: &w.management_url(),
            provider_id: &w.config.provider_id,
            username: &intent.registration.to_string(),
            client_password: rss_mdm_windows_mdm::Secret(&secrets.client_password),
            server_password: rss_mdm_windows_mdm::Secret(&secrets.server_password),
            server_nonce: &secrets.server_nonce,
        },
        &rss_mdm_windows_mdm::CodecLimits::default(),
    )
    .map_err(|_| Error::Unavailable(Failure::Protocol))
}

use rss_mdm_audit_integration::RequestAudit;
