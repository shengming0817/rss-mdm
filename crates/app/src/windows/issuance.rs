use super::{certificate::Csr, *};
use crate::identity::Principal;
use crate::{
    access_store::{Operation, db},
    audit::Audit,
    device::{BindRegistration, VerifiedChannelCredential, store::bind_in},
    enrollment::{
        Authorization,
        store::{actor, request, uuid},
    },
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
impl crate::AccessStore {
    pub(super) async fn issuance_intent(
        &self,
        windows: &Windows,
        auth: &Authorization,
        proof: &Principal,
        input: (&[u8], EnrollmentType),
        now: i64,
    ) -> Result<Intent, Error> {
        let (csr, enrollment_type) = input;
        let verified = Csr::verify(csr)?;
        let mut tx = self.begin(proof.tenant_id()).await?;
        let row = request(&mut tx, proof.tenant_id(), auth.id).await?;
        current(&row, auth, proof)?;
        if let Some(old) = sqlx::query("SELECT enrollment_type,csr,tbs,issuer,configuration,registration::text,credential::text,epoch::text,secrets FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(proof.tenant_id()).bind(auth.id.to_string()).fetch_optional(&mut *tx).await.map_err(db)? {
            let old = intent(old)?;
            if old.enrollment_type != enrollment_type || old.csr != csr || old.issuer != windows.ca.der || old.configuration != windows.configuration {
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
        sqlx::query("INSERT INTO mdm_access.enrollment_intents(tenant_id,request_id,csr,tbs,issuer,configuration,registration,credential,epoch,secrets,enrollment_type) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7::uuid,$8::uuid,$9::uuid,$10,$11)")
            .bind(proof.tenant_id()).bind(auth.id.to_string()).bind(&intent.csr).bind(&intent.tbs).bind(&intent.issuer).bind(&intent.configuration).bind(intent.registration.to_string()).bind(intent.credential.to_string()).bind(intent.epoch.to_string()).bind(&intent.sealed).bind(enrollment_type.as_str())
            .execute(&mut *tx).await.map_err(db)?;
        // An intent is not a completed enrollment. No success receipt/audit is published here.
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(intent)
    }
    pub(super) async fn issued_certificate(
        &self,
        tenant: &str,
        id: Uuid,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut tx = self.begin(tenant).await?;
        sqlx::query_scalar("SELECT certificate FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(tenant).bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authorization, immutable intent and commit audit inputs"
    )]
    pub(super) async fn complete_issuance(
        &self,
        windows: &Windows,
        auth: &Authorization,
        proof: &Principal,
        intent: &Intent,
        certificate: &[u8],
        audit: &Audit,
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
            actor: actor(proof),
            key: auth.operation,
            digest: &digest,
        };
        let mut tx = self.begin(proof.tenant_id()).await?;
        let old = Self::replay(&mut tx, &operation).await?;
        let row = request(&mut tx, proof.tenant_id(), auth.id).await?;
        current(&row, auth, proof)?;
        if old.is_some() {
            self.active_enrollment(&mut tx, proof.tenant_id(), auth.id)
                .await?;
            let old: Vec<u8> = sqlx::query_scalar("SELECT certificate FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
                .bind(proof.tenant_id()).bind(auth.id.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
            if old != certificate {
                return Err(Error::Conflict);
            }
            return Ok(());
        }
        if row.try_get::<String, _>("state").map_err(db)? != "pending" {
            return Err(Error::Conflict);
        }
        let receipt = bind_in(
            &mut tx,
            proof,
            &credential,
            &BindRegistration {
                operation_id: auth.operation,
                request_id: auth.id,
                expected_generation: auth.expected_generation,
                source: ReportSource::MdmWindows,
            },
            auth.device.clone(),
            [intent.registration, intent.credential, intent.epoch],
        )
        .await?;
        let secrets = windows
            .protection
            .open(proof.tenant_id(), auth.id, &intent.sealed)?;
        sqlx::query("INSERT INTO mdm_access.enrollment_certificates(tenant_id,request_id,certificate,server_nonce) VALUES($1::uuid,$2::uuid,$3,$4)")
            .bind(proof.tenant_id()).bind(auth.id.to_string()).bind(certificate).bind(secrets.server_nonce.as_slice()).execute(&mut *tx).await.map_err(db)?;
        // Evaluate again after channel/registration lock waits, immediately before committing.
        let updated = sqlx::query("UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND password_version=$3 AND expires_at>clock_timestamp()")
            .bind(proof.tenant_id()).bind(auth.id.to_string()).bind(auth.version).execute(&mut *tx).await.map_err(db)?;
        if updated.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
        audit.registration(receipt.registration);
        proof.enrollment(&auth.device)?;
        self.finish(
            tx,
            &operation,
            &serde_json::to_string(&receipt).expect("closed receipt"),
            audit,
            Some(auth.id),
        )
        .await
    }
}
fn current(
    row: &sqlx::postgres::PgRow,
    auth: &Authorization,
    proof: &Principal,
) -> Result<(), Error> {
    proof.enrollment(&auth.device)?;
    if row.try_get::<String, _>("state").map_err(db)? == "cancelled"
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
