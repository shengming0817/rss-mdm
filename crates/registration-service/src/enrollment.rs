//! Enrollment is the single lifecycle owner; the grant retains immutable authorization origin.
pub mod admission;
pub mod credentials;
pub mod read;
pub mod store;
use crate::Error;
use rss_mdm_inventory::ReportSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub device_id: String,
    pub password: Password,
    pub source: ReportSource,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resume {
    pub password: Password,
}
/// Deliberately has no Debug or Serialize implementation.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Password(Zeroizing<String>);
impl Password {
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
    pub fn new(value: String) -> Result<Self, EnrollmentError> {
        if !valid(&value) {
            return Err(EnrollmentError::InvalidPassword);
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn digest(&self, tenant: &str, device: &str) -> Result<String, EnrollmentError> {
        if !valid(&self.0) {
            return Err(EnrollmentError::InvalidPassword);
        }
        Ok(digest(&(
            "mdm.enrollment.password.v1",
            tenant,
            device,
            self.0.as_str(),
        )))
    }
}
pub fn digest(value: &impl Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("closed operation"))
    )
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub operation_id: Uuid,
    pub enrollment_id: Uuid,
    pub status: String,
    pub expires_at: i64,
    #[serde(rename = "registrationId")]
    pub registration: Option<Uuid>,
    pub source: ReportSource,
}
/// All fields originate in PG, never in device claims.
pub struct Authorization {
    pub id: Uuid,
    pub device: String,
    pub actor: String,
    pub instance: String,
    pub credential_ref: Uuid,
    pub version: i64,
    pub expected_generation: i64,
    pub operation: Uuid,
    pub state: String,
    pub source: ReportSource,
}

/// Enrollment password generation, independent of browser authentication.
pub fn random() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

pub fn equal(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn valid(value: &str) -> bool {
    use base64::Engine;
    value.len() == 43
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|v| v.len() == 32)
}

#[cfg(test)]
#[path = "../tests/enrollment.rs"]
mod tests;

#[derive(Clone, Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("invalid enrollment password")]
    InvalidPassword,
}

/// Registration request workflows own the short-lived browser credential handoff.
pub struct EnrollmentService {
    access: std::sync::Arc<crate::Store>,
    credentials: std::sync::Arc<credentials::Credentials>,
    audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
}
pub struct ResumeCommand<'a> {
    pub id: Uuid,
    pub password: &'a Password,
    pub operation: Uuid,
}
impl EnrollmentService {
    pub fn new(
        access: std::sync::Arc<crate::Store>,
        credentials: std::sync::Arc<credentials::Credentials>,
        audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Self {
        Self {
            access,
            credentials,
            audit_store,
        }
    }
    pub async fn create(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        input: &Create,
        continuation: &rss_identity_core::session::SessionSecret,
        key: Uuid,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Receipt, Error> {
        let permission = proof.enrollment(&input.device_id)?;
        audit.target(&input.device_id);
        let reference = self.credentials.insert(
            rss_identity_core::session::SessionSecret::parse(continuation.expose().into())
                .map_err(|_| Error::Unauthorized)?,
        )?;
        store::create_enrollment(
            &self.audit_store,
            permission,
            &input.password,
            input.source,
            reference,
            key,
            audit,
        )
        .await
    }
    pub async fn resume(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        command: ResumeCommand<'_>,
        continuation: &rss_identity_core::session::SessionSecret,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Receipt, Error> {
        let device = store::enrollment_target(&self.access, proof, command.id).await?;
        let permission = proof.enrollment(&device)?;
        audit.target(&device);
        let reference = self.credentials.insert(
            rss_identity_core::session::SessionSecret::parse(continuation.expose().into())
                .map_err(|_| Error::Unauthorized)?,
        )?;
        store::change_enrollment(
            &self.audit_store,
            permission,
            command.id,
            Some((command.password, reference)),
            command.operation,
            audit,
        )
        .await
    }
}

impl EnrollmentService {
    pub async fn status(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<read::Status, Error> {
        let device = store::enrollment_target(&self.access, proof, id).await?;
        let permission = proof.enrollment(&device)?;
        audit.target(&device);
        read::enrollment_status(&self.access, permission, id).await
    }
    pub async fn registrations(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        device: &str,
        page: read::Page,
    ) -> Result<read::Registrations, Error> {
        read::registration_list(&self.access, proof, device, page).await
    }
    pub async fn cancel(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
        key: Uuid,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Receipt, Error> {
        let device = store::enrollment_target(&self.access, proof, id).await?;
        let permission = proof.enrollment(&device)?;
        audit.target(&device);
        store::change_enrollment(&self.audit_store, permission, id, None, key, audit).await
    }
}
