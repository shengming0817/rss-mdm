//! Enrollment is the single lifecycle owner; the grant retains immutable authorization origin.
pub mod credentials;
pub mod managed;
pub mod read;
pub mod store;
use crate::Error;
use rss_mdm_inventory::ReportSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Immutable, administrator-selected Windows certificate and user-context profile.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum WindowsProfile {
    Full,
    Device,
}
impl WindowsProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Device => "Device",
        }
    }
    pub(crate) fn parse(value: Option<&str>) -> Result<Option<Self>, Error> {
        match value {
            None => Ok(None),
            Some("Full") => Ok(Some(Self::Full)),
            Some("Device") => Ok(Some(Self::Device)),
            _ => Err(Error::Storage),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub device_id: String,
    pub password: Password,
    pub source: ReportSource,
    pub windows_profile: Option<WindowsProfile>,
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
    pub self_service: bool,
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
    pub windows_profile: Option<WindowsProfile>,
}

impl Authorization {
    /// Ownership is immutable authorization origin, independent of mutable organization metadata.
    pub fn authorize(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    ) -> Result<(), Error> {
        proof.check_live()?;
        if self.actor != proof.principal_id() || self.instance != proof.instance_id() {
            return Err(Error::Unauthorized);
        }
        if !self.self_service {
            proof.enrollment(&self.device)?;
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfCreate {
    pub password: Password,
    pub source: ReportSource,
    pub windows_profile: Option<WindowsProfile>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfReceipt {
    pub device_id: String,
    #[serde(flatten)]
    pub receipt: Receipt,
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
    pub fn quotas(&self) -> crate::quotas::Quotas {
        crate::quotas::Quotas::new(self.access.clone(), self.audit_store.clone())
    }
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
        if input.source == ReportSource::AgentBuiltin {
            return Err(Error::Malformed);
        }
        if (input.source == ReportSource::MdmWindows) != input.windows_profile.is_some() {
            return Err(Error::Malformed);
        }
        let permission = proof.enrollment(&input.device_id)?;
        audit.target(&input.device_id);
        let reference = self.credentials.insert(
            rss_identity_core::session::SessionSecret::parse(continuation.expose().into())
                .map_err(|_| Error::Unauthorized)?,
        )?;
        let result = store::create_enrollment(
            &self.audit_store,
            permission,
            &input.password,
            input.source,
            input.windows_profile,
            reference,
            key,
            audit,
        )
        .await;
        self.settle_handoff(reference, result, audit)
    }
    pub async fn create_self(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        input: &SelfCreate,
        continuation: &rss_identity_core::session::SessionSecret,
        key: Uuid,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<SelfReceipt, Error> {
        if key.is_nil()
            || input.source == ReportSource::AgentBuiltin
            || (input.source == ReportSource::MdmWindows) != input.windows_profile.is_some()
        {
            return Err(Error::Malformed);
        }
        // Namespace is derived from authenticated identity and operation, never a device claim.
        let device_id = format!(
            "self:{}:{}:{}",
            proof.instance_id(),
            proof.principal_id(),
            key
        );
        let permission = proof.self_enrollment(&device_id)?;
        audit.target(&device_id);
        let reference = self.credentials.insert(
            rss_identity_core::session::SessionSecret::parse(continuation.expose().into())
                .map_err(|_| Error::Unauthorized)?,
        )?;
        let result = store::create_enrollment(
            &self.audit_store,
            permission,
            &input.password,
            input.source,
            input.windows_profile,
            reference,
            key,
            audit,
        )
        .await;
        let receipt = self.settle_handoff(reference, result, audit)?;
        Ok(SelfReceipt { device_id, receipt })
    }
    pub async fn resume(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        command: ResumeCommand<'_>,
        continuation: &rss_identity_core::session::SessionSecret,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Receipt, Error> {
        let permission = store::owned_permission(&self.access, proof, command.id).await?;
        let device = permission.device().to_owned();
        audit.target(&device);
        let reference = self.credentials.insert(
            rss_identity_core::session::SessionSecret::parse(continuation.expose().into())
                .map_err(|_| Error::Unauthorized)?,
        )?;
        let result = store::change_enrollment(
            &self.audit_store,
            permission,
            command.id,
            Some((command.password, reference)),
            command.operation,
            audit,
        )
        .await;
        self.settle_handoff(reference, result, audit)
    }
    fn settle_handoff<T>(
        &self,
        reference: Uuid,
        result: Result<T, Error>,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<T, Error> {
        // The lifecycle producer sets Replayed only after returning the locked
        // old receipt without using this attempt's reference.
        let replayed = matches!(
            audit.snapshot().management_result,
            Some(rss_mdm_audit_integration::ManagementResult::Replayed)
        );
        self.credentials.settle(reference, result, replayed)
    }
}

impl EnrollmentService {
    pub async fn status(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<read::Status, Error> {
        let permission = store::owned_permission(&self.access, proof, id).await?;
        let device = permission.device().to_owned();
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
        let permission = store::owned_permission(&self.access, proof, id).await?;
        let device = permission.device().to_owned();
        audit.target(&device);
        store::change_enrollment(&self.audit_store, permission, id, None, key, audit).await
    }
}
