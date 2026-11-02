//! Persistent Agent enrollment and online certificate authority.
//! ref: smallstep/certificates api/sign.go@v0.30.2; sqlx-core/src/transaction.rs@v0.9.0.
mod activation;
pub mod bootstrap;
pub mod configurations;
pub mod connections;
pub mod current_user;
pub mod da;
mod grants;
pub(crate) mod issuance;
pub mod native;
pub mod queries;
pub mod settings;
mod trust;
use crate::certificate_issuance::{Clock, DeviceIssuer};
use crate::{Error, Store, database::db};
use base64::{Engine, engine::general_purpose::STANDARD};
use issuance::{now, row_platform};
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_certificate::device_identity::VerifiedDeviceCsr;
use rss_mdm_device_trust::device_identity::DeviceIdentityTrust;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row, postgres::PgRow};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use uuid::Uuid;

/// Closed enrollment failure; the optional source is for internal classification only.
#[derive(Debug, thiserror::Error)]
#[error("Agent enrollment rejected: {code:?}")]
pub struct Failure {
    pub code: wire::ErrorCode,
    pub issuance_id: Option<Uuid>,
    pub source: Option<Error>,
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        use wire::ErrorCode as C;
        let code = match e {
            Error::Agent(c) => c,
            Error::EnrollmentPaused => C::EnrollmentPaused,
            Error::Malformed => C::MalformedRequest,
            Error::Unauthorized => C::InvalidIdentity,
            Error::Forbidden => C::PermissionDenied,
            Error::Conflict => C::OperationConflict,
            Error::CommitUnknown | Error::RollbackFailed => C::ActivationUnknown,
            Error::Capacity | Error::RegistrationLimit => C::RegistrationLimit,
            _ => C::ServiceUnavailable,
        };
        Self {
            code,
            issuance_id: None,
            source: Some(e),
        }
    }
}
impl From<rss_mdm_authorization_service::Error> for Failure {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Error::from(e).into()
    }
}
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
/// Coordinates allocated only by the registration owner at activation.
pub struct Binding {
    pub profile: rss_mdm_install_support::StorageProfile,
    pub tenant: rss_request_context::TenantId,
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub epoch: Uuid,
    pub operation: Uuid,
}
/// The Agent channel owns capability bindings and collection definitions.
pub trait RuntimeBinding: Send + Sync {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile;
    fn bind<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: Binding,
        profile: &'a wire::RuntimeProfile,
    ) -> Pending<'a, runtime::BindingProfile>;
}
/// The installation owner rechecks the exact frozen native installation authority.
pub trait NativeAdmission: Send + Sync {
    fn bootstrap<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a native::Source,
    ) -> Pending<'a, ()>;
    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        authority: &'a native::Source,
    ) -> Pending<'a, crate::enrollment::managed::Authority>;
}
pub struct Service {
    pub(crate) cursor: rss_mdm_query::cursor::CursorCodec,
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) store: Arc<Store>,
    audit: Arc<AuditStore>,
    issuer: Arc<DeviceIssuer>,
    clock: Arc<dyn Clock>,
    binding: Option<Arc<dyn RuntimeBinding>>,
    native: Option<Arc<dyn NativeAdmission>>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    installations: Option<Arc<dyn configurations::InstallationAdmission>>,
    bootstrap: Option<Arc<bootstrap::Configuration>>,
}
pub struct Assembly {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub tenant: rss_request_context::TenantId,
    pub store: Arc<Store>,
    pub audit: Arc<AuditStore>,
    pub issuer: Arc<DeviceIssuer>,
    pub clock: Arc<dyn Clock>,
    pub binding: Arc<dyn RuntimeBinding>,
    pub native: Option<Arc<dyn NativeAdmission>>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub installations: Option<Arc<dyn configurations::InstallationAdmission>>,
    pub bootstrap: Option<Arc<bootstrap::Configuration>>,
}
pub(crate) struct Change<R> {
    pub(crate) value: R,
    pub(crate) replay: bool,
}
impl Service {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.store.profile()
    }
    pub fn new(a: Assembly) -> Result<Self, Error> {
        if a.issuer.purpose() != rss_mdm_agent_wire::pki::Purpose::Agent
            || a.binding.storage_profile() != a.store.profile()
            || a.issuer.profile() != a.store.profile()
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            tenant: a.tenant,
            cursor: a.cursor,
            store: a.store,
            audit: a.audit,
            issuer: a.issuer,
            clock: a.clock,
            binding: Some(a.binding),
            native: a.native,
            protection: a.protection,
            installations: a.installations,
            bootstrap: a.bootstrap,
        })
    }
    pub fn service_id(&self) -> Result<Uuid, Error> {
        self.issuer
            .trust()
            .trust
            .public()
            .map(|t| t.service_id)
            .map_err(|_| Error::Configuration)
    }
    pub fn trust(&self) -> &Arc<DeviceIdentityTrust> {
        self.issuer.trust()
    }
    pub fn now(&self) -> Result<i64, Error> {
        self.clock.unix_seconds()
    }
    pub(crate) fn proof(&self, p: &AuthorizedPrincipal, a: &RequestAudit) -> Result<(), Error> {
        if p.profile() != self.profile()
            || p.tenant_id() != self.tenant.to_string()
            || a.tenant() != p.tenant_id()
        {
            return Err(Error::Forbidden);
        }
        p.check_live()?;
        p.bind_audit(a).map_err(Into::into)
    }
    pub(crate) async fn write<C: Send, R: Send>(
        &self,
        a: &RequestAudit,
        context: C,
        f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, Change<R>> + Send,
    ) -> Result<R, Error> {
        self.write_admitted(
            &self.audit,
            a,
            context,
            |_, _| Box::pin(async { Ok(()) }),
            f,
        )
        .await
    }
    /// One settlement implementation. Identity admission precedes every product lock.
    pub(crate) async fn write_admitted<C: Send, R: Send>(
        &self,
        source: &AuditStore,
        a: &RequestAudit,
        context: C,
        before: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, ()> + Send,
        f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, Change<R>> + Send,
    ) -> Result<R, Error> {
        let profile = self.profile();
        let installation = self.service_id()?;

        if a.profile() != profile || a.tenant() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(6));
        let out = source
            .write(
                self.tenant,
                &budget.source_control(),
                (
                    source,
                    a,
                    (self.tenant.to_string(), context, Some(f), Some(before)),
                ),
                |ctx, tx| {
                    Box::pin(async move {
                        let (store, a, context) = ctx;
                        let change = tx
                            .with_connection_context(context, |ctx, c| {
                                Box::pin(async move {
                                    let before = ctx.3.take().ok_or(Error::Corrupt)?;
                                    before(&mut ctx.1, c).await?;
                                    if crate::device::installation_in(profile, c).await?
                                        != installation
                                    {
                                        return Err(Error::Forbidden);
                                    }
                                    crate::admission::lock_in(profile, c, &ctx.0).await?;
                                    let f = ctx.2.take().ok_or(Error::Corrupt)?;
                                    f(&mut ctx.1, c).await
                                })
                            })
                            .await?;
                        let snapshot = a.snapshot();
                        if snapshot.intent != rss_mdm_audit_integration::AuditIntent::Routine {
                            let op = snapshot.operation_id.ok_or(Error::Malformed)?;
                            let fact = Fact::business(
                                a,
                                &format!("certificate-registration:{}:{op}", snapshot.action),
                                200,
                                "success",
                                None,
                            )?;
                            (if change.replay {
                                Ok(())
                            } else {
                                store.append(tx, &fact).await
                            })
                            .map_err(Error::from)?;
                        }
                        if change.replay {
                            a.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            )
                        }
                        a.mark_commit_started();
                        Ok(change.value)
                    })
                },
            )
            .await;
        crate::operations::settle(out, a)
    }
    async fn grant_live(&self, c: &mut PgConnection, row: &PgRow) -> Result<(), Error> {
        if row
            .try_get::<String, _>("certificate_purpose")
            .map_err(db)?
            != rss_mdm_pki_service::registry::purpose(self.issuer.purpose())
        {
            return Err(Error::Forbidden);
        }
        let profile = self.profile();

        if row.try_get::<String, _>("state").map_err(db)? == "revoked" {
            return Err(Error::Agent(wire::ErrorCode::GrantRevoked));
        }
        if row.try_get::<i64, _>("expiry").map_err(db)? <= now(c).await? {
            return Err(Error::Agent(wire::ErrorCode::GrantExpired));
        }
        if row.try_get::<String, _>("state").map_err(db)? == "pending" {
            return Err(Error::Agent(wire::ErrorCode::PermissionDenied));
        }
        if let Some(authority) = row
            .try_get::<Option<serde_json::Value>, _>("native_authority")
            .map_err(db)?
        {
            let source = native::source(profile, c, self.tenant, authority).await?;
            crate::lifecycle::require_work_in(
                profile,
                c,
                &self.tenant.to_string(),
                source.principal().device(),
            )
            .await?;
            self.native
                .as_ref()
                .ok_or(Error::Unsupported)?
                .validate(c, &source)
                .await?;
        }
        Ok(())
    }
}
fn digest(value: &impl Serialize) -> Result<String, Error> {
    serde_json::to_vec(value)
        .map(|v| hex(Sha256::digest(v)))
        .map_err(|_| Error::Malformed)
}
fn hex(value: impl AsRef<[u8]>) -> String {
    value.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn secret_digest(tenant: &str, id: Uuid, secret: &runtime::Secret) -> String {
    let mut h = Sha256::new();
    h.update(b"rss-device-certificate-grant/v1\0");
    h.update(tenant.as_bytes());
    h.update(id.as_bytes());
    h.update(secret.expose().as_bytes());
    hex(h.finalize())
}
fn check_secret(tenant: &str, row: &PgRow, secret: &runtime::Secret) -> Result<(), Error> {
    use subtle::ConstantTimeEq;
    let id: Uuid = row.try_get("id").map_err(db)?;
    let expected: String = row.try_get("secret_digest").map_err(db)?;
    if !bool::from(
        secret_digest(tenant, id, secret)
            .as_bytes()
            .ct_eq(expected.as_bytes()),
    ) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
fn version(v: u8, operation: Uuid) -> Result<(), Error> {
    if v != wire::API_VERSION || operation.is_nil() {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
fn csr(encoded: &str) -> Result<VerifiedDeviceCsr, Error> {
    if encoded.len() > 43692 {
        return Err(Error::Malformed);
    }
    let der = STANDARD.decode(encoded).map_err(|_| Error::Malformed)?;
    VerifiedDeviceCsr::verify(&der, rss_mdm_agent_wire::pki::Purpose::Agent)
        .map_err(|_| Error::Malformed)
}
async fn grant_row(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<PgRow, Error> {
    sqlx::query(crate::storage_profile::sql(profile).agent_grant_row_1)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)
}
fn receipt(row: &PgRow) -> Result<wire::GrantReceipt, Error> {
    let state = match row.try_get::<String, _>("state").map_err(db)?.as_str() {
        "revoked" => wire::GrantState::Revoked,
        _ if !row.try_get::<bool, _>("live").map_err(db)? => wire::GrantState::Expired,
        "pending" => wire::GrantState::Pending,
        "available" => wire::GrantState::Available,
        "consumed" => wire::GrantState::Consumed,
        _ => return Err(Error::Corrupt),
    };
    let platform = match row.try_get::<String, _>("platform").map_err(db)?.as_str() {
        "windows" => runtime::TaskPlatform::Windows,
        "macos" => runtime::TaskPlatform::Macos,
        _ => return Err(Error::Corrupt),
    };
    Ok(wire::GrantReceipt {
        wire_version: wire::API_VERSION,
        grant_id: row.try_get("id").map_err(db)?,
        state,
        expires_at: row.try_get("expiry").map_err(db)?,
        platform,
    })
}
fn platform(p: runtime::TaskPlatform) -> &'static str {
    match p {
        runtime::TaskPlatform::Windows => "windows",
        runtime::TaskPlatform::Macos => "macos",
    }
}

async fn authorize_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    permission: rss_mdm_authorization_service::Permission,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    p.check_live()?;
    rss_mdm_authorization_service::lock_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    rss_mdm_authorization_service::snapshot_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?
    .require(p, permission, None)
    .map_err(|_| Error::Forbidden)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "receipt", rename_all = "snake_case")]
pub(crate) enum ActivationResult {
    Agent(wire::ActivationReceipt),
    Da(rss_mdm_agent_wire::da::Registration),
}
impl ActivationResult {
    pub(crate) fn agent(self) -> Result<wire::ActivationReceipt, Error> {
        match self {
            Self::Agent(v) => Ok(v),
            _ => Err(Error::Forbidden),
        }
    }
    pub(crate) fn da(self) -> Result<rss_mdm_agent_wire::da::Registration, Error> {
        match self {
            Self::Da(v) => Ok(v),
            _ => Err(Error::Forbidden),
        }
    }
}

impl Service {
    pub(super) fn consumer_use(&self) -> crate::device::ConsumerUse {
        match self.registration_kind() {
            crate::device::RegistrationKind::DaDevice => {
                crate::device::ConsumerUse::DaConfiguration
            }
            _ => crate::device::ConsumerUse::AgentTask,
        }
    }
    pub(super) fn registration_kind(&self) -> crate::device::RegistrationKind {
        match self.issuer.purpose() {
            rss_mdm_agent_wire::pki::Purpose::DaDevice => crate::device::RegistrationKind::DaDevice,
            _ => crate::device::RegistrationKind::Agent,
        }
    }
    pub(super) fn registration_channel(&self) -> Option<&'static str> {
        self.registration_kind().channel().map(|c| c.as_str())
    }
    pub(super) fn registration_purpose(&self) -> crate::device::Purpose {
        match self.registration_kind() {
            crate::device::RegistrationKind::DaDevice => crate::device::Purpose::DaDevice,
            _ => crate::device::Purpose::Primary,
        }
    }
}
