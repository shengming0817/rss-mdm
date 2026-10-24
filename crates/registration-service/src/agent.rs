//! Persistent Agent enrollment and online certificate authority.
//! ref: smallstep/certificates api/sign.go@v0.30.2; sqlx-core/src/transaction.rs@v0.9.0.
mod activation;
pub mod bootstrap;
pub mod configurations;
pub mod connections;
pub mod current_user;
mod grants;
pub(crate) mod issuance;
pub mod native;
pub mod settings;
mod trust;
use crate::agent_pki::{AgentIssuer, Clock};
use crate::{Error, Store, database::db};
use base64::{Engine, engine::general_purpose::STANDARD};
use issuance::{now, row_platform};
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_certificate::agent::VerifiedAgentCsr;
use rss_mdm_device_trust::agent::AgentTrust;
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
    pub tenant: rss_request_context::TenantId,
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub epoch: Uuid,
    pub operation: Uuid,
}
/// The Agent channel owns capability bindings and collection definitions.
pub trait RuntimeBinding: Send + Sync {
    fn bind<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: Binding,
        profile: &'a wire::RuntimeProfile,
    ) -> Pending<'a, runtime::BindingProfile>;
}
/// Execution owns rechecking the exact frozen native installation authorization.
pub trait NativeAdmission: Send + Sync {
    fn bootstrap<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a native::Source,
    ) -> Pending<'a, ()>;
    fn grant<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a native::Source,
        input: &'a wire::NativeGrantRequest,
    ) -> Pending<'a, (wire::GrantReceipt, bool)>;

    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        authority: &'a native::Source,
    ) -> Pending<'a, ()>;
}
pub struct Service {
    cursor: rss_mdm_query::cursor::CursorCodec,
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) store: Arc<Store>,
    audit: Arc<AuditStore>,
    pub(crate) access_audit: Arc<AuditStore>,
    issuer: Arc<AgentIssuer>,
    clock: Arc<dyn Clock>,
    binding: Arc<dyn RuntimeBinding>,
    native: Arc<dyn NativeAdmission>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    installations: Arc<dyn configurations::InstallationAdmission>,
    bootstrap: Option<Arc<bootstrap::Configuration>>,
}
pub struct Assembly {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub tenant: rss_request_context::TenantId,
    pub store: Arc<Store>,
    pub audit: Arc<AuditStore>,
    pub access_audit: Arc<AuditStore>,
    pub issuer: Arc<AgentIssuer>,
    pub clock: Arc<dyn Clock>,
    pub binding: Arc<dyn RuntimeBinding>,
    pub native: Arc<dyn NativeAdmission>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub installations: Arc<dyn configurations::InstallationAdmission>,
    pub bootstrap: Option<Arc<bootstrap::Configuration>>,
}
pub(crate) struct Change<R> {
    pub(crate) value: R,
    pub(crate) replay: bool,
    pub(crate) digest: String,
}
impl Service {
    pub fn new(a: Assembly) -> Result<Self, Error> {
        Ok(Self {
            tenant: a.tenant,
            cursor: a.cursor,
            store: a.store,
            audit: a.audit,
            access_audit: a.access_audit,
            issuer: a.issuer,
            clock: a.clock,
            binding: a.binding,
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
    pub fn trust(&self) -> &Arc<AgentTrust> {
        self.issuer.trust()
    }
    pub fn now(&self) -> Result<i64, Error> {
        self.clock.unix_seconds()
    }
    pub(crate) fn proof(&self, p: &AuthorizedPrincipal, a: &RequestAudit) -> Result<(), Error> {
        if p.tenant_id() != self.tenant.to_string() || a.tenant() != p.tenant_id() {
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
        if a.tenant() != self.tenant.to_string() {
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
                                    crate::admission::lock_in(c, &ctx.0).await?;
                                    let f = ctx.2.take().ok_or(Error::Corrupt)?;
                                    f(&mut ctx.1, c).await
                                })
                            })
                            .await?;
                        let snapshot = a.snapshot();
                        let op = snapshot.operation_id.ok_or(Error::Malformed)?;
                        let fact = Fact::business(
                            a,
                            &format!("agent-enroll:{}:{op}", snapshot.action),
                            change.digest.as_bytes(),
                            200,
                            "success",
                            None,
                        )?;
                        store
                            .append(tx, &fact, change.replay)
                            .await
                            .map_err(Error::from)?;
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
            let source = native::source(c, self.tenant, authority).await?;
            crate::lifecycle::require_work_in(
                c,
                &self.tenant.to_string(),
                source.principal().device(),
            )
            .await?;
            self.native.validate(c, &source).await?
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
    h.update(b"rss-mdm-agent-bootstrap/v1\0");
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
fn csr(encoded: &str) -> Result<VerifiedAgentCsr, Error> {
    if encoded.len() > 43692 {
        return Err(Error::Malformed);
    }
    let der = STANDARD.decode(encoded).map_err(|_| Error::Malformed)?;
    VerifiedAgentCsr::verify(&der).map_err(|_| Error::Malformed)
}
async fn grant_row(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<PgRow, Error> {
    sqlx::query("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?.ok_or(Error::Unauthorized)
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
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    permission: rss_mdm_authorization_service::Permission,
) -> Result<(), Error> {
    p.check_live()?;
    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id()).await?;
    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await?
        .require(p, permission, None)
        .map_err(|_| Error::Forbidden)
}

#[cfg(feature = "integration")]
mod fixture;
