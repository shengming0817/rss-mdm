//! Explicit choices of the standalone DA host; Identity still validates each public policy.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    pub kdf_concurrency: NonZeroUsize,
    pub kdf_memory_bytes: NonZeroU64,
    pub source_attempts: u32,
    pub source_window_seconds: u32,
    pub scope_attempts: u32,
    pub scope_window_seconds: u32,
    pub password_attempts: u32,
    pub password_window_seconds: u32,
    pub record_capacity: u32,
    pub cleanup_batch: u16,
    pub claim_seconds: u64,
    pub provider_capacity: NonZeroU16,
    pub profile_receipt_capacity: NonZeroU32,
    pub request_seconds: u64,
    pub startup_seconds: u64,
    pub maintenance_seconds: u64,
    pub profile_bytes: usize,
    pub profile_members: usize,
    pub profile_depth: usize,
    pub profile_array: usize,
    pub profile_max_age_seconds: u32,
    pub drain_seconds: u64,
    pub rp_generation: i64,
    pub oidc_request_seconds: u64,
    pub oidc_connect_seconds: u64,
    pub oidc_response_bytes: usize,
    pub oidc_jwks_keys: usize,
    pub audit_recovery_seconds: u64,
    pub audit_recovery_rows: u16,
    pub audit_recovery_bytes: u64,
}
pub(super) fn seconds(n: u64) -> Result<Duration> {
    let value = Duration::from_secs(n);
    if n == 0
        || rss_request_context::Clock::now(&crate::host::Timer)
            .checked_add(value)
            .is_none()
    {
        return Err(Error::Configuration);
    }
    Ok(value)
}
impl IdentityPolicy {
    pub fn kdf(&self) -> Result<rss_identity_core::account::PasswordKdf> {
        rss_identity_core::account::PasswordKdf::new(self.kdf_concurrency, self.kdf_memory_bytes)
            .map_err(|_| Error::Configuration)
    }
    pub fn startup(&self) -> Result<Duration> {
        seconds(self.startup_seconds)
    }
    pub fn maintenance(&self) -> Result<Duration> {
        seconds(self.maintenance_seconds)
    }
    pub fn request(&self) -> Result<Duration> {
        seconds(self.request_seconds)
    }
    pub fn drain(&self) -> Result<Duration> {
        seconds(self.drain_seconds)
    }
    pub fn rp(&self) -> Result<rss_identity_postgres::RpGeneration> {
        rss_identity_postgres::RpGeneration::new(self.rp_generation)
            .map_err(|_| Error::Configuration)
    }
    pub fn transport(&self) -> Result<rss_identity_oidc::TransportPolicy> {
        rss_identity_oidc::TransportPolicy::new(
            seconds(self.oidc_request_seconds)?,
            seconds(self.oidc_connect_seconds)?,
            self.oidc_response_bytes,
            self.oidc_jwks_keys,
        )
        .map_err(|_| Error::Configuration)
    }
    pub fn audit_budget(&self) -> Result<rss_mdm_audit_integration::budget::AuditBudget> {
        Ok(rss_mdm_audit_integration::budget::AuditBudget::new(
            seconds(self.audit_recovery_seconds)?,
        ))
    }
    pub fn audit_limit(&self) -> Result<rss_ledger_postgres::ReadLimit> {
        rss_ledger_postgres::ReadLimit::new(self.audit_recovery_rows, self.audit_recovery_bytes)
            .map_err(|_| Error::Configuration)
    }
    fn authority(
        &self,
        installation: &super::Installation,
        integrity: rss_audit_postgres::Integrity,
    ) -> Result<rss_identity_postgres::AuthorityConfig> {
        use rss_identity_postgres::{AttemptWindow, AuthenticationPolicy};
        if self.claim_seconds < self.request_seconds.max(self.maintenance_seconds) {
            return Err(Error::Configuration);
        }
        let bad = |_| Error::Configuration;
        let authentication = AuthenticationPolicy::new(
            AttemptWindow::new(self.source_attempts, self.source_window_seconds).map_err(bad)?,
            AttemptWindow::new(self.scope_attempts, self.scope_window_seconds).map_err(bad)?,
            AttemptWindow::new(self.password_attempts, self.password_window_seconds)
                .map_err(bad)?,
            self.record_capacity,
            self.cleanup_batch,
            seconds(self.claim_seconds)?,
        )
        .map_err(bad)?;
        rss_identity_postgres::AuthorityConfig::new(
            rss_identity_core::InstanceId::parse(&installation.instance.to_string())
                .map_err(|_| Error::Configuration)?,
            rss_identity_core::session::SessionPolicy::new(900, 14400)
                .map_err(|_| Error::Configuration)?,
            integrity,
            rss_mdm_audit_integration::budget::identity_write_budget(4)
                .map_err(|_| Error::Configuration)?,
        )
        .map_err(bad)?
        .with_authentication_policy(authentication)
        .with_profile_limits(
            rss_identity_core::profile::ProfileLimits::new(
                self.profile_bytes,
                self.profile_members,
                self.profile_depth,
                self.profile_array,
                self.profile_max_age_seconds,
            )
            .map_err(|_| Error::Configuration)?,
        )
        .with_profile_receipt_capacity(self.profile_receipt_capacity)
        .with_provider_capacity(self.provider_capacity)
        .map_err(bad)
    }
}

pub struct Compiled {
    pub kdf: std::sync::Arc<rss_identity_core::account::PasswordKdf>,
    pub authority: rss_identity_postgres::AuthorityConfig,
    pub transport: rss_identity_oidc::TransportPolicy,
    pub rp: rss_identity_postgres::RpGeneration,
    pub request: Duration,
    pub startup: Duration,
    pub maintenance: Duration,
    pub drain: Duration,
}
impl IdentityPolicy {
    pub(super) fn compile(
        &self,
        installation: &super::Installation,
        integrity: rss_audit_postgres::Integrity,
    ) -> Result<Compiled> {
        seconds(self.audit_recovery_seconds)?;
        self.audit_limit()?;
        Ok(Compiled {
            authority: self.authority(installation, integrity)?,
            transport: self.transport()?,
            rp: self.rp()?,
            request: self.request()?,
            startup: self.startup()?,
            maintenance: self.maintenance()?,
            drain: self.drain()?,
            kdf: std::sync::Arc::new(self.kdf()?),
        })
    }
}
