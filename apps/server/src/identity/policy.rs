//! Product choices for the pinned Identity SDK. Constructors remain owned by Identity.
//! ref: rss-identity app/identity/src/config.rs@242f87970a8b3bc25c078794fde139a4cebbbe59
use super::{AuthorityConfig, Error, InstanceId, invalid};
use serde::{Deserialize, Serialize};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    pub password: PasswordWork,
    pub authentication: Authentication,
    pub profile: Profile,
    pub provider_capacity: NonZeroU16,
    pub request_seconds: u64,
    pub startup_seconds: u64,
    pub maintenance_seconds: u64,
    pub kdf_drain_seconds: u64,
    pub rp_generation: i64,
    pub transport: Transport,
    pub jwks: Jwks,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordWork {
    pub concurrency: NonZeroUsize,
    pub reserved_memory_bytes: NonZeroU64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptWindow {
    pub limit: u32,
    pub seconds: u32,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub source: AttemptWindow,
    pub scope: AttemptWindow,
    pub password: AttemptWindow,
    pub record_capacity: u32,
    pub cleanup_batch: u16,
    pub claim_seconds: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub source_page_size: u16,
    pub bytes: usize,
    pub members: usize,
    pub depth: usize,
    pub array: usize,
    pub max_age_seconds: u32,
    pub receipt_capacity: NonZeroU32,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub request_seconds: u64,
    pub connect_seconds: u64,
    pub max_response_bytes: usize,
    pub max_jwks_keys: usize,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Jwks {
    pub ttl_seconds: u64,
    pub max_tenants: NonZeroUsize,
    pub refresh_cooldown_seconds: u64,
    pub max_token_bytes: usize,
}
pub(crate) fn seconds(value: u64) -> Result<Duration, Error> {
    let duration = Duration::from_secs(value);
    if value == 0
        || rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            .checked_add(duration)
            .is_none()
    {
        return Err(invalid());
    }
    Ok(duration)
}
impl PasswordWork {
    pub(crate) fn build(&self) -> Result<rss_identity_core::account::PasswordKdf, Error> {
        rss_identity_core::account::PasswordKdf::new(self.concurrency, self.reserved_memory_bytes)
            .map_err(|_| invalid())
    }
}
impl Transport {
    pub(crate) fn build(&self) -> Result<rss_identity_oidc::TransportPolicy, Error> {
        rss_identity_oidc::TransportPolicy::new(
            seconds(self.request_seconds)?,
            seconds(self.connect_seconds)?,
            self.max_response_bytes,
            self.max_jwks_keys,
        )
        .map_err(|_| invalid())
    }
}
impl Jwks {
    pub(crate) fn build(&self) -> Result<rss_identity_oidc::entra::JwksCachePolicy, Error> {
        if self.max_tenants.get() > 1024 || self.max_token_bytes == 0 {
            return Err(invalid());
        }
        rss_identity_oidc::entra::JwksCachePolicy::new(
            seconds(self.ttl_seconds)?,
            self.max_tenants,
            seconds(self.refresh_cooldown_seconds)?,
        )
        .map_err(|_| invalid())
    }
}
impl RuntimePolicy {
    /// Initial installation values, serialized explicitly into the current configuration.
    pub(crate) fn installation() -> Self {
        Self {
            password: PasswordWork {
                concurrency: NonZeroUsize::new(4).expect("positive installation value"),
                reserved_memory_bytes: NonZeroU64::new(128 * 1024 * 1024)
                    .expect("positive installation value"),
            },
            authentication: Authentication {
                source: AttemptWindow {
                    limit: 30,
                    seconds: 300,
                },
                scope: AttemptWindow {
                    limit: 5,
                    seconds: 900,
                },
                password: AttemptWindow {
                    limit: 5,
                    seconds: 600,
                },
                record_capacity: 10000,
                cleanup_batch: 128,
                claim_seconds: 60,
            },
            profile: Profile {
                source_page_size: 64,
                bytes: 65536,
                members: 1024,
                depth: 8,
                array: 1024,
                max_age_seconds: 86400,
                receipt_capacity: NonZeroU32::new(4096).expect("positive installation value"),
            },
            provider_capacity: NonZeroU16::new(100).expect("positive installation value"),
            request_seconds: 10,
            startup_seconds: 10,
            maintenance_seconds: 10,
            kdf_drain_seconds: 5,
            rp_generation: 1,
            transport: Transport {
                request_seconds: 5,
                connect_seconds: 3,
                max_response_bytes: 1024 * 1024,
                max_jwks_keys: 128,
            },
            jwks: Jwks {
                ttl_seconds: 60,
                max_tenants: NonZeroUsize::new(128).expect("positive installation value"),
                refresh_cooldown_seconds: 1,
                max_token_bytes: 32768,
            },
        }
    }
    pub(crate) fn compile(
        &self,
        instance: InstanceId,
        integrity: rss_audit_postgres::Integrity,
    ) -> Result<Compiled, Error> {
        for value in [
            self.request_seconds,
            self.startup_seconds,
            self.maintenance_seconds,
            self.kdf_drain_seconds,
        ] {
            seconds(value)?;
        }
        if self.authentication.claim_seconds < self.request_seconds.max(self.maintenance_seconds) {
            return Err(invalid());
        }
        if !(1..=1024).contains(&self.profile.source_page_size) {
            return Err(invalid());
        }
        if self.provider_capacity.get() > rss_identity_core::federation::MAX_PROVIDERS {
            return Err(invalid());
        }
        Ok(Compiled {
            authority: self.authority(instance, integrity)?,
            transport: self.transport.build()?,
            jwks: self.jwks.build()?,
            rp: self.rp()?,
            request: seconds(self.request_seconds)?,
            startup: seconds(self.startup_seconds)?,
            maintenance: seconds(self.maintenance_seconds)?,
            drain: seconds(self.kdf_drain_seconds)?,
            kdf: std::sync::Arc::new(self.password.build()?),
        })
    }
    fn authentication_policy(&self) -> Result<rss_identity_postgres::AuthenticationPolicy, Error> {
        let window = |v: &AttemptWindow| {
            rss_identity_postgres::AttemptWindow::new(v.limit, v.seconds).map_err(super::failure)
        };
        let a = &self.authentication;
        rss_identity_postgres::AuthenticationPolicy::new(
            window(&a.source)?,
            window(&a.scope)?,
            window(&a.password)?,
            a.record_capacity,
            a.cleanup_batch,
            seconds(a.claim_seconds)?,
        )
        .map_err(super::failure)
    }
    fn profile_limits(&self) -> Result<rss_identity_core::profile::ProfileLimits, Error> {
        let p = &self.profile;
        rss_identity_core::profile::ProfileLimits::new(
            p.bytes,
            p.members,
            p.depth,
            p.array,
            p.max_age_seconds,
        )
        .map_err(|_| invalid())
    }
    fn authority(
        &self,
        instance: InstanceId,
        integrity: rss_audit_postgres::Integrity,
    ) -> Result<AuthorityConfig, Error> {
        AuthorityConfig::new(
            instance,
            rss_identity_core::session::SessionPolicy::new(900, 14400).map_err(|_| invalid())?,
            integrity,
        )
        .map_err(super::failure)?
        .with_authentication_policy(self.authentication_policy()?)
        .with_profile_limits(self.profile_limits()?)
        .with_profile_receipt_capacity(self.profile.receipt_capacity)
        .with_provider_capacity(self.provider_capacity)
        .map_err(super::failure)
    }
    pub(crate) fn rp(&self) -> Result<rss_identity_postgres::RpGeneration, Error> {
        rss_identity_postgres::RpGeneration::new(self.rp_generation).map_err(super::failure)
    }
}

#[derive(Clone)]
pub(crate) struct Compiled {
    pub kdf: std::sync::Arc<rss_identity_core::account::PasswordKdf>,
    pub authority: AuthorityConfig,
    pub transport: rss_identity_oidc::TransportPolicy,
    pub jwks: rss_identity_oidc::entra::JwksCachePolicy,
    pub rp: rss_identity_postgres::RpGeneration,
    pub request: Duration,
    pub startup: Duration,
    pub maintenance: Duration,
    pub drain: Duration,
}
