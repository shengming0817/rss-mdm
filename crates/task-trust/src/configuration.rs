//! Borrowed DA signing operations. Policy owns publication; the caller owns settlement/audit.
//! ref: ring src/ec/curve25519/ed25519/signing.rs@2723abbca9e83347d82b056d5b239c6604f786df.
use crate::{Error, Service, Use, trust};
use rss_mdm_agent_wire::da::{
    Audience, Configuration, ConfigurationTrust, Export, SignedConfiguration,
};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::{PgConnection, Row};
use std::{num::NonZeroU32, sync::Arc};
use uuid::Uuid;

pub struct ConfigurationService {
    trust: Arc<Service>,
    max_lifetime: NonZeroU32,
}
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(crate::Failure::Database)
}
impl ConfigurationService {
    pub fn new(trust: Arc<Service>, max_lifetime: NonZeroU32) -> Result<Self, Error> {
        if trust.signing.usage != Use::DaConfiguration {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            trust,
            max_lifetime,
        })
    }
    pub fn trust(&self) -> &Arc<Service> {
        &self.trust
    }
    async fn authorize(
        &self,
        c: &mut PgConnection,
        p: &AuthorizedPrincipal,
        config: &Configuration,
        write: bool,
    ) -> Result<(), Error> {
        if p.profile() != self.trust.signing.profile
            || p.tenant_id() != self.trust.tenant.to_string()
        {
            return Err(Error::Forbidden);
        }
        p.check_live()?;
        rss_mdm_authorization_service::lock_shared_on(
            p.authority_profile(),
            c,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        let scope = match &config.audience {
            Audience::Tenant => None,
            Audience::Device { device, .. } => Some(device.as_str()),
        };
        rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            c,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?
        .require(
            p,
            match (scope.is_some(), write) {
                (true, true) => Permission::ConfigurationWrite,
                (true, false) => Permission::OperationRead,
                (false, true) => Permission::RegistrationConfigurationWrite,
                (false, false) => Permission::RegistrationConfigurationRead,
            },
            scope,
        )?;
        Ok(())
    }
    /// Exact replay precedes current publication/time checks. No new signature is produced.
    pub async fn replay_on(
        &self,
        c: &mut PgConnection,
        p: &AuthorizedPrincipal,
        input: &Export,
    ) -> Result<Option<SignedConfiguration>, Error> {
        if input.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3129))")
            .bind(format!("{}:{}", self.trust.tenant, input.operation_id))
            .execute(&mut *c)
            .await
            .map_err(db)?;
        let sql = crate::storage_profile::sql(self.trust.signing.profile, Use::DaConfiguration);
        let row = sqlx::query(sql.configuration_receipt)
            .bind(self.trust.tenant.to_string())
            .bind(input.operation_id)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?;
        let Some(row) = row else { return Ok(None) };
        if row.try_get::<String, _>("actor").map_err(db)? != p.principal_id()
            || row.try_get::<String, _>("instance").map_err(db)? != p.instance_id()
            || row.try_get::<serde_json::Value, _>("request").map_err(db)?
                != serde_json::to_value(input).map_err(|_| Error::Malformed)?
        {
            return Err(Error::Conflict);
        }
        let signed: SignedConfiguration =
            serde_json::from_value(row.try_get("result").map_err(db)?)
                .map_err(|_| Error::Conflict)?;
        self.authorize(c, p, &signed.decode().map_err(|_| Error::Conflict)?, true)
            .await?;
        Ok(Some(signed))
    }
    /// Issue only a typed publication selected by the product on this original transaction.
    /// The caller holds its publication/authorization locks and appends one audit fact.
    pub async fn issue_on(
        &self,
        c: &mut PgConnection,
        p: &AuthorizedPrincipal,
        input: &Export,
        mut config: Configuration,
    ) -> Result<SignedConfiguration, Error> {
        self.authorize(c, p, &config, true).await?;
        if input.policy != config.id
            || input.version != config.version
            || input.operation_id != config.operation_id
            || input.delivery != config.delivery
            || input.lifetime_seconds == 0
            || input.lifetime_seconds > self.max_lifetime.get()
        {
            return Err(Error::Malformed);
        }
        let profile = self.trust.signing.profile;
        let tenant = self.trust.tenant;
        let current = trust::current(profile, Use::DaConfiguration, c, tenant).await?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        if config.service_id != current.service_id || config.tenant != current.tenant {
            return Err(Error::Forbidden);
        }
        config.trust_revision = current.revision;
        config.issued_at = now;
        config.expires_at = now
            .checked_add(i64::from(input.lifetime_seconds))
            .ok_or(Error::Malformed)?;
        let signer = self
            .trust
            .signing
            .signer
            .as_ref()
            .ok_or(Error::Unsupported)?;
        trust::require_active_key(profile, Use::DaConfiguration, c, tenant, signer.key_id())
            .await?;
        let signed = signer.sign_configuration(config.clone())?;
        trust::retain_until(
            profile,
            Use::DaConfiguration,
            c,
            tenant,
            signer.key_id(),
            config.expires_at,
        )
        .await?;
        sqlx::query(crate::storage_profile::sql(profile, Use::DaConfiguration).configuration_save)
            .bind(tenant.to_string())
            .bind(input.operation_id)
            .bind(p.principal_id())
            .bind(p.instance_id())
            .bind(serde_json::to_value(input).map_err(|_| Error::Malformed)?)
            .bind(config.id)
            .bind(i64::try_from(config.revision).map_err(|_| Error::Malformed)?)
            .bind(i64::try_from(config.trust_revision).map_err(|_| Error::Malformed)?)
            .bind(serde_json::to_value(&signed).map_err(|_| Error::Malformed)?)
            .bind(config.issued_at)
            .bind(config.expires_at)
            .execute(c)
            .await
            .map_err(db)?;
        Ok(signed)
    }
    /// Newest unexpired backend artifact for an exact current publication revision.
    pub async fn current_on(
        &self,
        c: &mut PgConnection,
        policy: Uuid,
        revision: i64,
    ) -> Result<Option<SignedConfiguration>, Error> {
        let value: Option<serde_json::Value> = sqlx::query_scalar(
            crate::storage_profile::sql(self.trust.signing.profile, Use::DaConfiguration)
                .configuration_current,
        )
        .bind(self.trust.tenant.to_string())
        .bind(policy)
        .bind(revision)
        .fetch_optional(c)
        .await
        .map_err(db)?;
        value
            .map(|v| serde_json::from_value(v).map_err(|_| Error::Conflict))
            .transpose()
    }
    /// Read the original immutable artifact; product authorization is checked by the consumer.
    pub async fn read_on(
        &self,
        c: &mut PgConnection,
        operation: Uuid,
    ) -> Result<SignedConfiguration, Error> {
        let row = sqlx::query(
            crate::storage_profile::sql(self.trust.signing.profile, Use::DaConfiguration)
                .configuration_receipt,
        )
        .bind(self.trust.tenant.to_string())
        .bind(operation)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::NotFound)?;
        serde_json::from_value(row.try_get("result").map_err(db)?).map_err(|_| Error::Conflict)
    }
    /// Recover a historical export under current management scope, without reissuing it.
    pub async fn operation_on(
        &self,
        c: &mut PgConnection,
        p: &AuthorizedPrincipal,
        operation: Uuid,
    ) -> Result<SignedConfiguration, Error> {
        let value = self.read_on(c, operation).await?;
        self.authorize(c, p, &value.decode().map_err(|_| Error::Conflict)?, false)
            .await?;
        Ok(value)
    }
    /// Current identity, exact artifact audience and independently installed trust are mandatory.
    pub async fn admit_device_on(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        signed: &SignedConfiguration,
    ) -> Result<Configuration, Error> {
        self.trust.signing.revalidate(c, p).await?;
        let config = signed.decode().map_err(|_| Error::Conflict)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        let identity = rss_mdm_agent_wire::da::ReportIdentity {
            service_id: p.installation(),
            tenant: Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Malformed)?,
            device_id: p.device().to_string(),
        };
        if !config.permits(&identity, p.device())
            || config.issued_at > now
            || config.expires_at <= now
        {
            return Err(Error::Forbidden);
        }
        trust::require_verification(
            self.trust.signing.profile,
            Use::DaConfiguration,
            c,
            p,
            &signed.key_id,
        )
        .await?;
        Ok(config)
    }
}
/// Verify exact payload bytes with independently obtained, purpose-specific installed trust.
/// Scope/current-publication checks remain mandatory at the consuming product boundary.
pub fn verify(
    signed: &SignedConfiguration,
    installed: &ConfigurationTrust,
    now: i64,
) -> Result<Configuration, Error> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let key = installed
        .keys
        .iter()
        .find(|k| {
            k.id == signed.key_id
                && matches!(
                    k.state,
                    rss_mdm_agent_wire::task_trust::KeyState::Active
                        | rss_mdm_agent_wire::task_trust::KeyState::VerifyOnly
                )
        })
        .ok_or(Error::Forbidden)?;
    let public = URL_SAFE_NO_PAD
        .decode(&key.public_key)
        .map_err(|_| Error::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| Error::Malformed)?;
    let bytes = SignedConfiguration::signing_bytes(&signed.payload, &signed.key_id)
        .map_err(|_| Error::Malformed)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(&bytes, &signature)
        .map_err(|_| Error::Forbidden)?;
    let value = signed.decode().map_err(|_| Error::Malformed)?;
    if value.service_id != installed.service_id
        || value.tenant != installed.tenant
        || value.trust_revision > installed.revision
        || value.issued_at > now
        || value.expires_at <= now
    {
        return Err(Error::Forbidden);
    }
    Ok(value)
}
