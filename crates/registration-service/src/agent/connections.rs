//! Registration-owned connection configuration, key material and installation receipts.
//! ref: ring src/ec/curve25519/ed25519/signing.rs; sqlx-core/src/transaction.rs.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rss_mdm_agent_wire::connections as w;
use rss_mdm_authorization_service::Permission;
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use std::collections::BTreeMap;

/// HTTPS origins installed on the Agent gateway, preserving its preferred entry.
#[derive(Clone)]
pub struct InstalledOrigins {
    preferred: String,
    origins: Vec<String>,
}

impl InstalledOrigins {
    pub fn new(preferred: String, additional: &[String]) -> Result<Self, Error> {
        let mut origins = additional.to_vec();
        origins.push(preferred.clone());
        origins.sort();
        if origins.len() > w::MAX_ORIGINS || origins.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Configuration);
        }
        for origin in &origins {
            w::validate_origin(origin).map_err(|_| Error::Configuration)?;
        }
        Ok(Self { preferred, origins })
    }

    pub fn preferred(&self) -> &str {
        &self.preferred
    }

    pub fn origins(&self) -> &[String] {
        &self.origins
    }
}

/// Read projection, not a claim that an offline device has applied a revision.
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub service_id: Uuid,
    pub configuration: Option<w::SignedConfiguration>,
    pub verification_keys: BTreeMap<String, String>,
    pub convergence: Convergence,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Convergence {
    pub target_revision: Option<u64>,
    pub active_devices: u64,
    pub confirmed_devices: u64,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceQuery {
    pub revision: u64,
    pub after: Option<Uuid>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedDevices {
    pub target_revision: u64,
    pub items: Vec<DeviceStatus>,
    pub next: Option<Uuid>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStatus {
    pub device: rss_mdm_agent_wire::DeviceId,
    pub installed_revision: Option<u64>,
    pub origin: Option<String>,
    pub received_at: Option<i64>,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub target_revision: Option<u64>,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub acknowledgement: Option<w::Acknowledgement>,
    pub received_at: Option<i64>,
    pub failure: Option<FailureObservation>,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureObservation {
    pub report: w::FailureReport,
    pub origin: String,
    pub received_at: i64,
}
fn key_aad(tenant: &str, key_id: &str) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Configuration)?,
        key_id,
        "agent-configuration.private-key",
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Configuration)
}

/// Read existing configuration keys only. Task-key state cannot replace this trust root.
pub(super) async fn signer_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    protection: &Protector,
) -> Result<configurations::Signer, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).agent_connections_signer_on_1)
        .bind(tenant)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::Conflict)?;
    let id: String = row.try_get("key_id").map_err(db)?;
    let public: String = row.try_get("public_key").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &key_aad(tenant, &id)?)
        .map_err(|_| Error::Corrupt)?;
    configurations::Signer::new(
        private.expose(),
        &id,
        &BTreeMap::from([(id.clone(), public)]),
    )
}

async fn ensure_signer_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    protection: &Protector,
) -> Result<configurations::Signer, Error> {
    let exists: bool = sqlx::query_scalar(
        crate::storage_profile::sql(profile).agent_connections_ensure_signer_on_1,
    )
    .bind(tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if !exists {
        let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| Error::Configuration)?;
        let key = Ed25519KeyPair::from_pkcs8(private.as_ref()).map_err(|_| Error::Configuration)?;
        let id = Uuid::new_v4().to_string();
        let sealed = protection
            .seal_bytes(private.as_ref(), &key_aad(tenant, &id)?)
            .map_err(|_| Error::Configuration)?;
        sqlx::query(crate::storage_profile::sql(profile).agent_connections_ensure_signer_on_2)
            .bind(tenant)
            .bind(id)
            .bind(URL_SAFE_NO_PAD.encode(key.public_key().as_ref()))
            .bind(sealed)
            .execute(&mut *c)
            .await
            .map_err(db)?;
    }
    signer_on(profile, c, tenant, protection).await
}

async fn service_id_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
) -> Result<Uuid, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).agent_connections_service_id_on_1)
        .fetch_one(c)
        .await
        .map_err(db)
}
async fn lock(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2894))")
        .bind(tenant)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
async fn signed_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    revision: Option<u64>,
) -> Result<Option<w::SignedConfiguration>, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).agent_connections_signed_on_1)
        .bind(tenant)
        .bind(
            revision
                .map(i64::try_from)
                .transpose()
                .map_err(|_| Error::Malformed)?,
        )
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let value: w::SignedConfiguration =
        serde_json::from_value(row.try_get("document").map_err(db)?).map_err(|_| Error::Corrupt)?;
    value.validate().map_err(|_| Error::Corrupt)?;
    let key: String = row.try_get("public_key").map_err(db)?;
    let key = URL_SAFE_NO_PAD.decode(key).map_err(|_| Error::Corrupt)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&value.signature)
        .map_err(|_| Error::Corrupt)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(
            &value
                .configuration
                .signing_bytes()
                .map_err(|_| Error::Corrupt)?,
            &signature,
        )
        .map_err(|_| Error::Corrupt)?;
    if value.configuration.service_id != service_id_on(profile, c).await?
        || value.configuration.tenant_id.to_string() != tenant
    {
        return Err(Error::Corrupt);
    }
    Ok(Some(value))
}
pub(super) async fn current_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
) -> Result<w::SignedConfiguration, Error> {
    signed_on(profile, c, tenant, None)
        .await?
        .ok_or(Error::Conflict)
}

async fn store_version(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    signed: &w::SignedConfiguration,
) -> Result<(), Error> {
    sqlx::query(crate::storage_profile::sql(profile).agent_connections_insert_version)
        .bind(tenant)
        .bind(i64::try_from(signed.configuration.revision).map_err(|_| Error::Malformed)?)
        .bind(serde_json::to_value(signed).map_err(|_| Error::Malformed)?)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}

impl InstalledOrigins {
    async fn sign_on(
        &self,
        profile: rss_mdm_install_support::StorageProfile,
        c: &mut PgConnection,
        tenant: &str,
        signer: &configurations::Signer,
        revision: u64,
    ) -> Result<w::SignedConfiguration, Error> {
        let signed = signer.sign_connections(w::Configuration {
            wire_version: 1,
            service_id: service_id_on(profile, c).await?,
            tenant_id: Uuid::parse_str(tenant).map_err(|_| Error::Configuration)?,
            revision,
            preferred_origin: self.preferred.clone(),
            origins: self.origins.clone(),
            key_id: signer.key_id.clone(),
        })?;
        store_version(profile, c, tenant, &signed).await?;
        Ok(signed)
    }
}

impl Service {
    /// A new file uses the gateway loaded by the issuing host. Replays bypass issuance.
    pub(super) async fn connections_for_new_file(
        &self,
        c: &mut PgConnection,
        tenant: &str,
    ) -> Result<(w::SignedConfiguration, configurations::Signer), Error> {
        let profile = self.profile();
        let origins = self.origins.as_ref().ok_or(Error::Configuration)?;
        lock(profile, c, tenant).await?;
        let current = signed_on(profile, c, tenant, None).await?;
        let signer = ensure_signer_on(profile, c, tenant, &self.protection).await?;
        let revision = match current {
            Some(current)
                if current.configuration.preferred_origin == origins.preferred
                    && current.configuration.origins == origins.origins =>
            {
                return Ok((current, signer));
            }
            Some(current) => current
                .configuration
                .revision
                .checked_add(1)
                .ok_or(Error::Conflict)?,
            None => 1,
        };
        let signed = origins
            .sign_on(profile, c, tenant, &signer, revision)
            .await?;
        Ok((signed, signer))
    }

    /// Native and self-service enrollment can activate before the tenant issues its first file.
    pub(super) async fn initialize_connections(
        &self,
        c: &mut PgConnection,
        tenant: &str,
    ) -> Result<(), Error> {
        let profile = self.profile();
        lock(profile, c, tenant).await?;
        if signed_on(profile, c, tenant, None).await?.is_none() {
            let origins = self.origins.as_ref().ok_or(Error::Configuration)?;
            let signer = ensure_signer_on(profile, c, tenant, &self.protection).await?;
            origins.sign_on(profile, c, tenant, &signer, 1).await?;
        }
        Ok(())
    }

    pub fn require_connection_origin(
        &self,
        origin: &rss_mdm_certificate::GatewayOrigin,
    ) -> Result<(), Failure> {
        if self
            .origins
            .as_ref()
            .is_some_and(|installed| !installed.origins.iter().any(|v| v == origin.as_str()))
        {
            return Err(Error::Unauthorized.into());
        }
        Ok(())
    }
    pub async fn connection_configuration(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<w::SignedConfiguration, Failure> {
        let profile = self.profile();

        let mut tx = self.store.begin(&binding.tenant().to_string()).await?;
        let out = current_on(profile, &mut tx, &binding.tenant().to_string()).await?;
        if out.configuration.service_id != self.service_id()? {
            return Err(Error::Configuration.into());
        }
        tx.rollback().await.map_err(db)?;
        Ok(out)
    }
    pub async fn connection_state(&self, p: &AuthorizedPrincipal) -> Result<State, Failure> {
        let profile = self.profile();

        p.manage(Permission::RegistrationConfigurationRead)?;

        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::authorize_on(
            profile,
            &mut tx,
            p,
            Permission::RegistrationConfigurationRead,
        )
        .await?;
        let configuration = signed_on(profile, &mut tx, p.tenant_id(), None).await?;
        let revision = configuration.as_ref().map(|v| v.configuration.revision);
        let (active, confirmed): (i64, i64) = sqlx::query_as(
            crate::storage_profile::sql(profile).agent_connections_connection_state_2,
        )
        .bind(p.tenant_id())
        .bind(
            revision
                .map(i64::try_from)
                .transpose()
                .map_err(|_| Error::Corrupt)?,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let keys: Vec<(String, String)> = sqlx::query_as(
            crate::storage_profile::sql(profile).agent_connections_connection_state_3,
        )
        .bind(p.tenant_id())
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let state = State {
            service_id: self.service_id()?,
            configuration,
            verification_keys: keys.into_iter().collect(),
            convergence: Convergence {
                target_revision: revision,
                active_devices: u64::try_from(active).map_err(|_| Error::Corrupt)?,
                confirmed_devices: u64::try_from(confirmed).map_err(|_| Error::Corrupt)?,
            },
        };
        tx.rollback().await.map_err(db)?;
        Ok(state)
    }
    pub async fn acknowledge_connections(
        &self,
        peer: &rss_mdm_certificate::ClientCertificateEvidence,
        input: &w::Acknowledgement,
        origin: &rss_mdm_certificate::GatewayOrigin,
        audit: &RequestAudit,
    ) -> Result<(), Failure> {
        let profile = self.profile();

        if input.origin != origin.as_str() {
            return Err(Error::Forbidden.into());
        }
        let p = self.authenticate(peer).await?;
        audit
            .bind_scope(p.binding())
            .map_err(|_| Error::Unauthorized)?;
        audit.identify_device(p.device());
        audit.target_device(p.device());
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            input.operation_id,
            "agent_connections_ack",
            rss_mdm_audit_integration::AuditIntent::Management,
        );

        self.write(audit, (self, p, input), |ctx, c| {
            Box::pin(async move {
                let (_, p, input) = ctx;
                lock(profile, c, &audit.binding()?.tenant().to_string()).await?;
                let current =
                    current_on(profile, c, &audit.binding()?.tenant().to_string()).await?;
                if !current.configuration.origins.contains(&input.origin) {
                    return Err(Error::Conflict);
                }
                crate::device::store::revalidate_source(
                    profile,
                    c,
                    p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                let configuration = signed_on(
                    profile,
                    c,
                    &audit.binding()?.tenant().to_string(),
                    Some(input.revision),
                )
                .await?
                .ok_or(Error::Conflict)?;
                input
                    .validate_for(&configuration.configuration)
                    .map_err(|_| Error::Conflict)?;
                let old: Option<serde_json::Value> = sqlx::query_scalar(
                    crate::storage_profile::sql(profile)
                        .agent_connections_acknowledge_connections_1,
                )
                .bind(audit.binding()?.tenant().to_string())
                .bind(p.device().into_uuid())
                .bind(input.operation_id)
                .fetch_optional(&mut *c)
                .await
                .map_err(db)?;
                if let Some(old) = old {
                    if old != serde_json::to_value(input).map_err(|_| Error::Malformed)? {
                        return Err(Error::Conflict);
                    }
                    return Ok(Change {
                        value: (),
                        replay: true,
                    });
                }
                let latest: Option<i64> = sqlx::query_scalar(
                    crate::storage_profile::sql(profile)
                        .agent_connections_acknowledge_connections_2,
                )
                .bind(audit.binding()?.tenant().to_string())
                .bind(p.device().into_uuid())
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
                if latest.is_some_and(|v| v > input.revision as i64) {
                    return Err(Error::Conflict);
                }
                sqlx::query(
                    crate::storage_profile::sql(profile)
                        .agent_connections_acknowledge_connections_3,
                )
                .bind(audit.binding()?.tenant().to_string())
                .bind(p.device().into_uuid())
                .bind(input.operation_id)
                .bind(input.revision as i64)
                .bind(serde_json::to_value(input).map_err(|_| Error::Malformed)?)
                .execute(c)
                .await
                .map_err(db)?;
                Ok(Change {
                    value: (),
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn report_connection_failure(
        &self,
        peer: &rss_mdm_certificate::ClientCertificateEvidence,
        input: &w::FailureReport,
        origin: &rss_mdm_certificate::GatewayOrigin,
        audit: &RequestAudit,
    ) -> Result<(), Failure> {
        let profile = self.profile();

        if input.operation_id.is_nil() || !(1..=i64::MAX as u64).contains(&input.revision) {
            return Err(Error::Malformed.into());
        }
        let principal = self.authenticate(peer).await?;
        self.require_connection_origin(origin)?;
        audit
            .bind_scope(principal.binding())
            .map_err(|_| Error::Unauthorized)?;
        audit.identify_device(principal.device());
        audit.target_device(principal.device());
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            input.operation_id,
            "agent_connections_failure",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(audit, (self, principal, input, origin), |ctx, c| {
            Box::pin(async move {
                let (_, p, input, origin) = ctx;
                crate::device::store::revalidate_source(
                    profile,
                    c,
                    p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                signed_on(
                    profile,
                    c,
                    &audit.binding()?.tenant().to_string(),
                    Some(input.revision),
                )
                .await?
                .ok_or(Error::Conflict)?;
                let previous = sqlx::query(
                    crate::storage_profile::sql(profile)
                        .agent_connections_report_connection_failure_1,
                )
                .bind(audit.binding()?.tenant().to_string())
                .bind(p.device().into_uuid())
                .bind(input.operation_id)
                .fetch_optional(&mut *c)
                .await
                .map_err(db)?;
                let document = serde_json::to_value(&**input).map_err(|_| Error::Malformed)?;
                if let Some(previous) = previous {
                    if previous
                        .try_get::<serde_json::Value, _>("document")
                        .map_err(db)?
                        != document
                    {
                        return Err(Error::Conflict);
                    }
                    return Ok(Change {
                        value: (),
                        replay: true,
                    });
                }
                sqlx::query(
                    crate::storage_profile::sql(profile)
                        .agent_connections_report_connection_failure_2,
                )
                .bind(audit.binding()?.tenant().to_string())
                .bind(p.device().into_uuid())
                .bind(input.operation_id)
                .bind(input.revision as i64)
                .bind(document)
                .bind(origin.as_str())
                .execute(c)
                .await
                .map_err(db)?;
                Ok(Change {
                    value: (),
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    /// Bounded keyset page of active devices that have not confirmed this exact target.
    pub async fn unconfirmed_connection_devices(
        &self,
        p: &AuthorizedPrincipal,
        input: &DeviceQuery,
    ) -> Result<UnconfirmedDevices, Failure> {
        let profile = self.profile();

        p.manage(Permission::RegistrationConfigurationRead)?;

        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::authorize_on(
            profile,
            &mut tx,
            p,
            Permission::RegistrationConfigurationRead,
        )
        .await?;
        let current = current_on(profile, &mut tx, p.tenant_id()).await?;
        if current.configuration.revision != input.revision {
            return Err(Error::Conflict.into());
        }
        let snapshot = rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        let mut rows = sqlx::query(
            crate::storage_profile::sql(profile).agent_connections_unconfirmed_connection_devices_1,
        )
        .bind(p.tenant_id())
        .bind(input.after)
        .bind(input.revision as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let more = rows.len() > 100;
        if more {
            rows.pop();
        }
        let next = if more {
            rows.last()
                .map(|r| r.try_get("id").map_err(db))
                .transpose()?
        } else {
            None
        };
        let mut items = Vec::new();
        for row in rows {
            let device: rss_mdm_agent_wire::DeviceId = row
                .try_get::<uuid::Uuid, _>("device")
                .and_then(crate::database::device_id)
                .map_err(db)?;
            match snapshot.require(p, Permission::InventoryRead, Some(&device)) {
                Ok(()) => {}
                Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => {
                    continue;
                }
                Err(error) => {
                    return Err(
                        Error::from(rss_mdm_authorization_service::Error::from(error)).into(),
                    );
                }
            }
            items.push(DeviceStatus {
                device,

                installed_revision: row
                    .try_get::<Option<i64>, _>("revision")
                    .map_err(db)?
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| Error::Corrupt)?,
                origin: row.try_get("origin").map_err(db)?,
                received_at: row.try_get("received_at").map_err(db)?,
            });
        }
        p.check_live()?;
        tx.rollback().await.map_err(db)?;
        Ok(UnconfirmedDevices {
            target_revision: input.revision,
            items,
            next,
        })
    }
    pub async fn connection_observation(
        &self,
        p: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<Option<Observation>, Failure> {
        let profile = self.profile();

        p.check_live()?;

        let mut tx = self.store.begin(p.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?
        .require(p, Permission::InventoryRead, Some(device))
        .map_err(|_| Error::Forbidden)?;
        let row = sqlx::query(
            crate::storage_profile::sql(profile).agent_connections_connection_observation_1,
        )
        .bind(p.tenant_id())
        .bind(device.into_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let out = row
            .map(|r| {
                Ok::<_, Error>(Observation {
                    target_revision: r
                        .try_get::<Option<i64>, _>("target_revision")
                        .map_err(db)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| Error::Corrupt)?,
                    device: r
                        .try_get::<uuid::Uuid, _>("device")
                        .and_then(crate::database::device_id)
                        .map_err(db)?,

                    acknowledgement: r
                        .try_get::<Option<serde_json::Value>, _>("document")
                        .map_err(db)?
                        .map(|v| serde_json::from_value(v).map_err(|_| Error::Corrupt))
                        .transpose()?,
                    received_at: r.try_get("received_at").map_err(db)?,
                    failure: r
                        .try_get::<Option<serde_json::Value>, _>("failure_document")
                        .map_err(db)?
                        .map(|v| {
                            Ok::<_, Error>(FailureObservation {
                                report: serde_json::from_value(v).map_err(|_| Error::Corrupt)?,
                                origin: r.try_get("failure_origin").map_err(db)?,
                                received_at: r.try_get("failure_received_at").map_err(db)?,
                            })
                        })
                        .transpose()?,
                })
            })
            .transpose()?;
        tx.rollback().await.map_err(db)?;
        Ok(out)
    }
}

/// Re-encrypt only the configuration private key under the existing Native protection rotation.
/// Signed public history, key identity and every connection revision remain unchanged.
pub async fn rewrap(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    protection: &Protector,
) -> Result<u64, Error> {
    let prefix = protection.ciphertext_prefix();
    let rows = sqlx::query(crate::storage_profile::sql(profile).agent_connections_rewrap_1)
        .bind(tenant.to_string())
        .bind(prefix.len() as i32)
        .bind(prefix)
        .fetch_all(&mut *c)
        .await
        .map_err(db)?;
    for row in &rows {
        let id: String = row.try_get("key_id").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
        let next = protection
            .rewrap_bytes(&sealed, &key_aad(&tenant.to_string(), &id)?)
            .map_err(|_| Error::Corrupt)?;
        sqlx::query(crate::storage_profile::sql(profile).agent_connections_rewrap_2)
            .bind(tenant.to_string())
            .bind(id)
            .bind(next)
            .execute(&mut *c)
            .await
            .map_err(db)?;
    }
    Ok(rows.len() as u64)
}
