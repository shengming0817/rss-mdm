//! One tenant/purpose registry; trust distribution precedes activation and safe retirement.
use crate::Error;
use rss_mdm_agent_wire::pki::{Acknowledgement, Mode, Purpose, Trust};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_device_trust::{DeviceTrust, decode};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

pub fn purpose(value: Purpose) -> &'static str {
    match value {
        Purpose::Windows => "windows",
        Purpose::Apple => "apple",
        Purpose::Agent => "agent",
        Purpose::AgentBootstrap => "agent_bootstrap",
    }
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub id: Uuid,
    pub purpose: Purpose,
    pub expected_revision: u64,
    pub candidate: Trust,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub id: Uuid,
    pub expected_revision: u64,
    pub action: Action,
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Activate,
    Retire,
}
/// Durable rotation progress; issuer trust modes remain a separate lifecycle.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    Distributing,
    Activated,
    Retired,
}
impl RotationState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Distributing => "distributing",
            Self::Activated => "activated",
            Self::Retired => "retired",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "distributing" => Ok(Self::Distributing),
            "activated" => Ok(Self::Activated),
            "retired" => Ok(Self::Retired),
            _ => Err(Error::Storage),
        }
    }
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: Uuid,
    pub revision: u64,
    pub state: RotationState,
}
pub struct Registry {
    profile: rss_mdm_install_support::StorageProfile,
    pub(crate) pool: PgPool,
    pub(crate) audit: Arc<AuditStore>,
    bindings: Vec<DeviceTrust>,
    pub(crate) providers: Arc<crate::providers::Providers>,
}
impl Registry {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        pool: PgPool,
        audit: Arc<AuditStore>,
        bindings: Vec<DeviceTrust>,
        providers: Arc<crate::providers::Providers>,
    ) -> Self {
        Self {
            profile,
            pool,
            audit,
            bindings,
            providers,
        }
    }
    pub fn bindings(&self) -> &[DeviceTrust] {
        &self.bindings
    }
    pub(crate) fn binding(&self, purpose: Purpose) -> Result<&DeviceTrust, Error> {
        if self.profile() == rss_mdm_install_support::StorageProfile::Da
            && !matches!(purpose, Purpose::Agent | Purpose::AgentBootstrap)
        {
            return Err(Error::Configuration);
        }
        self.bindings
            .iter()
            .find(|b| b.public().is_ok_and(|t| t.purpose == purpose))
            .ok_or(Error::Configuration)
    }
    /// Bootstrap is audited. Durable revisions win over deployment files after rotation.
    pub async fn admit(&self, tenant: TenantId, now: i64) -> Result<(), Error> {
        self.admit_selected(tenant, now, None).await
    }
    /// Isolate admission by purpose while keeping the same durable trust/rollback checks.
    pub async fn admit_purpose(
        &self,
        tenant: TenantId,
        now: i64,
        purpose: Purpose,
    ) -> Result<(), Error> {
        self.admit_selected(tenant, now, Some(purpose)).await
    }
    async fn admit_selected(
        &self,
        tenant: TenantId,
        now: i64,
        selected_purpose: Option<Purpose>,
    ) -> Result<(), Error> {
        let profile = self.profile();

        if self.profile() == rss_mdm_install_support::StorageProfile::Da
            && self.bindings.iter().any(|b| {
                b.public().map_or(true, |t| {
                    !matches!(t.purpose, Purpose::Agent | Purpose::AgentBootstrap)
                })
            })
        {
            return Err(Error::Configuration);
        }
        for binding in &self.bindings {
            if selected_purpose.is_some_and(|p| binding.public().is_ok_and(|t| t.purpose != p)) {
                continue;
            }
            let configured = binding.public().map_err(|_| Error::Configuration)?;
            if configured.tenant.to_string() != tenant.to_string() {
                return Err(Error::Forbidden);
            }
            let mut read = self.begin(&tenant.to_string()).await?;
            let stored = sqlx::query_scalar::<_, Vec<u8>>(
                crate::storage_profile::sql(profile).registry_admit_selected_1,
            )
            .bind(tenant.to_string())
            .bind(purpose(configured.purpose))
            .fetch_optional(&mut *read)
            .await
            .map_err(|_| Error::Storage)?;
            let archived: Vec<Vec<u8>> =
                sqlx::query_scalar(crate::storage_profile::sql(profile).registry_admit_selected_2)
                    .bind(tenant.to_string())
                    .bind(purpose(configured.purpose))
                    .fetch_all(&mut *read)
                    .await
                    .map_err(|_| Error::Storage)?;
            let archived = archived
                .into_iter()
                .map(|bytes| {
                    serde_json::from_slice::<rss_mdm_agent_wire::pki::Issuer>(&bytes)
                        .map_err(|_| Error::Storage)
                })
                .collect::<Result<Vec<_>, _>>()?;
            read.rollback().await.map_err(|_| Error::Storage)?;
            let mut next = match stored.as_ref() {
                Some(bytes) => {
                    let mut stored: Trust =
                        serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
                    if configured.service_id != stored.service_id
                        || (configured.origin != stored.origin
                            && !matches!(
                                configured.purpose,
                                Purpose::Agent | Purpose::AgentBootstrap
                            ))
                        || configured.issuers.iter().any(|g| {
                            !stored.issuers.iter().chain(archived.iter()).any(|s| {
                                s.digest == g.digest
                                    && s.certificate == g.certificate
                                    && s.root == g.root
                                    && s.provisioner == g.provisioner
                                    && s.kid == g.kid
                            })
                        })
                    {
                        return Err(Error::Conflict);
                    }
                    for g in &mut stored.issuers {
                        if let Some(c) = configured.issuers.iter().find(|c| c.digest == g.digest) {
                            let root = x509_cert::Certificate::from_der(
                                &decode(&g.root, 32768).map_err(|_| Error::Storage)?,
                            )
                            .map_err(|_| Error::Storage)?;
                            let previous = rss_mdm_device_trust::crl(
                                &decode(&g.root_crl, 16 * 1024 * 1024)
                                    .map_err(|_| Error::Storage)?,
                                &root,
                                crate::maintenance::publication_time(
                                    &serde_json::from_slice(bytes).map_err(|_| Error::Storage)?,
                                )?,
                            )
                            .map_err(|_| Error::Storage)?;
                            if let Ok(replacement) = rss_mdm_device_trust::crl(
                                &decode(&c.root_crl, 16 * 1024 * 1024)
                                    .map_err(|_| Error::Configuration)?,
                                &root,
                                now,
                            ) && (replacement.number > previous.number
                                || (replacement.number == previous.number
                                    && replacement.der == previous.der))
                            {
                                g.root_crl = c.root_crl.clone();
                            }
                        }
                    }
                    stored
                }
                None => configured.clone(),
            };
            // Fresh online CRLs are fetched before entering the Audit/business transaction.
            for g in &mut next.issuers {
                if let Ok(provider) = self.providers.get(next.purpose, &g.digest) {
                    g.crl = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        provider.published_crl().await?,
                    );
                } else if g.mode != Mode::VerifyOnly || !g.provisioner.is_empty() {
                    return Err(Error::Configuration);
                }
            }
            DeviceTrust::new(next.clone(), next.purpose, now).map_err(|_| Error::Configuration)?;
            if let Some(bytes) = &stored {
                let old: Trust = serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
                let previous = DeviceTrust::new(
                    old.clone(),
                    old.purpose,
                    crate::maintenance::publication_time(&old)?,
                )
                .map_err(|_| Error::Storage)?;
                previous
                    .update(next.clone(), now)
                    .map_err(|_| Error::Conflict)?;
            }
            let hash =
                sha2::Sha256::digest(serde_json::to_vec(&next).map_err(|_| Error::Configuration)?)
                    .to_vec();
            let id = Uuid::from_bytes(hash[..16].try_into().map_err(|_| Error::Storage)?);
            let a = RequestAudit::new(
                tenant.to_string(),
                "device_pki_admit",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            a.identify_service("service:device-pki");
            a.operation(
                id,
                "device_pki_admit",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let result = self
                .mutation(tenant, &a, (next.clone(), stored, hash, id), |ctx, c| {
                    Box::pin(async move {
                        let (next, observed, hash, id) = ctx;
                        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
                            .bind(next.tenant.to_string())
                            .execute(&mut *c)
                            .await
                            .map_err(|_| Error::Storage)?;
                        let current = sqlx::query_scalar::<_, Vec<u8>>(
                            crate::storage_profile::sql(profile).registry_admit_selected_3,
                        )
                        .bind(next.tenant)
                        .bind(purpose(next.purpose))
                        .fetch_optional(&mut *c)
                        .await
                        .map_err(|_| Error::Storage)?;
                        if current != *observed {
                            return Err(Error::Conflict);
                        }
                        let replay = crate::mutation::replay(
                            profile,
                            c,
                            &next.tenant.to_string(),
                            "service:device-pki",
                            "",
                            *id,
                            "admit",
                            hash,
                        )
                        .await?
                        .is_some();
                        persist(profile, c, next).await?;
                        if !replay {
                            crate::mutation::save(
                                profile,
                                c,
                                (&next.tenant.to_string(), "service:device-pki", ""),
                                *id,
                                "admit",
                                hash,
                                b"null",
                            )
                            .await?;
                        }
                        Ok(crate::mutation::Change {
                            value: (),
                            replay,
                            key: format!("pki:{id}:admit"),
                        })
                    })
                })
                .await;
            a.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result?;
            binding.update(next, now).map_err(|_| Error::Conflict)?;
        }
        Ok(())
    }
    pub async fn begin(
        &self,
        tenant: &str,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
        Ok(tx)
    }
    /// Durable approval and publications are shared across app processes.
    pub async fn synchronize(&self, now: i64) -> Result<(), Error> {
        let profile = self.profile();

        if self.profile() == rss_mdm_install_support::StorageProfile::Da
            && self.bindings.iter().any(|b| {
                b.public().map_or(true, |t| {
                    !matches!(t.purpose, Purpose::Agent | Purpose::AgentBootstrap)
                })
            })
        {
            return Err(Error::Configuration);
        }
        for binding in &self.bindings {
            let current = binding.public().map_err(|_| Error::Storage)?;
            let mut tx = self.begin(&current.tenant.to_string()).await?;
            let bytes: Vec<u8> =
                sqlx::query_scalar(crate::storage_profile::sql(profile).registry_synchronize_1)
                    .bind(current.tenant)
                    .bind(purpose(current.purpose))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| Error::Storage)?;
            tx.rollback().await.map_err(|_| Error::Storage)?;
            let stored: Trust = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            DeviceTrust::restore(stored.clone(), stored.purpose, now)
                .map_err(|_| Error::Storage)?;
            binding
                .update(
                    stored.clone(),
                    crate::maintenance::publication_time(&stored)?,
                )
                .map_err(|_| Error::Conflict)?;
        }
        Ok(())
    }
    pub fn trust(&self, purpose: Purpose) -> Result<Trust, Error> {
        self.binding(purpose)?.public().map_err(|_| Error::Storage)
    }
    pub async fn prepare(
        &self,
        p: &AuthorizedPrincipal,
        input: &Rotation,
        a: &RequestAudit,
        now: i64,
    ) -> Result<Receipt, Error> {
        if p.profile() != self.profile() {
            return Err(Error::Forbidden);
        }

        p.require_all_devices(Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        self.synchronize(now).await?;
        let request =
            sha2::Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Request)?).to_vec();
        if let Some(old) = self
            .rotation_replay(p, a, input.id, RotationState::Distributing, &request)
            .await?
        {
            return Ok(old);
        }
        let old = self.trust(input.purpose)?;
        if input.id.is_nil()
            || old.tenant.to_string() != p.tenant_id()
            || input.expected_revision != old.revision
            || input.candidate.revision != old.revision + 1
            || input.candidate.service_id != old.service_id
            || (input.candidate.origin != old.origin
                && !matches!(old.purpose, Purpose::Agent | Purpose::AgentBootstrap))
            || input.candidate.tenant != old.tenant
            || input.candidate.purpose != old.purpose
        {
            return Err(Error::Conflict);
        }
        let mut candidate_trust = input.candidate.clone();
        for previous in &old.issuers {
            let next = candidate_trust
                .issuers
                .iter_mut()
                .find(|g| g.digest == previous.digest)
                .ok_or(Error::Conflict)?;
            if next.mode != previous.mode
                || next.certificate != previous.certificate
                || next.root != previous.root
                || next.provisioner != previous.provisioner
                || next.kid != previous.kid
            {
                return Err(Error::Conflict);
            }
            // Concurrent CRL refresh must not invalidate an otherwise exact rotation proposal.
            *next = previous.clone();
        }
        DeviceTrust::new(candidate_trust.clone(), input.purpose, now)
            .map_err(|_| Error::Request)?;
        let added = input
            .candidate
            .issuers
            .iter()
            .filter(|g| !old.issuers.iter().any(|p| p.digest == g.digest))
            .collect::<Vec<_>>();
        if added.len() != 1 || added[0].mode != Mode::Prepared {
            return Err(Error::Request);
        }
        self.providers
            .get(input.purpose, &added[0].digest)?
            .verify_issuer(&added[0].digest)
            .await?;
        let previous = old
            .issuers
            .iter()
            .find(|g| g.mode == Mode::Active)
            .ok_or(Error::Configuration)?
            .digest
            .clone();
        let candidate = added[0].digest.clone();
        let state = RotationState::Distributing;
        let receipt = self
            .write(
                p,
                a,
                (input.id, input.expected_revision),
                (&candidate_trust, state, Some((&previous, &candidate))),
                now,
                &request,
            )
            .await?;
        self.binding(input.purpose)?
            .update(candidate_trust, now)
            .map_err(|_| Error::Storage)?;
        Ok(receipt)
    }
    pub async fn transition(
        &self,
        p: &AuthorizedPrincipal,
        purpose_value: Purpose,
        input: &Transition,
        a: &RequestAudit,
        now: i64,
    ) -> Result<Receipt, Error> {
        if p.profile() != self.profile() {
            return Err(Error::Forbidden);
        }

        let profile = self.profile();

        p.require_all_devices(Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        self.synchronize(now).await?;
        let state = match input.action {
            Action::Activate => RotationState::Activated,
            Action::Retire => RotationState::Retired,
        };
        let request = sha2::Sha256::digest(
            serde_json::to_vec(&(purpose_value, input)).map_err(|_| Error::Request)?,
        )
        .to_vec();
        if let Some(old) = self
            .rotation_replay(p, a, input.id, state, &request)
            .await?
        {
            return Ok(old);
        }
        let mut trust = self.trust(purpose_value)?;
        if trust.tenant.to_string() != p.tenant_id() || trust.revision != input.expected_revision {
            return Err(Error::Conflict);
        }
        let mut tx = self.begin(p.tenant_id()).await?;
        let row = sqlx::query(crate::storage_profile::sql(profile).registry_transition_1)
            .bind(p.tenant_id())
            .bind(input.id)
            .bind(purpose(purpose_value))
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        let previous: String = row.try_get("previous").map_err(|_| Error::Storage)?;
        let candidate: String = row.try_get("candidate").map_err(|_| Error::Storage)?;
        let old_state = RotationState::parse(row.try_get("state").map_err(|_| Error::Storage)?)?;
        if !matches!(
            (input.action, old_state),
            (Action::Activate, RotationState::Distributing)
                | (Action::Retire, RotationState::Activated)
        ) {
            return Err(Error::Conflict);
        }
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if matches!(input.action, Action::Activate) {
            self.providers
                .get(purpose_value, &candidate)?
                .verify_issuer(&candidate)
                .await?;
        }
        trust = crate::rotation::next_trust(
            trust,
            &previous,
            &candidate,
            old_state,
            input.action,
            now,
        )?;
        let receipt = self
            .write(
                p,
                a,
                (input.id, input.expected_revision),
                (&trust, state, None),
                now,
                &request,
            )
            .await?;
        self.binding(purpose_value)?
            .update(trust, now)
            .map_err(|_| Error::Storage)?;
        Ok(receipt)
    }
    pub async fn acknowledge_in(
        profile: rss_mdm_install_support::StorageProfile,
        c: &mut sqlx::PgConnection,
        tenant: &str,
        registration: Uuid,
        trust: &Trust,
        input: &Acknowledgement,
    ) -> Result<(), Error> {
        input.validate().map_err(|_| Error::Conflict)?;
        if input.revision != trust.revision || input.digest != trust.installation_digest() {
            return Err(Error::Conflict);
        }
        if trust.tenant.to_string() != tenant {
            return Err(Error::Forbidden);
        }
        let prior: Option<(i64, String)> =
            sqlx::query_as(crate::storage_profile::sql(profile).registry_acknowledge_in_1)
                .bind(tenant)
                .bind(purpose(trust.purpose))
                .bind(registration)
                .fetch_optional(&mut *c)
                .await
                .map_err(|_| Error::Storage)?;
        if prior.is_some_and(|(r, d)| {
            r > input.revision as i64 || (r == input.revision as i64 && d != input.digest)
        }) {
            return Err(Error::Conflict);
        }
        sqlx::query(crate::storage_profile::sql(profile).registry_acknowledge_in_2)
            .bind(tenant)
            .bind(purpose(trust.purpose))
            .bind(registration)
            .bind(input.revision as i64)
            .bind(&input.digest)
            .bind(serde_json::to_vec(trust).map_err(|_| Error::Storage)?)
            .execute(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
        sqlx::query(crate::storage_profile::sql(profile).registry_acknowledge_in_3)
            .bind(tenant)
            .bind(registration)
            .bind(input.revision as i64)
            .bind(input.digest.as_bytes())
            .bind(purpose(trust.purpose))
            .execute(c)
            .await
            .map_err(|_| Error::Storage)?;
        Ok(())
    }
    async fn rotation_replay(
        &self,
        p: &AuthorizedPrincipal,
        a: &RequestAudit,
        id: Uuid,
        state: RotationState,
        hash: &[u8],
    ) -> Result<Option<Receipt>, Error> {
        if p.profile() != self.profile() {
            return Err(Error::Forbidden);
        }

        let profile = self.profile();

        p.bind_audit(a).map_err(|_| Error::Forbidden)?;
        let phase = state.as_str();
        let mut tx = self.begin(p.tenant_id()).await?;
        let found = sqlx::query_scalar::<_, bool>(
            crate::storage_profile::sql(profile).registry_rotation_replay_1,
        )
        .bind(p.tenant_id())
        .bind(p.principal_id())
        .bind(id)
        .bind(phase)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if !found {
            return Ok(None);
        }
        a.operation(
            id,
            "device_pki_rotation",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.mutation(
            TenantId::parse(p.tenant_id()).map_err(|_| Error::Request)?,
            a,
            (p, id, phase, hash),
            |ctx, c| {
                Box::pin(async move {
                    let (p, id, phase, hash) = ctx;
                    live(profile, c, p).await?;
                    let bytes = crate::mutation::replay(
                        profile,
                        c,
                        p.tenant_id(),
                        p.principal_id(),
                        p.instance_id(),
                        *id,
                        phase,
                        hash,
                    )
                    .await?
                    .ok_or(Error::Conflict)?;
                    let receipt = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
                    Ok(crate::mutation::Change {
                        value: Some(receipt),
                        replay: true,
                        key: format!("pki:{id}:{phase}"),
                    })
                })
            },
        )
        .await
    }
    async fn write(
        &self,
        p: &AuthorizedPrincipal,
        a: &RequestAudit,
        request: (Uuid, u64),
        change: (&Trust, RotationState, Option<(&str, &str)>),
        now: i64,
        hash: &[u8],
    ) -> Result<Receipt, Error> {
        if p.profile() != self.profile() {
            return Err(Error::Forbidden);
        }

        let profile = self.profile();

        let (id, expected) = request;
        let (trust, state, added) = change;
        p.bind_audit(a).map_err(|_| Error::Forbidden)?;
        a.operation(
            id,
            "device_pki_rotation",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.mutation(
            TenantId::parse(p.tenant_id()).map_err(|_| Error::Request)?,
            a,
            (p, id, expected, trust, state, added, now, hash),
            |ctx, c| {
                Box::pin(async move {
                    let (p, id, expected, trust, state, added, now, hash) = ctx;
                    let phase = state.as_str();
                    live(profile, c, p).await?;
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
                        .bind(p.tenant_id())
                        .execute(&mut *c)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if let Some(bytes) = crate::mutation::replay(
                        profile,
                        c,
                        p.tenant_id(),
                        p.principal_id(),
                        p.instance_id(),
                        *id,
                        phase,
                        hash,
                    )
                    .await?
                    {
                        return Ok(crate::mutation::Change {
                            value: serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?,
                            replay: true,
                            key: format!("pki:{id}:{phase}"),
                        });
                    }
                    let revision: i64 =
                        sqlx::query_scalar(crate::storage_profile::sql(profile).registry_write_1)
                            .bind(p.tenant_id())
                            .bind(purpose(trust.purpose))
                            .fetch_one(&mut *c)
                            .await
                            .map_err(|_| Error::Storage)?;
                    if revision != *expected as i64 {
                        return Err(Error::Conflict);
                    }
                    if added.is_none() {
                        crate::rotation::gates::require(
                            profile,
                            c,
                            p.tenant_id(),
                            *id,
                            *state,
                            *now,
                        )
                        .await?;
                    }
                    if let Some((previous, candidate)) = added {
                        sqlx::query(crate::storage_profile::sql(profile).registry_write_2)
                            .bind(p.tenant_id())
                            .bind(*id)
                            .bind(purpose(trust.purpose))
                            .bind(*previous)
                            .bind(*candidate)
                            .bind(trust.revision as i64)
                            .execute(&mut *c)
                            .await
                            .map_err(|_| Error::Storage)?;
                    } else {
                        sqlx::query(crate::storage_profile::sql(profile).registry_write_3)
                            .bind(p.tenant_id())
                            .bind(*id)
                            .bind(phase)
                            .execute(&mut *c)
                            .await
                            .map_err(|_| Error::Storage)?;
                    }
                    persist(profile, c, trust).await?;
                    let receipt = Receipt {
                        operation: *id,
                        revision: trust.revision,
                        state: *state,
                    };
                    crate::mutation::save(
                        profile,
                        c,
                        (p.tenant_id(), p.principal_id(), p.instance_id()),
                        *id,
                        phase,
                        hash,
                        &serde_json::to_vec(&receipt).map_err(|_| Error::Storage)?,
                    )
                    .await?;

                    Ok(crate::mutation::Change {
                        value: receipt,
                        replay: false,
                        key: format!("pki:{id}:{phase}"),
                    })
                })
            },
        )
        .await
    }
}
async fn live(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
) -> Result<(), Error> {
    p.check_live().map_err(|_| Error::Forbidden)?;
    rss_mdm_authorization_service::lock_on(profile, c, p.tenant_id(), p.instance_id())
        .await
        .map_err(|_| Error::Storage)?;
    rss_mdm_authorization_service::snapshot_on(profile, c, p.tenant_id(), p.instance_id())
        .await
        .map_err(|_| Error::Storage)?
        .require_all_devices(p, Permission::Credentials)
        .map_err(|_| Error::Forbidden)
}

pub async fn persist(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    trust: &Trust,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(trust).map_err(|_| Error::Request)?;
    sqlx::query(crate::storage_profile::sql(profile).registry_persist_1)
        .bind(trust.tenant)
        .bind(purpose(trust.purpose))
        .bind(trust.revision as i64)
        .bind(bytes)
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::query(crate::storage_profile::sql(profile).registry_persist_2)
        .bind(trust.tenant)
        .bind(purpose(trust.purpose))
        .bind(
            trust
                .issuers
                .iter()
                .map(|g| g.digest.clone())
                .collect::<Vec<_>>(),
        )
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    // Retire the previous active row before promoting another generation under the unique fence.
    sqlx::query(crate::storage_profile::sql(profile).registry_persist_3)
        .bind(trust.tenant)
        .bind(purpose(trust.purpose))
        .bind(
            trust
                .issuers
                .iter()
                .find(|g| g.mode == Mode::Active)
                .ok_or(Error::Request)?
                .digest
                .as_str(),
        )
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    for g in &trust.issuers {
        for (encoded, list) in [(&g.certificate, &g.crl), (&g.root, &g.root_crl)] {
            let cert_der = decode(encoded, 32768).map_err(|_| Error::Request)?;
            let digest = rss_mdm_device_trust::digest(&cert_der);
            let certificate =
                x509_cert::Certificate::from_der(&cert_der).map_err(|_| Error::Request)?;
            let der = decode(list, 16 * 1024 * 1024).map_err(|_| Error::Request)?;
            let parsed =
                x509_cert::crl::CertificateList::from_der(&der).map_err(|_| Error::Request)?;
            let at = parsed
                .tbs_cert_list
                .this_update
                .to_unix_duration()
                .as_secs() as i64;
            let checked =
                rss_mdm_device_trust::crl(&der, &certificate, at).map_err(|_| Error::Request)?;
            if let Some(old) = sqlx::query(crate::storage_profile::sql(profile).registry_persist_4)
                .bind(trust.tenant)
                .bind(purpose(trust.purpose))
                .bind(&digest)
                .fetch_optional(&mut *c)
                .await
                .map_err(|_| Error::Storage)?
            {
                let number: i64 = old.try_get("number").map_err(|_| Error::Storage)?;
                let previous: i64 = old.try_get("this_update").map_err(|_| Error::Storage)?;
                if checked.number < number as u64
                    || checked.this_update < previous
                    || (checked.number == number as u64
                        && checked.der
                            != old
                                .try_get::<Vec<u8>, _>("der")
                                .map_err(|_| Error::Storage)?)
                {
                    return Err(Error::Conflict);
                }
            }
            sqlx::query(crate::storage_profile::sql(profile).registry_persist_5)
                .bind(trust.tenant)
                .bind(purpose(trust.purpose))
                .bind(&digest)
                .bind(i64::try_from(checked.number).map_err(|_| Error::Request)?)
                .bind(checked.this_update)
                .bind(checked.next_update)
                .bind(&checked.der)
                .execute(&mut *c)
                .await
                .map_err(|_| Error::Storage)?;
        }
        let certificate = x509_cert::Certificate::from_der(
            &decode(&g.certificate, 32768).map_err(|_| Error::Request)?,
        )
        .map_err(|_| Error::Request)?;
        sqlx::query(crate::storage_profile::sql(profile).registry_persist_6)
            .bind(trust.tenant)
            .bind(purpose(trust.purpose))
            .bind(&g.digest)
            .bind(trust.revision as i64)
            .bind(match g.mode {
                Mode::Active => "active",
                Mode::Prepared => "prepared",
                Mode::VerifyOnly => "verify_only",
            })
            .bind(serde_json::to_vec(g).map_err(|_| Error::Request)?)
            .bind(
                certificate
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs() as i64,
            )
            .bind(if g.provisioner.is_empty() {
                "legacy"
            } else {
                "step_ca"
            })
            .execute(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    }
    crate::qualification::publish_in(
        profile,
        c,
        &trust.tenant.to_string(),
        trust.purpose,
        &serde_json::to_vec(trust).map_err(|_| Error::Request)?,
    )
    .await?;
    Ok(())
}
use sha2::Digest;
use x509_cert::der::Decode;

/// Revalidate a persisted identity when a later operation borrows its authority without TLS.
/// The certificate, current purpose trust and pending revocations belong to this registry.
pub async fn current_certificate_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    usage: Purpose,
    fingerprint: &[u8],
) -> Result<(), Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).registry_current_certificate_in_1)
        .bind(tenant.to_string())
        .bind(purpose(usage))
        .bind(fingerprint)
        .fetch_optional(c)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Forbidden)?;
    let now: i64 = row.try_get("now").map_err(|_| Error::Storage)?;
    let trust: Trust = serde_json::from_slice(
        &row.try_get::<Vec<u8>, _>("body")
            .map_err(|_| Error::Storage)?,
    )
    .map_err(|_| Error::Configuration)?;
    let trust = DeviceTrust::new(trust, usage, now).map_err(|_| Error::Forbidden)?;
    let certificate: Vec<u8> = row.try_get("certificate").map_err(|_| Error::Storage)?;
    trust
        .verify(&[certificate.into()], now)
        .map_err(|_| Error::Forbidden)?;
    Ok(())
}

/// Qualify a bounded presentation set using the owner's full-verifier records.
/// This returns presentation eligibility only, never an authentication proof.
pub async fn current_certificates_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    usage: Purpose,
    fingerprints: &[Vec<u8>],
) -> Result<std::collections::BTreeSet<Vec<u8>>, Error> {
    if fingerprints.len() > 1000 || fingerprints.iter().any(|f| f.len() != 32) {
        return Err(Error::Request);
    }
    let rows: Vec<Vec<u8>> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).registry_current_certificates_in_1)
            .bind(tenant.to_string())
            .bind(purpose(usage))
            .bind(fingerprints)
            .fetch_all(c)
            .await
            .map_err(|_| Error::Storage)?;
    Ok(rows.into_iter().collect())
}

/// Read current trust under the issuer-generation fence in the initiating business transaction.
/// The caller retains the connection and owns commit or rollback.
pub async fn trust_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    usage: Purpose,
) -> Result<Trust, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,2639))")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    let body: Vec<u8> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).registry_trust_on_1)
            .bind(tenant.to_string())
            .bind(purpose(usage))
            .fetch_one(c)
            .await
            .map_err(|_| Error::Storage)?;
    let trust: Trust = serde_json::from_slice(&body).map_err(|_| Error::Configuration)?;
    if trust.tenant.to_string() != tenant.to_string() || trust.purpose != usage {
        return Err(Error::Forbidden);
    }
    Ok(trust)
}

/// A signing retry must remain bound to an issuer retained for this purpose.
pub async fn retained_issuer_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    usage: Purpose,
    digest: &str,
) -> Result<bool, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::query_scalar(crate::storage_profile::sql(profile).registry_retained_issuer_on_1)
        .bind(tenant.to_string())
        .bind(purpose(usage))
        .bind(digest)
        .fetch_one(c)
        .await
        .map_err(|_| Error::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_wire_accepts_only_current_actions_and_receipt_states() {
        let id = Uuid::new_v4();
        for action in ["activate", "retire"] {
            let value = serde_json::json!({"id": id, "expected_revision": 2, "action": action});
            let input: Transition = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(input).unwrap(), value);
        }
        {
            let action = "";
            assert!(
                serde_json::from_value::<Transition>(serde_json::json!({
                    "id": id, "expected_revision": 2, "action": action,
                }))
                .is_err()
            );
        }
        for state in [
            RotationState::Distributing,
            RotationState::Activated,
            RotationState::Retired,
        ] {
            let receipt = Receipt {
                operation: id,
                revision: 2,
                state,
            };
            let value = serde_json::to_value(receipt).unwrap();
            assert_eq!(value["state"], state.as_str());
            assert_eq!(
                serde_json::from_value::<Receipt>(value).unwrap().state,
                state
            );
            assert_eq!(RotationState::parse(state.as_str()).unwrap(), state);
        }
        {
            let state = "";
            assert!(
                serde_json::from_value::<Receipt>(serde_json::json!({
                    "operation": id, "revision": 2, "state": state,
                }))
                .is_err()
            );
            assert!(matches!(RotationState::parse(state), Err(Error::Storage)));
        }
    }
}
