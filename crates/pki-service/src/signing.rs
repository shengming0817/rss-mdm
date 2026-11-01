//! Durable CA dispatch: one network invocation, immutable response, explicit unknown recovery.
use crate::{Error, Sign, StepCa};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frozen {
    pub version: u8,
    pub purpose: String,
    pub issuer: String,
    pub provider: String,
    pub csr: String,
    pub csr_digest: [u8; 32],
    pub subject: String,
    pub sans: Vec<String>,
    pub start: i64,
    pub end: i64,
    pub deadline: i64,
}
impl Frozen {
    fn matches(&self, purpose: &str, issuer: &str, i: Sign<'_>) -> bool {
        self.version == 1
            && self.purpose == purpose
            && self.issuer == issuer
            && self.csr == i.csr_pem
            && self.csr_digest == *i.csr_digest
            && self.subject == i.subject
            && self.sans == i.sans
            && self.start == i.start
            && self.end == i.end
            && self.deadline == i.deadline
    }
}
fn binding(
    purpose: &str,
    issuer: &str,
    provider: &StepCa,
    intent: Sign<'_>,
) -> Result<Vec<u8>, Error> {
    let binding = serde_json::to_vec(&Frozen {
        version: 1,
        purpose: purpose.into(),
        issuer: issuer.into(),
        provider: provider.authority_digest(issuer),
        csr: intent.csr_pem.into(),
        csr_digest: *intent.csr_digest,
        subject: intent.subject.into(),
        sans: intent.sans.to_vec(),
        start: intent.start,
        end: intent.end,
        deadline: intent.deadline,
    })
    .map_err(|_| Error::Request)?;
    Ok(binding)
}
/// Freeze external dispatch in the original lifecycle transaction, under the rotation fence.
/// The later audited claim may use this exact old issuer after activation switches.
pub async fn authorize_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    purpose: &str,
    issuer: &str,
    provider: &StepCa,
    intent: Sign<'_>,
) -> Result<(), Error> {
    if !matches!(purpose, "windows" | "agent" | "da_device")
        || issuer.len() != 64
        || intent.attempt.is_nil()
    {
        return Err(Error::Request);
    }
    require_active_in(profile, c, tenant, purpose, issuer).await?;
    let bytes = binding(purpose, issuer, provider, intent)?;
    sqlx::query(crate::storage_profile::sql(profile).signing_authorize_in_1)
        .bind(tenant)
        .bind(intent.attempt)
        .bind(purpose)
        .bind(issuer)
        .bind(&bytes)
        .bind(intent.deadline)
        .bind(Sha256::digest(&bytes).to_vec())
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}
/// Retire only a proven undispatched Windows attempt under the claim fence.
/// The caller must authorize and persist the successor in this same transaction.
/// `successor` is recorded with a deferred FK so rollback cannot leave a half replacement.
pub async fn supersede_expired_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    previous: Sign<'_>,
    issuer: &str,
    successor: Uuid,
) -> Result<bool, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    let row = sqlx::query(crate::storage_profile::sql(profile).signing_supersede_expired_in_1)
        .bind(tenant)
        .bind(previous.attempt)
        .fetch_one(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    let frozen: Frozen = serde_json::from_slice(
        &row.try_get::<Vec<u8>, _>("binding")
            .map_err(|_| Error::Storage)?,
    )
    .map_err(|_| Error::Storage)?;
    if !frozen.matches("windows", issuer, previous)
        || successor.is_nil()
        || successor == previous.attempt
    {
        return Err(Error::Conflict);
    }
    let state: String = row.try_get("state").map_err(|_| Error::Storage)?;
    match state.as_str() {
        "signing" | "unknown" | "issued" => return Ok(false),
        "prepared" => {}
        _ => return Err(Error::Conflict),
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if now < previous.deadline && now.saturating_sub(previous.start) < 60 {
        return Ok(false);
    }
    sqlx::query(crate::storage_profile::sql(profile).signing_supersede_expired_in_2)
        .bind(tenant)
        .bind(previous.attempt)
        .bind(successor)
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(true)
}

/// Fence new issuance against the durable active generation in its original transaction.
pub async fn require_active_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    purpose: &str,
    issuer: &str,
) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    let active: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).signing_require_active_in_1)
            .bind(tenant)
            .bind(purpose)
            .bind(issuer)
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if !active {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub struct SigningStore {
    profile: rss_mdm_install_support::StorageProfile,
    audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
}
enum Claim {
    New,
    Cached(Vec<Vec<u8>>),
}
impl SigningStore {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Self {
        Self { profile, audit }
    }
    pub async fn issue<F>(
        &self,
        tenant: Uuid,
        generation: (&str, &str),
        provider: &StepCa,
        intent: Sign<'_>,
        clock: &(dyn Fn() -> Result<i64, Error> + Send + Sync),
        validate: F,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        F: FnOnce(&[Vec<u8>]) -> bool,
    {
        let profile = self.profile();

        let (purpose, issuer) = generation;
        if !matches!(purpose, "windows" | "agent" | "da_device")
            || issuer.len() != 64
            || intent.attempt.is_nil()
        {
            return Err(Error::Request);
        }
        let unknown = || Error::Unknown {
            attempt: intent.attempt,
        };
        let binding = binding(purpose, issuer, provider, intent)?;
        let hash = Sha256::digest(&binding).to_vec();
        let a = rss_mdm_audit_integration::RequestAudit::new(
            self.profile(),
            tenant.to_string(),
            "device_pki_signing_claim",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        a.identify_service("service:device-pki-signing");
        a.operation(
            intent.attempt,
            "device_pki_signing_claim",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let claim = crate::mutation::run(
            profile,
            &self.audit,
            rss_request_context::TenantId::parse(&tenant.to_string())
                .map_err(|_| Error::Request)?,
            &a,
            (tenant, purpose, issuer, intent, &binding, clock),
            |ctx, c| {
                Box::pin(async move {
                    let (tenant, purpose, issuer, intent, binding, clock) = ctx;
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
                        .bind(tenant.to_string())
                        .execute(&mut *c)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if let Some(row) =
                        sqlx::query(crate::storage_profile::sql(profile).signing_issue_1)
                            .bind(*tenant)
                            .bind(intent.attempt)
                            .fetch_optional(&mut *c)
                            .await
                            .map_err(|_| Error::Storage)?
                    {
                        let frozen: Frozen = serde_json::from_slice(
                            &row.try_get::<Vec<u8>, _>("binding")
                                .map_err(|_| Error::Storage)?,
                        )
                        .map_err(|_| Error::Storage)?;
                        if !frozen.matches(purpose, issuer, *intent) {
                            return Err(Error::Conflict);
                        }
                        let state = row
                            .try_get::<String, _>("state")
                            .map_err(|_| Error::Storage)?;
                        if state == "superseded" {
                            return Err(Error::Conflict);
                        }
                        if state == "prepared" {
                            let now = clock()?;
                            if row
                                .try_get::<Vec<u8>, _>("binding")
                                .map_err(|_| Error::Storage)?
                                != **binding
                                || now < intent.start
                                || now >= intent.deadline
                                || now - intent.start >= 60
                            {
                                return Err(Error::Request);
                            }
                            sqlx::query(crate::storage_profile::sql(profile).signing_issue_2)
                                .bind(*tenant)
                                .bind(intent.attempt)
                                .execute(c)
                                .await
                                .map_err(|_| Error::Storage)?;
                        } else {
                            if state != "issued" {
                                return Err(Error::Unknown {
                                    attempt: intent.attempt,
                                });
                            }
                            let chain = serde_json::from_slice(
                                &row.try_get::<Vec<u8>, _>("chain")
                                    .map_err(|_| Error::Storage)?,
                            )
                            .map_err(|_| Error::Storage)?;
                            return Ok(crate::mutation::Change {
                                value: Claim::Cached(chain),
                                replay: false,
                                key: String::new(),
                            });
                        }
                    } else {
                        return Err(Error::Request);
                    }
                    Ok(crate::mutation::Change {
                        value: Claim::New,
                        replay: false,
                        key: format!("pki:{}:claim", intent.attempt),
                    })
                })
            },
        )
        .await;
        a.finalize(
            claim
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        match claim? {
            Claim::Cached(chain) => {
                if !validate(&chain) {
                    return Err(unknown());
                }
                return Ok(chain);
            }
            Claim::New => {}
        }
        // Audit and the immutable dispatch claim are committed before the single network call.
        let now = clock().map_err(|_| unknown())?;
        let chain = match provider.sign(intent, now).await {
            Ok(chain) if validate(&chain) => chain,
            _ => {
                // The original dispatch remains unknown; retain the canonical audit diagnosis.
                self.settle(tenant, intent.attempt, &hash, None).await?;
                return Err(unknown());
            }
        };
        self.settle(tenant, intent.attempt, &hash, Some(&chain))
            .await?;
        Ok(chain)
    }
    async fn settle(
        &self,
        tenant: Uuid,
        attempt: Uuid,
        hash: &[u8],
        chain: Option<&[Vec<u8>]>,
    ) -> Result<(), Error> {
        let profile = self.profile();

        let bytes = chain
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| Error::Storage)?;
        let a = rss_mdm_audit_integration::RequestAudit::new(
            self.profile(),
            tenant.to_string(),
            "device_pki_signing_result",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        a.identify_service("service:device-pki-signing");
        a.operation(
            attempt,
            "device_pki_signing_result",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let result = crate::mutation::run(
            profile,
            &self.audit,
            rss_request_context::TenantId::parse(&tenant.to_string())
                .map_err(|_| Error::Request)?,
            &a,
            (tenant, attempt, hash, chain, bytes),
            |ctx, c| {
                Box::pin(async move {
                    let (tenant, attempt, hash, chain, bytes) = ctx;
                    let row = sqlx::query(crate::storage_profile::sql(profile).signing_settle_1)
                        .bind(*tenant)
                        .bind(*attempt)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if row
                        .try_get::<Vec<u8>, _>("digest")
                        .map_err(|_| Error::Storage)?
                        != *hash
                    {
                        return Err(Error::Conflict);
                    }
                    if row
                        .try_get::<String, _>("state")
                        .map_err(|_| Error::Storage)?
                        != "signing"
                    {
                        if row
                            .try_get::<Option<Vec<u8>>, _>("chain")
                            .map_err(|_| Error::Storage)?
                            == *bytes
                        {
                            return Ok(crate::mutation::Change {
                                value: (),
                                replay: false,
                                key: String::new(),
                            });
                        }
                        return Err(Error::Conflict);
                    }
                    let state = if chain.is_some() { "issued" } else { "unknown" };
                    if let Some(chain) = chain {
                        let frozen: Frozen = serde_json::from_slice(
                            &row.try_get::<Vec<u8>, _>("binding")
                                .map_err(|_| Error::Storage)?,
                        )
                        .map_err(|_| Error::Storage)?;
                        crate::certificates::record_candidate_in(
                            profile,
                            c,
                            &tenant.to_string(),
                            &frozen.purpose,
                            None,
                            &frozen.issuer,
                            chain.first().ok_or(Error::Request)?,
                        )
                        .await?;
                    }
                    sqlx::query(crate::storage_profile::sql(profile).signing_settle_2)
                        .bind(*tenant)
                        .bind(*attempt)
                        .bind(state)
                        .bind(&*bytes)
                        .execute(c)
                        .await
                        .map_err(|_| Error::Storage)?;

                    Ok(crate::mutation::Change {
                        value: (),
                        replay: false,
                        key: format!("pki:{attempt}:{state}"),
                    })
                })
            },
        )
        .await;
        a.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
