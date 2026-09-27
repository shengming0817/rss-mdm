use crate::{
    ADMISSION, STORAGE,
    core::{Change, Policy},
    error::*,
};
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::MessagingDomain, policy::OperationDeadline};
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::Value;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
/// Tenant/runtime-bound Policy mutations. The caller owns commit and companion audit.
pub struct PolicyStore {
    tenant: TenantId,
    runtime: Arc<PgRuntime>,
    binding: PgOutboxWriter,
}
/// Host-frozen immutable resource content. The adapter never interprets device protocols.
pub struct Publication {
    /// Checked Policy aggregate or immutable owning Policy identity.
    pub policy: Policy,
    /// Opaque host content, present on publication only for a new semantic version.
    pub frozen: Option<Value>,
    /// Bounded caller provenance retained for audit; never a runtime authorization lease.
    pub author: Value,
    /// Publication Unix seconds.
    pub at: i64,
}
/// One immutable Policy execution/configuration version.
pub struct Version {
    /// Immutable version identity.
    pub id: Uuid,
    /// Checked Policy aggregate or immutable owning Policy identity.
    pub policy: Uuid,
    /// Monotonic semantic version number.
    pub number: i64,
    /// Opaque host content, present on publication only for a new semantic version.
    pub frozen: Value,
}
impl PolicyStore {
    /// Admit the exact owner schema and bind every mutation to this runtime instance.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, deadline, |tx| {
                    Box::pin(async move {
                        STORAGE.verify(tx, ADMISSION).await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )?;
        let binding = PgOutboxWriter::new(
            runtime.clone(),
            MessagingDomain::parse("mdm-policy").expect("constant domain"),
        );
        Ok(Self {
            tenant,
            runtime,
            binding,
        })
    }
    fn check(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.binding.validate_transaction(tx)?;
        Ok(if tx.tenant_id() == self.tenant {
            Ok(())
        } else {
            Err(Rejection::TenantMismatch)
        })
    }
    /// Atomically persist the checked configuration and, only when changed, a new immutable version.
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Publication,
    ) -> InTransaction<()> {
        input!(self.check(tx)?);
        let p = &input.policy;
        if p.revision < 1 || input.at < 0 {
            return Ok(Err(Rejection::InvalidInput));
        }
        STORAGE.lock(tx, "policy", &p.id.to_string()).await?;
        let old = read_in(tx, p.id).await?;
        let expected = (p.revision - 1) as u64;
        let checked = input!(
            Policy::apply(
                p.id,
                old.as_ref(),
                expected,
                &Change::Put {
                    definition: Box::new(p.definition.clone()),
                    enabled: p.enabled
                },
                p.version
            )
            .map_err(|e| match e {
                crate::core::Error::Malformed => Rejection::InvalidInput,
                crate::core::Error::Conflict => Rejection::Conflict,
                crate::core::Error::NotFound => Rejection::NotFound,
            })
        );
        if checked.policy.number != p.number
            || checked.policy.version != p.version
            || checked.semantic_changed != input.frozen.is_some()
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = self.tenant.to_string();
        let p = p.clone();
        let frozen = input.frozen.clone();
        let author = input.author.clone();
        let at = input.at;
        let hash = checked.semantic.to_vec();
        let definition = STORAGE.json("publish.definition", serde_json::to_value(&p.definition))?;
        tx.with_connection(move|c|Box::pin(async move {
   sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,enabled,definition,author,updated_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,current_version=excluded.current_version,version_number=excluded.version_number,enabled=excluded.enabled,definition=excluded.definition,author=excluded.author,updated_at=excluded.updated_at").bind(&tenant).bind(p.id).bind(p.revision).bind(p.version).bind(p.number).bind(p.enabled).bind(definition).bind(author).bind(at).execute(&mut *c).await?;
   if let Some(frozen)=frozen {sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)").bind(tenant).bind(p.version).bind(p.id).bind(p.number).bind(p.definition.resource.id).bind(p.definition.resource.version).bind(frozen).bind(hash).execute(c).await?;}
   Ok(())
  })).await?;
        Ok(Ok(()))
    }
    /// Recover a fixed request identity. A different body under that identity is rejected.
    pub async fn replay_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        fingerprint: &[u8],
    ) -> InTransaction<Option<Value>> {
        input!(self.check(tx)?);
        STORAGE.lock(tx, "request", &id.to_string()).await?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT fingerprint,receipt FROM mdm_policy.requests WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
        if let Some(row) = row {
            if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return Ok(Ok(Some(row.try_get("receipt")?)));
        }
        Ok(Ok(None))
    }
    /// Record the host-visible receipt in the same transaction as the Policy and audit.
    pub async fn receipt_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        fingerprint: &[u8],
        value: &Value,
    ) -> InTransaction<()> {
        input!(self.check(tx)?);
        let tenant = self.tenant.to_string();
        let fingerprint = fingerprint.to_vec();
        let value = value.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO mdm_policy.requests VALUES($1::uuid,$2,$3,$4)")
                    .bind(tenant)
                    .bind(id)
                    .bind(fingerprint)
                    .bind(value)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(Ok(()))
    }
    /// Publish one explicit trigger; devices consume it lazily without editing the Policy CAS.
    pub async fn trigger_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        version: Uuid,
        at: i64,
        deadline: i64,
    ) -> InTransaction<()> {
        input!(self.check(tx)?);
        if id.is_nil() || version.is_nil() || deadline <= at {
            return Ok(Err(Rejection::InvalidInput));
        }
        let Some(binding) = version_in(tx, version).await? else {
            return Ok(Err(Rejection::NotFound));
        };
        STORAGE
            .lock(tx, "policy", &binding.policy.to_string())
            .await?;
        let Some(policy) = read_in(tx, binding.policy).await? else {
            return Ok(Err(Rejection::NotFound));
        };
        if !policy.enabled
            || policy.version != version
            || !matches!(
                policy.definition.behavior,
                crate::core::Behavior::Execution { .. }
            )
        {
            return Ok(Err(Rejection::Conflict));
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_policy.triggers(tenant_id,id,version,created_at,deadline) VALUES($1::uuid,$2,$3,$4,$5)").bind(tenant).bind(id).bind(version).bind(at).bind(deadline).execute(c).await?;Ok(())})).await?;
        Ok(Ok(()))
    }
    /// Read the current aggregate through the store's own tenant/runtime fence.
    pub async fn get(
        &self,
        id: Uuid,
        deadline: OperationDeadline,
    ) -> Result<Option<Policy>, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, self, move |s, tx| {
                    Box::pin(async move {
                        input!(s.check(tx)?);
                        Ok(Ok(read_in(tx, id).await?))
                    })
                })
                .await,
        )
    }
}
/// Read a typed aggregate from the caller's tenant-scoped transaction.
/// Mutating consumers must serialize via their owner lock before trusting this snapshot.
pub async fn read_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Option<Policy>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT revision,current_version,version_number,enabled,definition FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
    row.map(|r| {
        Ok(Policy {
            id,
            revision: r.try_get("revision")?,
            version: r.try_get("current_version")?,
            number: r.try_get("version_number")?,
            enabled: r.try_get("enabled")?,
            definition: STORAGE.json(
                "read.definition",
                serde_json::from_value(r.try_get("definition")?),
            )?,
        })
    })
    .transpose()
}
/// Read immutable host content together with its owning Policy identity.
pub async fn version_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Option<Version>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT policy,number,frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
    row.map(|r| {
        Ok(Version {
            id,
            policy: r.try_get("policy")?,
            number: r.try_get("number")?,
            frozen: r.try_get("frozen")?,
        })
    })
    .transpose()
}
