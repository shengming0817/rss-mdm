use crate::{
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
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    runtime: Arc<PgRuntime>,
    reader: PolicyReader,
}
/// Host-frozen immutable resource content. The adapter never interprets device protocols.
pub struct Publication {
    /// Exact checked mutation, revalidated against the locked previous aggregate.
    pub change: Change,
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
    /// Immutable authored action identity; decoded by the Policy owner.
    pub action_kind: crate::core::ActionKind,
    /// Monotonic semantic version number.
    pub number: i64,
    /// Opaque host content, present on publication only for a new semantic version.
    pub frozen: Value,
}
impl PolicyStore {
    /// The immutable installation profile bound to this provider.
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    /// Admit the exact owner schema and bind every mutation to this runtime instance.
    pub async fn new(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, deadline, |tx| {
                    Box::pin(async move {
                        crate::storage(profile)
                            .verify(tx, crate::admission(profile))
                            .await?;
                        tx.with_connection(move |c| Box::pin(crate::verify_authority(profile, c)))
                            .await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )?;
        let reader = PolicyReader::bind(profile, runtime.clone(), tenant);
        Ok(Self {
            profile,
            tenant,
            runtime,
            reader,
        })
    }
    /// Borrow the read capability bound to this store's exact runtime and tenant.
    pub fn reader(&self) -> &PolicyReader {
        &self.reader
    }
    fn check(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.reader.check(tx)
    }
    /// Read for a management mutation under the existing aggregate lock and an exclusive row lock.
    /// The caller takes shared product fences before entering this method.
    pub async fn read_for_update_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> InTransaction<Option<Policy>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        lock_coordination_in(tx, id).await?;
        crate::storage(profile)
            .lock(tx, "policy", &id.to_string())
            .await?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_read_for_update_in_1)
                    .bind(tenant)
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(Ok(read_snapshot(profile, tx, id).await?))
    }
    /// Atomically persist the checked configuration and, only when changed, a new immutable version.
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Publication,
    ) -> InTransaction<()> {
        let profile = self.profile();

        input!(self.check(tx)?);
        let p = &input.policy;
        if p.revision < 1 || input.at < 0 {
            return Ok(Err(Rejection::InvalidInput));
        }
        crate::storage(profile)
            .lock(tx, "policy", &p.id.to_string())
            .await?;
        let old = read_snapshot(profile, tx, p.id).await?;
        let expected = (p.revision - 1) as u64;
        let checked = input!(
            Policy::apply(
                p.id,
                old.as_ref(),
                expected,
                &input.change,
                p.version,
                p.execution_binding
            )
            .map_err(|e| match e {
                crate::core::Error::Malformed => Rejection::InvalidInput,
                crate::core::Error::Conflict => Rejection::Conflict,
                crate::core::Error::NotFound => Rejection::NotFound,
            })
        );
        if serde_json::to_value(&checked.policy)
            .map_err(|_| crate::storage(profile).fault("policy.encode"))?
            != serde_json::to_value(p)
                .map_err(|_| crate::storage(profile).fault("policy.encode"))?
            || checked.policy.number != p.number
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
        let definition = crate::storage(profile)
            .json("publish.definition", serde_json::to_value(&p.definition))?;
        let written = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let write =
                        sqlx::query(crate::storage_profile::sql(profile).store_publish_in_1)
                            .bind(&tenant)
                            .bind(p.id)
                            .bind(p.revision)
                            .bind(p.version)
                            .bind(p.number)
                            .bind(p.state.as_str())
                            .bind(definition)
                            .bind(author)
                            .bind(at)
                            .bind(p.execution_binding.map(|v| v.to_vec()))
                            .execute(&mut *c)
                            .await;
                    match write {
                        Err(error)
                            if error
                                .as_database_error()
                                .is_some_and(|e| e.constraint() == Some("policy_alias_unique")) =>
                        {
                            return Ok(Err(Rejection::Conflict));
                        }
                        Err(error) => return Err(error),
                        Ok(_) => (),
                    }
                    if let Some(frozen) = frozen {
                        sqlx::query(crate::storage_profile::sql(profile).store_publish_in_2)
                            .bind(tenant)
                            .bind(p.version)
                            .bind(p.id)
                            .bind(p.number)
                            .bind(p.definition.action.resource().map(|r| r.id()))
                            .bind(p.definition.action.resource().map(|r| r.version()))
                            .bind(frozen)
                            .bind(hash)
                            .bind(p.definition.action.kind().as_str())
                            .execute(c)
                            .await?;
                    }
                    Ok(Ok(()))
                })
            })
            .await?;
        Ok(written)
    }
    /// Read an immutable management receipt without executing or replaying a command.
    pub async fn operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> InTransaction<Option<Value>> {
        input!(self.check(tx)?);
        let tenant = self.tenant.to_string();
        let sql = crate::storage_profile::sql(self.profile()).store_replay_in_1;
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(sql)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        Ok(Ok(row.map(|r| r.try_get("receipt")).transpose()?))
    }
    /// Recover a fixed request identity. A different body under that identity is rejected.
    pub async fn replay_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        fingerprint: &[u8],
    ) -> InTransaction<Option<Value>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        crate::storage(profile)
            .lock(tx, "request", &id.to_string())
            .await?;
        let tenant = self.tenant.to_string();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_replay_in_1)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
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
        let profile = self.profile();

        input!(self.check(tx)?);
        let tenant = self.tenant.to_string();
        let fingerprint = fingerprint.to_vec();
        let value = value.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_receipt_in_1)
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
        let profile = self.profile();

        input!(self.check(tx)?);
        if id.is_nil() || version.is_nil() || deadline <= at {
            return Ok(Err(Rejection::InvalidInput));
        }
        let Some(binding) = version_snapshot(profile, tx, version).await? else {
            return Ok(Err(Rejection::NotFound));
        };
        crate::storage(profile)
            .lock(tx, "policy", &binding.policy.to_string())
            .await?;
        let Some(policy) = read_snapshot(profile, tx, binding.policy).await? else {
            return Ok(Err(Rejection::NotFound));
        };
        if !policy.state.is_enabled()
            || policy.version != version
            || !policy.definition.action.kind().supports_rerun()
        {
            return Ok(Err(Rejection::Conflict));
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_trigger_in_1)
                    .bind(tenant)
                    .bind(id)
                    .bind(version)
                    .bind(at)
                    .bind(deadline)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
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
                        s.reader.read_in(tx, id).await
                    })
                })
                .await,
        )
    }
}
/// Read a typed aggregate from the caller's tenant-scoped transaction.
/// Mutating consumers must serialize via their owner lock before trusting this snapshot.
async fn read_snapshot(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>, PgError> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(read_snapshot_on(profile, c, tenant, id).await) })
    })
    .await?
}
async fn read_snapshot_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<Policy>, PgError> {
    let row = sqlx::query(crate::storage_profile::sql(profile).store_read_snapshot_on_1)
        .bind(tenant.to_string())
        .bind(id)
        .fetch_optional(c)
        .await?;
    row.map(|r| {
        Ok(Policy {
            id,
            revision: r.try_get("revision")?,
            version: r.try_get("current_version")?,
            number: r.try_get("version_number")?,
            state: crate::storage(profile).json(
                "policy.state",
                serde_json::from_value(serde_json::json!(r.try_get::<String, _>("state")?)),
            )?,
            execution_binding: r
                .try_get::<Option<Vec<u8>>, _>("execution_binding")?
                .map(|v| {
                    v.try_into()
                        .map_err(|_| crate::storage(profile).fault("lifecycle binding"))
                })
                .transpose()?,
            definition: crate::storage(profile).json(
                "read.definition",
                serde_json::from_value(r.try_get("definition")?),
            )?,
        })
    })
    .transpose()
}
/// Read immutable host content together with its owning Policy identity.
async fn version_snapshot(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Version>, PgError> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(version_snapshot_on(profile, c, tenant, id).await) })
    })
    .await?
}
async fn version_snapshot_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<Version>, PgError> {
    let row = sqlx::query(crate::storage_profile::sql(profile).store_version_snapshot_on_1)
        .bind(tenant.to_string())
        .bind(id)
        .fetch_optional(c)
        .await?;
    row.map(|r| {
        Ok(Version {
            id,
            policy: r.try_get("policy")?,
            number: r.try_get("number")?,
            action_kind: crate::storage(profile).json(
                "version.action_kind",
                serde_json::from_value(serde_json::json!(r.try_get::<String, _>("action_kind")?)),
            )?,
            frozen: r.try_get("frozen")?,
        })
    })
    .transpose()
}

/// Read-only capability bound to one exact RSS runtime instance and tenant.
/// Composition admits its read-role/schema contract before binding this handle;
/// binding neither opens a connection nor grants database privileges.
pub struct PolicyReader {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    binding: PgOutboxWriter,
}
impl PolicyReader {
    /// The immutable installation profile bound to this provider.
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    async fn check_on(&self, c: &mut sqlx::PgConnection) -> Result<(), PgError> {
        let profile = self.profile();

        let tenant: Option<String> =
            sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
                .fetch_one(c)
                .await?;
        if tenant.as_deref() != Some(self.tenant.to_string().as_str()) {
            return Err(crate::storage(profile).fault("reader tenant"));
        }
        Ok(())
    }
    /// Borrow the page's admitted read-only connection; retain this capability's tenant.
    pub async fn read_on(
        &self,
        c: &mut sqlx::PgConnection,
        id: Uuid,
    ) -> InTransaction<Option<Policy>> {
        let profile = self.profile();

        self.check_on(c).await?;
        Ok(Ok(read_snapshot_on(profile, c, self.tenant, id).await?))
    }
    /// Read an exact immutable version in the caller's tenant-bound page snapshot.
    pub async fn version_on(
        &self,
        c: &mut sqlx::PgConnection,
        id: Uuid,
    ) -> InTransaction<Option<Version>> {
        let profile = self.profile();

        self.check_on(c).await?;
        Ok(Ok(version_snapshot_on(profile, c, self.tenant, id).await?))
    }

    /// Count every immutable Policy version referencing this resource, including
    /// superseded versions and disabled or archived policies. The initiating
    /// Resource owner holds its aggregate lock until this transaction settles.
    pub async fn resource_usage_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        version: &str,
    ) -> InTransaction<u64> {
        let profile = self.profile();

        input!(self.check(tx)?);
        let tenant = self.tenant.to_string();
        let resource = resource.to_owned();
        let version = version.to_owned();
        let count: i64 = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                        "SELECT count(*) FROM ({}) facts",
                        crate::resource_reference_facts_sql(profile)
                    )))
                    .bind(tenant)
                    .bind(resource)
                    .bind(version)
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        Ok(Ok(count as u64))
    }

    /// Resolve an exact address in this reader's tenant; the host checks current visibility.
    pub async fn resolve_in(
        &self,
        tx: &mut PgTransaction<'_>,
        selector: &rss_mdm_agent_wire::runtime::CapabilitySelector,
    ) -> InTransaction<Option<Uuid>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        if let Some(id) = input!(selector.policy_id().map_err(|_| Rejection::InvalidInput)) {
            return Ok(Ok(Some(id)));
        }
        let rss_mdm_agent_wire::runtime::CapabilitySelector::Alias { alias } = selector else {
            unreachable!()
        };
        let tenant = self.tenant.to_string();
        let alias = alias.as_str().to_owned();
        let id = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(crate::storage_profile::sql(profile).store_resolve_in_1)
                        .bind(tenant)
                        .bind(alias)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        Ok(Ok(id))
    }
    /// Bind a host-admitted runtime. Command readers retain their SELECT-only role.
    pub fn bind(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
    ) -> Self {
        Self {
            profile,
            tenant,
            binding: PgOutboxWriter::new(
                runtime,
                MessagingDomain::parse(match profile {
                    rss_mdm_install_support::StorageProfile::Mdm => "mdm-policy",
                    rss_mdm_install_support::StorageProfile::Da => "da-policy",
                })
                .expect("constant domain"),
            ),
        }
    }
    fn check(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.binding.validate_transaction(tx)?;
        Ok(if tx.tenant_id() == self.tenant {
            Ok(())
        } else {
            Err(Rejection::TenantMismatch)
        })
    }
    /// Fence a current source read using the shared Policy reader lock.
    pub async fn locked_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> InTransaction<Option<Policy>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_locked_in_1)
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(Ok(read_snapshot(profile, tx, id).await?))
    }
    /// Read an aggregate only through this capability's runtime and tenant.
    pub async fn read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> InTransaction<Option<Policy>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        Ok(Ok(read_snapshot(profile, tx, id).await?))
    }
    /// Historical action identities remain relevant when an authored action changes owners.
    pub async fn action_kinds_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: Uuid,
    ) -> InTransaction<Vec<crate::core::ActionKind>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        let tenant = self.tenant.to_string();
        let values: Vec<String> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(crate::storage_profile::sql(profile).store_action_kinds_in_1)
                        .bind(tenant)
                        .bind(policy)
                        .fetch_all(c)
                        .await
                })
            })
            .await?;
        let values = values
            .into_iter()
            .map(|value| {
                crate::storage(profile).json(
                    "version.action_kind",
                    serde_json::from_value(serde_json::json!(value)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Ok(values))
    }
    /// Read immutable version content through this capability's runtime and tenant.
    pub async fn version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> InTransaction<Option<Version>> {
        let profile = self.profile();

        input!(self.check(tx)?);
        Ok(Ok(version_snapshot(profile, tx, id).await?))
    }
}

/// Serialize management and Execution source recovery using the existing Policy aggregate key.
/// This lock also covers creation, where no Policy row exists yet.
pub async fn lock_coordination_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<(), PgError> {
    let key = format!("{}:policy:{id}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
