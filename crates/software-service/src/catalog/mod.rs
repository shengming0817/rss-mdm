mod binding;
pub use binding::{
    BindingRequest, admitted_on, binding_on, bindings_many_locked_on, bindings_many_on,
    execution_admitted_on,
};
// Borrowed-transaction software lifecycle; external publication is a separate capability.
mod imports;
mod installers;
mod model;
pub use model::*;
mod event;
pub(crate) mod storage;
use crate::AuditPort;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_resource as r;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("software read budget exceeded")]
    Capacity,
    #[error("invalid software definition")]
    Input,
    #[error("software source behavior unsupported")]
    Unsupported,
    #[error("exact source dependency unavailable or mismatched")]
    Dependency,
    #[error("software revision or operation conflict")]
    Conflict,
    #[error("software source or version not admitted")]
    NotAdmitted,
    #[error("software resource unavailable")]
    Missing,
    #[error("software content unavailable or invalid")]
    Content,
    #[error("software storage integrity failure")]
    Integrity,
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Audit(#[from] rss_mdm_audit_integration::Error),
    #[error(transparent)]
    Fact(#[from] rss_mdm_audit_integration::InvalidFact),
}
pub type Result<T> = std::result::Result<T, Error>;
pub const INSTALL_SQL: &str = include_str!("install.sql");
pub struct Catalog {
    tenant: TenantId,
    audit: Arc<dyn AuditPort>,
    writer: PgOutboxWriter,
}
/// Borrowed-transaction reads and lifecycle rules; no runtime, audit writer or commit capability.
#[derive(Clone, Copy)]
pub struct Reader {
    tenant: TenantId,
}
impl Reader {
    pub fn new(tenant: TenantId) -> Self {
        Self { tenant }
    }
    /// Shared software lifecycle lock, acquired before Resource locks by companions.
    pub async fn lock_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.tenant(tx)?;
        storage::lock(tx).await
    }
    pub async fn read_lock_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.tenant(tx)?;
        storage::read_lock(tx).await
    }

    pub async fn source_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        revision: &str,
    ) -> Result<Value> {
        self.tenant(tx)?;
        let (definition, lifecycle) = storage::source(tx, id, revision)
            .await?
            .ok_or(Error::Missing)?;
        Ok(json!({"snapshot":definition.snapshot()?,"source":definition,"lifecycle":lifecycle}))
    }
    fn tenant(&self, tx: &PgTransaction<'_>) -> Result<()> {
        if tx.tenant_id() != self.tenant {
            Err(Error::NotAdmitted)
        } else {
            Ok(())
        }
    }
    pub async fn version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        version: &str,
    ) -> Result<r::Version> {
        self.tenant(tx)?;
        let (v, state) = rss_mdm_resource_postgres::lock_reference_in(
            tx,
            &r::Id::new(resource).map_err(|_| Error::Input)?,
            &r::Id::new(version).map_err(|_| Error::Input)?,
        )
        .await?
        .map_err(|_| Error::Missing)?;
        if v.kind() != r::Kind::Software || state == r::State::Archived {
            return Err(Error::Missing);
        }
        Ok(v)
    }
    /// Borrow exact resource facts; mutation callers retain the resource lock.
    pub(crate) async fn version_on(
        &self,
        c: &mut sqlx::PgConnection,
        resource: &str,
        label: &str,
        locked: bool,
    ) -> Result<r::Version> {
        if locked {
            rss_mdm_resource_postgres::lock_reference_key_on(
                c,
                self.tenant,
                &r::Id::new(resource).map_err(|_| Error::Input)?,
            )
            .await?;
        }
        let mut facts = rss_mdm_resource_postgres::version_facts_on(
            c,
            self.tenant,
            &[(resource.to_owned(), label.to_owned())],
        )
        .await?;
        let (version, state) = facts.versions.pop().flatten().ok_or(Error::Missing)?;
        if version.kind() != r::Kind::Software || state == r::State::Archived {
            return Err(Error::Missing);
        }
        Ok(version)
    }
    /// Inspect an original operation without requiring current content availability.
    /// The subsequent mutation entry replays and audits this receipt in its own transaction.
    pub async fn has_version_receipt_in(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        resource: &str,
        label: &str,
        op: &Operation<VersionChange>,
    ) -> Result<bool> {
        self.tenant(tx)?;
        check_operation(op.operation_id, op.expected_revision)?;
        let hash = fingerprint(&(self.tenant.to_string(), actor(audit)?, resource, label, op))?;
        Ok(storage::replay(tx, op.operation_id, &hash).await?.is_some())
    }
    /// Direct authoring is private; imported evidence is produced only by the importer.
    pub async fn private_authoring_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: &r::Version,
    ) -> Result<()> {
        self.tenant(tx)?;
        storage::lock(tx).await?;
        for variant in version.variants() {
            let r::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Input);
            };
            if !matches!(definition.spec().provenance, r::SoftwareProvenance::Private) {
                return Err(Error::Input);
            }
            let (source, _) = storage::source(
                tx,
                &definition.spec().source.id,
                &definition.spec().source.revision,
            )
            .await?
            .ok_or(Error::Missing)?;
            if !matches!(source.protocol, SourceProtocol::Private)
                || source.snapshot()? != definition.spec().source
            {
                return Err(Error::Input);
            }
        }
        Ok(())
    }
    /// Native publication borrows the same source/version/dependency lifecycle locks.
    /// This grants no mutation capability to the publication runtime.
    pub async fn publication_admitted_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: &r::Version,
    ) -> Result<()> {
        self.tenant(tx)?;
        storage::lock(tx).await?;
        let current = self
            .version_in(tx, version.resource().as_str(), version.label().as_str())
            .await?;
        let lifecycle =
            storage::lifecycle(tx, version.resource().as_str(), version.label().as_str())
                .await?
                .ok_or(Error::NotAdmitted)?;
        if current.digest() != version.digest()
            || lifecycle.digest != version.digest().bytes()
            || !matches!(lifecycle.state, LifecycleState::Enabled)
        {
            return Err(Error::NotAdmitted);
        }
        self.check_sources(tx, version).await?;
        self.dependencies(tx, version).await
    }
    /// Hold current source lifecycle stable through the caller's final transaction.
    pub async fn source_admitted_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &r::SoftwareSource,
    ) -> Result<()> {
        self.tenant(tx)?;
        storage::read_lock(tx).await?;
        let (stored, lifecycle) = storage::source(tx, &source.id, &source.revision)
            .await?
            .ok_or(Error::NotAdmitted)?;
        if !matches!(lifecycle.state, LifecycleState::Enabled) || stored.snapshot()? != *source {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }
    async fn check_sources(&self, tx: &mut PgTransaction<'_>, version: &r::Version) -> Result<()> {
        for variant in version.variants() {
            let r::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Input);
            };
            self.source_admitted_in(tx, &definition.spec().source)
                .await?;
        }
        Ok(())
    }
    async fn dependencies(&self, tx: &mut PgTransaction<'_>, root: &r::Version) -> Result<()> {
        self.dependency_versions_in(tx, root).await.map(|_| ())
    }
    /// All-variant fixed materials, also consumed by native publication derivation.
    pub(crate) async fn dependency_versions_in(
        &self,
        tx: &mut PgTransaction<'_>,
        root: &r::Version,
    ) -> Result<Vec<r::Version>> {
        self.tenant(tx)?;
        self.read_lock_in(tx).await?;
        tx.with_connection_context(&mut (self, root), |(reader, root), c| {
            Box::pin(async move { Ok(reader.dependency_versions_on(c, root, true).await) })
        })
        .await?
    }
    pub(crate) async fn dependency_versions_on(
        &self,
        c: &mut sqlx::PgConnection,
        root: &r::Version,
        locked: bool,
    ) -> Result<Vec<r::Version>> {
        use std::collections::BTreeSet;
        let root_ref = r::SoftwareDependency {
            resource: root.resource().as_str().into(),
            version: root.label().as_str().into(),
            sha256: root.digest().bytes(),
        };
        let mut active = BTreeSet::from([(root_ref.resource.clone(), root_ref.version.clone())]);
        let mut done = BTreeSet::new();
        let mut materials = std::collections::BTreeMap::<_, r::Version>::new();
        let mut stack = vec![(root_ref, true)];
        stack.extend(dependency_refs(root)?.into_iter().map(|d| (d, false)));
        while let Some((dependency, exit)) = stack.pop() {
            let key = (dependency.resource.clone(), dependency.version.clone());
            if exit {
                active.remove(&key);
                done.insert(key);
                continue;
            }
            if active.contains(&key) {
                return Err(Error::Input);
            }
            if let Some(previous) = materials.get(&key)
                && previous.digest().bytes() != dependency.sha256
            {
                return Err(Error::NotAdmitted);
            }
            if done.contains(&key) {
                continue;
            }
            if active.len() + done.len() >= 256 {
                return Err(Error::Input);
            }
            let version = self
                .version_on(c, &dependency.resource, &dependency.version, locked)
                .await?;
            let lifecycle =
                storage::lifecycle_on(c, self.tenant, &dependency.resource, &dependency.version)
                    .await?
                    .ok_or(Error::NotAdmitted)?;
            if version.digest().bytes() != dependency.sha256
                || lifecycle.digest != dependency.sha256
                || !matches!(lifecycle.state, LifecycleState::Enabled)
            {
                return Err(Error::NotAdmitted);
            }
            for variant in version.variants() {
                let r::Declaration::Software { definition } = variant.declaration() else {
                    return Err(Error::Input);
                };
                let expected = &definition.spec().source;
                let (source, lifecycle) =
                    storage::source_on(c, self.tenant, &expected.id, &expected.revision)
                        .await?
                        .ok_or(Error::NotAdmitted)?;
                if !matches!(lifecycle.state, LifecycleState::Enabled)
                    || source.snapshot()? != *expected
                {
                    return Err(Error::NotAdmitted);
                }
            }
            materials.insert(key.clone(), version.clone());
            active.insert(key);
            stack.push((dependency, true));
            stack.extend(dependency_refs(&version)?.into_iter().map(|d| (d, false)));
        }
        Ok(materials.into_values().collect())
    }
    pub async fn version_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        label: &str,
    ) -> Result<Value> {
        self.tenant(tx)?;
        let version = self.version_in(tx, resource, label).await?;
        let lifecycle = storage::lifecycle(tx, resource, label).await?;
        Ok(
            json!({"resource":resource,"version":label,"resourceDigest":version.digest().bytes(),"lifecycle":lifecycle}),
        )
    }
    /// Recheck the selected immutable variant and its explicit withdrawal state.
    pub async fn recheck_admitted_in(
        &self,
        tx: &mut PgTransaction<'_>,
        expected: &FrozenSoftware,
    ) -> Result<()> {
        let current = self
            .resolve_admitted_in(
                tx,
                expected.version.resource().as_str(),
                expected.version.label().as_str(),
                expected.platform,
                expected.architecture,
                &expected.variant,
            )
            .await?;
        if current.version.digest() != expected.version.digest() {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }
    /// Recheck current lifecycle and exact variant under the caller's execution transaction.
    pub async fn resolve_admitted_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        label: &str,
        platform: r::Platform,
        architecture: r::Architecture,
        variant: &r::Id,
    ) -> Result<FrozenSoftware> {
        self.tenant(tx)?;
        storage::read_lock(tx).await?;
        tx.with_connection_context(
            &mut (self, resource, label, variant),
            |(reader, resource, label, variant), c| {
                Box::pin(async move {
                    Ok(reader
                        .resolve_admitted_on(
                            c,
                            resource,
                            label,
                            (platform, architecture),
                            variant,
                            true,
                        )
                        .await)
                })
            },
        )
        .await?
    }
    pub(crate) async fn resolve_admitted_on(
        &self,
        c: &mut sqlx::PgConnection,
        resource: &str,
        label: &str,
        target: (r::Platform, r::Architecture),
        variant: &r::Id,
        locked: bool,
    ) -> Result<FrozenSoftware> {
        let (platform, architecture) = target;
        let version = self.version_on(c, resource, label, locked).await?;
        let lifecycle = storage::lifecycle_on(c, self.tenant, resource, label)
            .await?
            .ok_or(Error::NotAdmitted)?;
        if !matches!(lifecycle.state, LifecycleState::Enabled)
            || lifecycle.digest != version.digest().bytes()
        {
            return Err(Error::NotAdmitted);
        }
        let selected = version
            .resolve(platform, architecture, variant)
            .map_err(|_| Error::Missing)?;
        let r::Declaration::Software { definition } = selected.declaration() else {
            return Err(Error::Input);
        };
        let expected = &definition.spec().source;
        let (source, source_lifecycle) =
            storage::source_on(c, self.tenant, &expected.id, &expected.revision)
                .await?
                .ok_or(Error::NotAdmitted)?;
        if !matches!(source_lifecycle.state, LifecycleState::Enabled)
            || source.snapshot()? != *expected
        {
            return Err(Error::NotAdmitted);
        }
        Ok(FrozenSoftware {
            source,
            version,
            variant: variant.clone(),
            platform,
            architecture,
            lifecycle,
        })
    }
}
impl Catalog {
    pub fn reader(&self) -> Reader {
        Reader::new(self.tenant)
    }
    pub fn new(runtime: Arc<PgRuntime>, tenant: TenantId, audit: Arc<dyn AuditPort>) -> Self {
        Self {
            tenant,
            audit,
            writer: PgOutboxWriter::new(runtime, event::domain()),
        }
    }

    async fn begin(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        key: &str,
    ) -> Result<()> {
        if tx.tenant_id() != self.tenant {
            return Err(Error::NotAdmitted);
        }
        storage::lock(tx).await?;
        self.audit
            .prepare_in(tx, audit, &[event::partition(self.tenant, key)?])
            .await?;
        Ok(())
    }
    async fn record(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        identity: (&str, uuid::Uuid, &[u8]),
        value: &Value,
        replayed: bool,
    ) -> Result<()> {
        let (key, id, hash) = identity;
        if audit.tenant() != self.tenant.to_string() {
            return Err(Error::NotAdmitted);
        }
        if !replayed {
            storage::receipt(tx, id, hash, value).await?;
            event::append(&self.writer, tx, key, id, value).await?;
        }
        let fact = Fact::business(audit, &format!("software:{id}"), 200, "success", None)?;
        (if replayed {
            Ok(())
        } else {
            self.audit.append_in(tx, &fact).await
        })?;
        Ok(())
    }
    pub async fn source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        id: &str,
        revision: &str,
        op: &Operation<SourceChange>,
    ) -> Result<Value> {
        check_operation(op.operation_id, op.expected_revision)?;
        r::Id::new(id).map_err(|_| Error::Input)?;
        r::Id::new(revision).map_err(|_| Error::Input)?;
        let key = format!("source/{id}/{revision}");
        self.begin(tx, audit, &key).await?;
        self.source_prepared_in(tx, audit, id, revision, op).await
    }
    /// The composing catalog operation has declared all partitions and acquired catalog locks.
    async fn source_prepared_in(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        id: &str,
        revision: &str,
        op: &Operation<SourceChange>,
    ) -> Result<Value> {
        let key = format!("source/{id}/{revision}");
        let actor = actor(audit)?;
        let hash = fingerprint(&(self.tenant.to_string(), &actor, id, revision, op))?;
        if let Some(value) = storage::replay(tx, op.operation_id, &hash).await? {
            self.record(tx, audit, (&key, op.operation_id, &hash), &value, true)
                .await?;
            return Ok(value);
        }
        let old = storage::source(tx, id, revision).await?;
        if old.as_ref().map_or(0, |(_, a)| a.revision) != op.expected_revision {
            return Err(Error::Conflict);
        }
        let (definition, state) = match &op.input {
            SourceChange::Register { definition } => {
                if old.is_some() || definition.id != id || definition.revision != revision {
                    return Err(Error::Conflict);
                }
                definition.snapshot()?;
                (definition.clone(), LifecycleState::Enabled)
            }
            SourceChange::Enable => {
                let (d, a) = old.ok_or(Error::Missing)?;
                if matches!(a.state, LifecycleState::Enabled) {
                    return Err(Error::Conflict);
                }
                (d, LifecycleState::Enabled)
            }
            SourceChange::Disable => {
                let (d, a) = old.ok_or(Error::Missing)?;
                if !matches!(a.state, LifecycleState::Enabled) {
                    return Err(Error::Conflict);
                }
                (d, LifecycleState::Disabled)
            }
        };
        let snapshot = definition.snapshot()?;
        let lifecycle = Lifecycle {
            revision: op.expected_revision + 1,
            state,
            operation: op.operation_id,
            actor,
            at: storage::now(tx).await?,
            digest: snapshot.sha256,
        };
        storage::save_source(tx, &definition, &lifecycle).await?;
        let value = json!({"source":definition,"snapshot":snapshot,"lifecycle":lifecycle});
        self.record(tx, audit, (&key, op.operation_id, &hash), &value, false)
            .await?;
        Ok(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the borrowed transaction declares content and all ordered message partitions together"
    )]
    pub async fn version_change_in(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        resource: &str,
        label: &str,
        op: &Operation<VersionChange>,
        content: Option<&dyn VerifiedContent>,
        additional: &[rss_transactional_messaging::message::PartitionIdentity],
    ) -> Result<Value> {
        check_operation(op.operation_id, op.expected_revision)?;
        let key = format!("resource/{resource}/{label}");
        self.reader().tenant(tx)?;
        storage::lock(tx).await?;
        let mut partitions = additional.to_vec();
        partitions.push(event::partition(self.tenant, &key)?);
        self.audit.prepare_in(tx, audit, &partitions).await?;
        let actor = actor(audit)?;
        let hash = fingerprint(&(self.tenant.to_string(), &actor, resource, label, op))?;
        if let Some(value) = storage::replay(tx, op.operation_id, &hash).await? {
            self.record(tx, audit, (&key, op.operation_id, &hash), &value, true)
                .await?;
            return Ok(value);
        }
        let version = self.reader().version_in(tx, resource, label).await?;
        let old = storage::lifecycle(tx, resource, label).await?;
        if old.as_ref().map_or(0, |a| a.revision) != op.expected_revision {
            return Err(Error::Conflict);
        }
        let state = match &op.input {
            VersionChange::Enable => {
                if old
                    .as_ref()
                    .is_some_and(|a| matches!(a.state, LifecycleState::Enabled))
                {
                    return Err(Error::Conflict);
                }
                if content.is_none_or(|c| c.resource_digest() != version.digest().bytes()) {
                    return Err(Error::Content);
                }
                self.reader().check_sources(tx, &version).await?;
                self.reader().dependencies(tx, &version).await?;
                storage::freeze_materials(tx, &version).await?;
                LifecycleState::Enabled
            }
            VersionChange::Withdraw => {
                if old
                    .as_ref()
                    .is_none_or(|a| !matches!(a.state, LifecycleState::Enabled))
                {
                    return Err(Error::Conflict);
                }
                LifecycleState::Withdrawn
            }
        };
        let lifecycle = Lifecycle {
            revision: op.expected_revision + 1,
            state,
            operation: op.operation_id,
            actor,
            at: storage::now(tx).await?,
            digest: version.digest().bytes(),
        };
        storage::save_lifecycle(tx, resource, label, &lifecycle).await?;
        let value = json!({"resource":resource,"version":label,"lifecycle":lifecycle});
        self.record(tx, audit, (&key, op.operation_id, &hash), &value, false)
            .await?;
        Ok(value)
    }
}
fn actor(audit: &RequestAudit) -> Result<String> {
    let s = audit.snapshot();
    let actor = s.actor.ok_or(Error::NotAdmitted)?;
    let instance = s.instance.ok_or(Error::NotAdmitted)?;
    if actor.is_empty() {
        return Err(Error::NotAdmitted);
    }
    Ok(format!("{instance}:{actor}"))
}

pub(crate) fn fingerprint(v: &impl serde::Serialize) -> Result<Vec<u8>> {
    Ok(Sha256::digest(serde_json::to_vec(v).map_err(|_| Error::Input)?).to_vec())
}
fn check_operation(id: uuid::Uuid, revision: u64) -> Result<()> {
    if id.is_nil() || revision >= i64::MAX as u64 {
        Err(Error::Input)
    } else {
        Ok(())
    }
}

pub const ADMISSION_SQL: &str = include_str!("admission.sql");

fn dependency_refs(version: &r::Version) -> Result<Vec<r::SoftwareDependency>> {
    let mut dependencies = std::collections::BTreeMap::new();
    for variant in version.variants() {
        let r::Declaration::Software { definition } = variant.declaration() else {
            return Err(Error::Input);
        };
        for dependency in &definition.spec().dependencies {
            dependencies.insert(
                (dependency.resource.clone(), dependency.version.clone()),
                dependency.clone(),
            );
        }
    }
    if dependencies.len() > 32 {
        return Err(Error::Input);
    }
    Ok(dependencies.into_values().collect())
}

/// Resource archive checks borrow the existing product transaction.
pub async fn reference_count_in(
    tx: &mut PgTransaction<'_>,
    resource: &str,
    version: &str,
) -> Result<u64> {
    let tenant = tx.tenant_id().to_string();
    let resource = resource.to_owned();
    let version = version.to_owned();
    let count:i64=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT count(*) FROM mdm_software.versions WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3").bind(tenant).bind(resource).bind(version).fetch_one(c).await})).await?;
    u64::try_from(count).map_err(|_| Error::Integrity)
}

#[cfg(feature = "integration")]
pub mod fixture;

/// Current installation permissions and objects of this owner.
pub const RELATIONS_SQL: &str = include_str!("relations.sql");
