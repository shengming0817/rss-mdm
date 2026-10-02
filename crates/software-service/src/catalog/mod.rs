//! Borrowed-transaction enterprise admission; external publication is a separate capability.
mod imports;
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
    #[error("invalid software definition or evidence")]
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
impl Catalog {
    pub fn new(runtime: Arc<PgRuntime>, tenant: TenantId, audit: Arc<dyn AuditPort>) -> Self {
        Self {
            tenant,
            audit,
            writer: PgOutboxWriter::new(runtime, event::domain()),
        }
    }
    /// Shared software admission lock, acquired before Resource locks by companions.
    pub async fn lock_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.tenant(tx)?;
        storage::lock(tx).await
    }
    async fn begin(&self, tx: &mut PgTransaction<'_>, key: &str) -> Result<()> {
        if tx.tenant_id() != self.tenant {
            return Err(Error::NotAdmitted);
        }
        tx.prepare_outbox_partitions(&[event::partition(self.tenant, key)?])
            .await?;
        self.audit.lock_in(tx).await?;
        storage::lock(tx).await
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
        let fact = Fact::business(audit, &format!("software:{id}"), hash, 200, "success", None)?;
        self.audit.append_in(tx, &fact, replayed).await?;
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
        self.begin(tx, &key).await?;
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
        let (definition, state, evidence) = match &op.input {
            SourceChange::Register { definition } => {
                if old.is_some() || definition.id != id || definition.revision != revision {
                    return Err(Error::Conflict);
                }
                definition.snapshot()?;
                (definition.clone(), AdmissionState::Registered, vec![])
            }
            SourceChange::Approve { evidence } => {
                model::evidence(evidence)?;
                let (d, a) = old.ok_or(Error::Missing)?;
                if matches!(a.state, AdmissionState::Approved) {
                    return Err(Error::Conflict);
                }
                (d, AdmissionState::Approved, evidence.clone())
            }
            SourceChange::Withdraw { evidence } => {
                model::evidence(evidence)?;
                let (d, a) = old.ok_or(Error::Missing)?;
                if !matches!(a.state, AdmissionState::Approved) {
                    return Err(Error::Conflict);
                }
                (d, AdmissionState::Withdrawn, evidence.clone())
            }
        };
        let snapshot = definition.snapshot()?;
        let admission = Admission {
            revision: op.expected_revision + 1,
            state,
            operation: op.operation_id,
            actor,
            evidence,
            at: storage::now(tx).await?,
            digest: snapshot.sha256,
        };
        storage::save_source(tx, &definition, &admission).await?;
        let value = json!({"source":definition,"snapshot":snapshot,"admission":admission});
        self.record(tx, audit, (&key, op.operation_id, &hash), &value, false)
            .await?;
        Ok(value)
    }
    pub async fn source_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        revision: &str,
    ) -> Result<Value> {
        self.tenant(tx)?;
        let (definition, admission) = storage::source(tx, id, revision)
            .await?
            .ok_or(Error::Missing)?;
        Ok(json!({"snapshot":definition.snapshot()?,"source":definition,"admission":admission}))
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
    pub async fn version_change_in(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        resource: &str,
        label: &str,
        op: &Operation<VersionChange>,
        content: Option<&dyn VerifiedContent>,
    ) -> Result<Value> {
        check_operation(op.operation_id, op.expected_revision)?;
        let key = format!("resource/{resource}/{label}");
        self.begin(tx, &key).await?;
        let actor = actor(audit)?;
        let hash = fingerprint(&(self.tenant.to_string(), &actor, resource, label, op))?;
        if let Some(value) = storage::replay(tx, op.operation_id, &hash).await? {
            self.record(tx, audit, (&key, op.operation_id, &hash), &value, true)
                .await?;
            return Ok(value);
        }
        let version = self.version_in(tx, resource, label).await?;
        let old = storage::admission(tx, resource, label).await?;
        if old.as_ref().map_or(0, |a| a.revision) != op.expected_revision {
            return Err(Error::Conflict);
        }
        let (state, evidence) = match &op.input {
            VersionChange::Approve { evidence } => {
                model::evidence(evidence)?;
                if old
                    .as_ref()
                    .is_some_and(|a| matches!(a.state, AdmissionState::Approved))
                {
                    return Err(Error::Conflict);
                }
                if content.is_none_or(|c| c.resource_digest() != version.digest().bytes()) {
                    return Err(Error::Content);
                }
                self.check_sources(tx, &version).await?;
                self.dependencies(tx, &version).await?;
                storage::freeze_materials(tx, &version).await?;
                (AdmissionState::Approved, evidence.clone())
            }
            VersionChange::Withdraw { evidence } => {
                model::evidence(evidence)?;
                if old
                    .as_ref()
                    .is_none_or(|a| !matches!(a.state, AdmissionState::Approved))
                {
                    return Err(Error::Conflict);
                }
                (AdmissionState::Withdrawn, evidence.clone())
            }
        };
        let admission = Admission {
            revision: op.expected_revision + 1,
            state,
            operation: op.operation_id,
            actor,
            evidence,
            at: storage::now(tx).await?,
            digest: version.digest().bytes(),
        };
        storage::save_admission(tx, resource, label, &admission).await?;
        let value = json!({"resource":resource,"version":label,"admission":admission});
        self.record(tx, audit, (&key, op.operation_id, &hash), &value, false)
            .await?;
        Ok(value)
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
    /// Native publication borrows the same source/version/dependency approval locks.
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
        let admission =
            storage::admission(tx, version.resource().as_str(), version.label().as_str())
                .await?
                .ok_or(Error::NotAdmitted)?;
        if current.digest() != version.digest()
            || admission.digest != version.digest().bytes()
            || !matches!(admission.state, AdmissionState::Approved)
        {
            return Err(Error::NotAdmitted);
        }
        self.check_sources(tx, version).await?;
        self.dependencies(tx, version).await
    }
    /// Hold current source admission stable through the caller's final transaction.
    pub async fn source_admitted_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &r::SoftwareSource,
    ) -> Result<()> {
        self.tenant(tx)?;
        storage::lock(tx).await?;
        let (stored, admission) = storage::source(tx, &source.id, &source.revision)
            .await?
            .ok_or(Error::NotAdmitted)?;
        if !matches!(admission.state, AdmissionState::Approved) || stored.snapshot()? != *source {
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
            if let Some(previous) = materials.get(&key) {
                if previous.digest().bytes() != dependency.sha256 {
                    return Err(Error::NotAdmitted);
                }
            }
            if done.contains(&key) {
                continue;
            }
            if active.len() + done.len() >= 256 {
                return Err(Error::Input);
            }
            let version = self
                .version_in(tx, &dependency.resource, &dependency.version)
                .await?;
            let admission = storage::admission(tx, &dependency.resource, &dependency.version)
                .await?
                .ok_or(Error::NotAdmitted)?;
            if version.digest().bytes() != dependency.sha256
                || admission.digest != dependency.sha256
                || !matches!(admission.state, AdmissionState::Approved)
            {
                return Err(Error::NotAdmitted);
            }
            self.check_sources(tx, &version).await?;
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
        let admission = storage::admission(tx, resource, label).await?;
        Ok(
            json!({"resource":resource,"version":label,"resourceDigest":version.digest().bytes(),"admission":admission}),
        )
    }
    /// An existing plan must match its original approval, never silently adopt a newer approval.
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
        if current.admission.operation != expected.admission.operation
            || current.version.digest() != expected.version.digest()
        {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }
    /// Recheck current admission and exact variant under the caller's execution transaction.
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
        storage::lock(tx).await?;
        let version = self.version_in(tx, resource, label).await?;
        let admission = storage::admission(tx, resource, label)
            .await?
            .ok_or(Error::NotAdmitted)?;
        if !matches!(admission.state, AdmissionState::Approved)
            || admission.digest != version.digest().bytes()
        {
            return Err(Error::NotAdmitted);
        }
        self.check_sources(tx, &version).await?;
        self.dependencies(tx, &version).await?;
        let selected = version
            .resolve(platform, architecture, variant)
            .map_err(|_| Error::Missing)?;
        let r::Declaration::Software { definition } = selected.declaration() else {
            return Err(Error::Input);
        };
        let (source, _) = storage::source(
            tx,
            &definition.spec().source.id,
            &definition.spec().source.revision,
        )
        .await?
        .ok_or(Error::NotAdmitted)?;
        Ok(FrozenSoftware {
            source,
            version,
            variant: variant.clone(),
            platform,
            architecture,
            admission,
        })
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

fn fingerprint(v: &impl serde::Serialize) -> Result<Vec<u8>> {
    Ok(Sha256::digest(serde_json::to_vec(v).map_err(|_| Error::Input)?).to_vec())
}
fn check_operation(id: uuid::Uuid, revision: u64) -> Result<()> {
    if id.is_nil() || revision >= i64::MAX as u64 {
        Err(Error::Input)
    } else {
        Ok(())
    }
}

pub const CATALOG_SQL: &str = include_str!("catalog.sql");
pub const CATALOG_JSON: &str = include_str!("catalog.json");
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
    let count:i64=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT count(*) FROM mdm_software.approvals WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3").bind(tenant).bind(resource).bind(version).fetch_one(c).await})).await?;
    u64::try_from(count).map_err(|_| Error::Integrity)
}

/// Recheck native execution's exact release and source approval on its existing transaction.
/// No caller session is retained, and the connection cannot commit through this function.
pub async fn admitted_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: &str,
    version: &str,
    digest: [u8; 32],
    operation: uuid::Uuid,
    sources: &[r::SoftwareSource],
) -> Result<bool> {
    use sqlx::Row;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mdm-software:{tenant}"))
        .execute(&mut *c)
        .await?;
    if !rss_mdm_resource_postgres::active_version_on(
        c,
        tenant,
        &r::Id::new(resource).map_err(|_| Error::Input)?,
        &r::Id::new(version).map_err(|_| Error::Input)?,
        digest,
    )
    .await?
    {
        return Ok(false);
    }
    let raw:Option<String>=sqlx::query_scalar("SELECT admission::text FROM mdm_software.approvals WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3").bind(tenant.to_string()).bind(resource).bind(version).fetch_optional(&mut *c).await?;
    let Some(raw) = raw else {
        return Ok(false);
    };
    let approval: Admission = serde_json::from_str(&raw).map_err(|_| Error::Integrity)?;
    if !matches!(approval.state, AdmissionState::Approved)
        || approval.operation != operation
        || approval.digest != digest
    {
        return Ok(false);
    }
    for expected in sources {
        let row=sqlx::query("SELECT definition::text,admission::text FROM mdm_software.sources WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3").bind(tenant.to_string()).bind(&expected.id).bind(&expected.revision).fetch_optional(&mut *c).await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let source: SourceDefinition =
            serde_json::from_str(row.try_get("definition")?).map_err(|_| Error::Integrity)?;
        let raw: Option<String> = row.try_get("admission")?;
        let Some(raw) = raw else {
            return Ok(false);
        };
        let approval: Admission = serde_json::from_str(&raw).map_err(|_| Error::Integrity)?;
        if source.snapshot()?.sha256 != expected.sha256
            || !matches!(approval.state, AdmissionState::Approved)
            || approval.digest != expected.sha256
        {
            return Ok(false);
        }
    }
    Ok(true)
}
