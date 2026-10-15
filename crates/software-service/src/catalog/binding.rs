//! Current lifecycle fingerprint for an exact immutable dependency closure.
//! Resource owns bytes; Software owns availability and generations.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

impl Reader {
    pub async fn binding_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: &r::Version,
    ) -> Result<[u8; 32]> {
        self.tenant(tx)?;
        let tenant = self.tenant;
        let resource = version.resource().as_str().to_owned();
        let label = version.label().as_str().to_owned();
        let digest = version.digest().bytes();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(binding_on(c, tenant, &resource, &label, digest).await) })
        })
        .await??
        .ok_or(Error::NotAdmitted)
    }
}

/// Borrow the caller's tenant transaction; never commit, refresh a frozen binding, or grant access.
async fn resolve_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: &str,
    version: &str,
    digest: [u8; 32],
    allow_draft: bool,
) -> Result<Option<[u8; 32]>> {
    use sqlx::Row;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mdm-software:{tenant}"))
        .execute(&mut *c)
        .await?;
    let (root_resource, root_version) = (resource.to_owned(), version.to_owned());
    let mut stack = vec![(resource.to_owned(), version.to_owned(), digest, false)];
    let mut active = BTreeSet::new();
    let mut versions = BTreeMap::new();
    let mut sources = BTreeMap::new();
    while let Some((resource, label, digest, exit)) = stack.pop() {
        let key = (resource.clone(), label.clone());
        if exit {
            active.remove(&key);
            continue;
        }
        if active.contains(&key) {
            return Err(Error::Input);
        }
        if let Some((old, _)) = versions.get(&key) {
            if old != &digest {
                return Err(Error::Conflict);
            }
            continue;
        }
        if versions.len() >= 256 {
            return Err(Error::Input);
        }
        let Some(value) = rss_mdm_resource_postgres::software_version_on(
            c,
            tenant,
            &r::Id::new(&resource).map_err(|_| Error::Input)?,
            &r::Id::new(&label).map_err(|_| Error::Input)?,
            digest,
        )
        .await?
        else {
            return Ok(None);
        };
        let raw: Option<String> = sqlx::query_scalar("SELECT lifecycle::text FROM mdm_software.versions WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3")
            .bind(tenant.to_string()).bind(&resource).bind(&label).fetch_optional(&mut *c).await?;
        let lifecycle: Lifecycle = match raw {
            Some(raw) => storage::decode(&raw)?,
            None if allow_draft && resource == root_resource && label == root_version => {
                Lifecycle {
                    revision: 1,
                    state: LifecycleState::Enabled,
                    operation: uuid::Uuid::nil(),
                    actor: String::new(),
                    at: 0,
                    digest,
                }
            }
            None => return Ok(None),
        };
        if !matches!(lifecycle.state, LifecycleState::Enabled) || lifecycle.digest != digest {
            return Ok(None);
        }
        versions.insert(key.clone(), (digest, lifecycle.revision));
        for variant in value.variants() {
            let r::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Integrity);
            };
            let expected = &definition.spec().source;
            let row = sqlx::query("SELECT definition::text,lifecycle::text FROM mdm_software.sources WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3")
                .bind(tenant.to_string()).bind(&expected.id).bind(&expected.revision).fetch_optional(&mut *c).await?;
            let Some(row) = row else {
                return Ok(None);
            };
            let source: SourceDefinition = storage::decode(row.try_get("definition")?)?;
            let lifecycle: Lifecycle = storage::decode(row.try_get("lifecycle")?)?;
            if source.snapshot()? != *expected
                || lifecycle.digest != expected.sha256
                || !matches!(lifecycle.state, LifecycleState::Enabled)
            {
                return Ok(None);
            }
            sources.insert(
                (expected.id.clone(), expected.revision.clone()),
                (expected.sha256, lifecycle.revision),
            );
        }
        active.insert(key);
        stack.push((resource, label, digest, true));
        for dependency in dependency_refs(&value)? {
            stack.push((
                dependency.resource,
                dependency.version,
                dependency.sha256,
                false,
            ));
        }
    }
    // Ordered sequences (rather than JSON object keys) make the canonical input unambiguous.
    let bytes = serde_json::to_vec(&(
        "software-lifecycle/v1",
        tenant.to_string(),
        versions.into_iter().collect::<Vec<_>>(),
        sources.into_iter().collect::<Vec<_>>(),
    ))
    .map_err(|_| Error::Integrity)?;
    Ok(Some(Sha256::digest(bytes).into()))
}

pub async fn admitted_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: &str,
    version: &str,
    digest: [u8; 32],
    expected: [u8; 32],
) -> Result<bool> {
    Ok(binding_on(c, tenant, resource, version, digest).await? == Some(expected))
}

pub async fn binding_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: &str,
    version: &str,
    digest: [u8; 32],
) -> Result<Option<[u8; 32]>> {
    resolve_on(c, tenant, resource, version, digest, false).await
}
impl Reader {
    pub async fn publication_binding_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: &r::Version,
        allow_draft: bool,
    ) -> Result<[u8; 32]> {
        self.tenant(tx)?;
        let tenant = self.tenant;
        let resource = version.resource().as_str().to_owned();
        let label = version.label().as_str().to_owned();
        let digest = version.digest().bytes();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(resolve_on(c, tenant, &resource, &label, digest, allow_draft).await)
            })
        })
        .await??
        .ok_or(Error::NotAdmitted)
    }
}
impl Catalog {
    pub fn publication_partition(
        &self,
        version: &r::Version,
    ) -> Result<rss_transactional_messaging::message::PartitionIdentity> {
        event::partition(
            self.tenant,
            &format!(
                "resource/{}/{}",
                version.resource().as_str(),
                version.label().as_str()
            ),
        )
    }
    /// Caller declares this version's publication partition with all other Outbox partitions.

    pub async fn enable_for_publication_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: &r::Version,
        content: &dyn VerifiedContent,
        actor: &str,
        operation: uuid::Uuid,
    ) -> Result<()> {
        let key = format!(
            "resource/{}/{}",
            version.resource().as_str(),
            version.label().as_str()
        );
        self.reader().lock_in(tx).await?;
        if content.resource_digest() != version.digest().bytes() {
            return Err(Error::Content);
        }
        if let Some(old) =
            storage::lifecycle(tx, version.resource().as_str(), version.label().as_str()).await?
        {
            if matches!(old.state, LifecycleState::Enabled)
                && old.digest == version.digest().bytes()
            {
                return Ok(());
            }
            return Err(Error::NotAdmitted);
        }
        self.reader().check_sources(tx, version).await?;
        self.reader().dependencies(tx, version).await?;
        storage::freeze_materials(tx, version).await?;
        let lifecycle = Lifecycle {
            revision: 1,
            state: LifecycleState::Enabled,
            operation,
            actor: actor.to_owned(),
            at: storage::now(tx).await?,
            digest: version.digest().bytes(),
        };
        storage::save_lifecycle(
            tx,
            version.resource().as_str(),
            version.label().as_str(),
            &lifecycle,
        )
        .await?;
        event::append(&self.writer,tx,&key,operation,&json!({"resource":version.resource().as_str(),"version":version.label().as_str(),"lifecycle":lifecycle})).await
    }
}
