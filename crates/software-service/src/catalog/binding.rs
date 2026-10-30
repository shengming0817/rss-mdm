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

/// Each request resolves one immutable dependency closure with the same pure evaluator.
#[derive(Clone)]
pub struct BindingRequest {
    pub resource: String,
    pub version: String,
    pub digest: [u8; 32],
    pub allow_draft: bool,
    pub selection: Option<(r::Platform, r::Architecture, String, bool)>,
}
type VersionKey = (String, String, [u8; 32]);
type SourceKey = (String, String);
#[derive(Default)]
struct Facts {
    retained_bytes: usize,
    versions: BTreeMap<VersionKey, Option<(r::Version, Option<Lifecycle>)>>,
    sources: BTreeMap<SourceKey, Option<(SourceDefinition, Lifecycle)>>,
}
enum Resolution {
    Done(Option<[u8; 32]>),
    Version(VersionKey),
    Source(SourceKey),
}
fn resolve(tenant: TenantId, request: &BindingRequest, facts: &Facts) -> Result<Resolution> {
    let (resource, version, digest, allow_draft) = (
        &request.resource[..],
        &request.version[..],
        request.digest,
        request.allow_draft,
    );
    let selection = request
        .selection
        .as_ref()
        .map(|(p, a, v, u)| (*p, *a, v.as_str(), *u));
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
        let Some(fact) = facts
            .versions
            .get(&(resource.clone(), label.clone(), digest))
        else {
            return Ok(Resolution::Version((resource, label, digest)));
        };
        let Some((value, lifecycle)) = fact else {
            return Ok(Resolution::Done(None));
        };
        let raw = lifecycle.clone();
        let lifecycle: Lifecycle = match raw {
            Some(value) => value,
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
            None => return Ok(Resolution::Done(None)),
        };
        if !matches!(lifecycle.state, LifecycleState::Enabled) || lifecycle.digest != digest {
            return Ok(Resolution::Done(None));
        }
        versions.insert(key.clone(), (digest, lifecycle.revision));
        let selected: Vec<_> = if let Some((platform, architecture, variant, _)) = selection {
            if resource == root_resource && label == root_version {
                vec![
                    value
                        .resolve(
                            platform,
                            architecture,
                            &r::Id::new(variant).map_err(|_| Error::Input)?,
                        )
                        .map_err(|_| Error::NotAdmitted)?,
                ]
            } else {
                let candidates: Vec<_> = value
                    .variants()
                    .iter()
                    .filter(|v| v.platform() == platform && v.architecture() == architecture)
                    .collect();
                if candidates.len() != 1 {
                    return Err(Error::NotAdmitted);
                }
                candidates
            }
        } else {
            value.variants().iter().collect()
        };
        let mut dependencies = Vec::new();
        for variant in selected {
            let r::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Integrity);
            };
            if !selection.is_some_and(|(_, _, _, uninstall)| {
                uninstall && resource == root_resource && label == root_version
            }) {
                dependencies.extend(definition.spec().dependencies.clone());
            }
            let expected = &definition.spec().source;
            let Some(fact) = facts
                .sources
                .get(&(expected.id.clone(), expected.revision.clone()))
            else {
                return Ok(Resolution::Source((
                    expected.id.clone(),
                    expected.revision.clone(),
                )));
            };
            let Some((source, lifecycle)) = fact else {
                return Ok(Resolution::Done(None));
            };
            if source.snapshot()? != *expected
                || lifecycle.digest != expected.sha256
                || !matches!(lifecycle.state, LifecycleState::Enabled)
            {
                return Ok(Resolution::Done(None));
            }
            sources.insert(
                (expected.id.clone(), expected.revision.clone()),
                (expected.sha256, lifecycle.revision),
            );
        }
        active.insert(key);
        stack.push((resource, label, digest, true));
        for dependency in dependencies {
            stack.push((
                dependency.resource,
                dependency.version,
                dependency.sha256,
                false,
            ));
        }
    }
    if selection.is_some() {
        return Ok(Resolution::Done(Some(digest)));
    }
    // Ordered sequences (rather than JSON object keys) make the canonical input unambiguous.
    let bytes = serde_json::to_vec(&(
        "software-lifecycle/v1",
        tenant.to_string(),
        versions.into_iter().collect::<Vec<_>>(),
        sources.into_iter().collect::<Vec<_>>(),
    ))
    .map_err(|_| Error::Integrity)?;
    Ok(Resolution::Done(Some(Sha256::digest(bytes).into())))
}

/// Read only batches of missing owner facts; no per-resource locks or per-request queries.
/// The caller must fence resource/software revision coordinates around the read.
pub async fn bindings_many_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    requests: &[BindingRequest],
) -> Result<Vec<Option<[u8; 32]>>> {
    bindings(c, tenant, requests, false).await
}
/// Mutation preflights retain the original catalog and resource lock discipline.
pub async fn bindings_many_locked_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    requests: &[BindingRequest],
) -> Result<Vec<Option<[u8; 32]>>> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind(format!("mdm-software:{tenant}"))
        .execute(&mut *c)
        .await?;
    bindings(c, tenant, requests, true).await
}
async fn bindings(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    requests: &[BindingRequest],
    lock: bool,
) -> Result<Vec<Option<[u8; 32]>>> {
    let mut facts = Facts::default();
    let mut results = vec![None; requests.len()];
    let mut pending = (0..requests.len()).collect::<Vec<_>>();
    while !pending.is_empty() {
        let mut versions = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut next = Vec::new();
        for index in pending {
            match resolve(tenant, &requests[index], &facts)? {
                Resolution::Done(value) => results[index] = value,
                Resolution::Version(key) => {
                    versions.insert(key);
                    next.push(index);
                }
                Resolution::Source(key) => {
                    sources.insert(key);
                    next.push(index);
                }
            }
        }
        let versions = versions.into_iter().collect::<Vec<_>>();
        for batch in versions.chunks(1000) {
            facts.load_versions(c, tenant, batch, lock).await?;
        }
        let sources = sources.into_iter().collect::<Vec<_>>();
        for batch in sources.chunks(1000) {
            facts.load_sources(c, tenant, batch).await?;
        }
        pending = next;
    }
    Ok(results)
}

impl Facts {
    async fn load_versions(
        &mut self,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
        batch: &[VersionKey],
        lock: bool,
    ) -> Result<()> {
        if lock {
            for resource in batch.iter().map(|v| &v.0).collect::<BTreeSet<_>>() {
                rss_mdm_resource_postgres::lock_reference_key_on(
                    c,
                    tenant,
                    &r::Id::new(resource).map_err(|_| Error::Input)?,
                )
                .await?;
            }
        }
        let loaded = rss_mdm_resource_postgres::software_versions_on(c, tenant, batch).await?;
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(loaded.payload_bytes)
            .saturating_add(batch.len() * 1024);
        if self.retained_bytes > 16 * 1024 * 1024 {
            return Err(Error::Capacity);
        }
        let values = loaded.versions;
        let ids = batch.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
        let labels = batch.iter().map(|v| v.1.clone()).collect::<Vec<_>>();
        let rows=sqlx::query_as::<_,(String,String,String)>("SELECT v.resource,v.version,v.lifecycle::text FROM mdm_software.versions v JOIN unnest($2::text[],$3::text[]) AS x(resource,version) USING(resource,version) WHERE tenant_id=$1::uuid").bind(tenant.to_string()).bind(ids).bind(labels).fetch_all(&mut *c).await?;
        let lifecycle = rows
            .into_iter()
            .map(|(r, v, l)| Ok(((r, v), storage::decode::<Lifecycle>(&l)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (key, value) in batch.iter().zip(values) {
            self.versions.insert(
                key.clone(),
                value.map(|v| (v, lifecycle.get(&(key.0.clone(), key.1.clone())).cloned())),
            );
        }
        Ok(())
    }
    async fn load_sources(
        &mut self,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
        batch: &[SourceKey],
    ) -> Result<()> {
        use sqlx::Row;

        let ids = batch.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
        let revisions = batch.iter().map(|v| v.1.clone()).collect::<Vec<_>>();
        let rows=sqlx::query("WITH selected AS MATERIALIZED(SELECT s.id,s.revision,s.definition::text,s.lifecycle::text FROM mdm_software.sources s JOIN unnest($2::text[],$3::text[]) AS x(id,revision) USING(id,revision) WHERE tenant_id=$1::uuid),budget AS(SELECT coalesce(sum(octet_length(definition)+octet_length(lifecycle)),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216").bind(tenant.to_string()).bind(ids).bind(revisions).fetch_all(&mut *c).await?;
        let bytes = rows
            .first()
            .ok_or(Error::Integrity)?
            .try_get::<i64, _>("bytes")?;
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(bytes as usize)
            .saturating_add(batch.len() * 1024);
        if self.retained_bytes > 16 * 1024 * 1024 {
            return Err(Error::Capacity);
        }
        for key in batch {
            self.sources.insert(key.clone(), None);
        }
        for row in rows {
            if row.try_get::<Option<String>, _>("id")?.is_none() {
                continue;
            }
            self.sources.insert(
                (row.try_get("id")?, row.try_get("revision")?),
                Some((
                    storage::decode(row.try_get("definition")?)?,
                    storage::decode(row.try_get("lifecycle")?)?,
                )),
            );
        }
        Ok(())
    }
}
/// Mutations retain their original catalog lock and use the same resolver as batch reads.
async fn resolve_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: &str,
    version: &str,
    digest: [u8; 32],
    allow_draft: bool,
    selection: Option<(r::Platform, r::Architecture, &str, bool)>,
) -> Result<Option<[u8; 32]>> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind(format!("mdm-software:{tenant}"))
        .execute(&mut *c)
        .await?;
    Ok(bindings(
        c,
        tenant,
        &[BindingRequest {
            resource: resource.to_owned(),
            version: version.to_owned(),
            digest,
            allow_draft,
            selection: selection.map(|(p, a, v, u)| (p, a, v.to_owned(), u)),
        }],
        true,
    )
    .await?
    .pop()
    .flatten())
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
    resolve_on(c, tenant, resource, version, digest, false, None).await
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
                Ok(resolve_on(c, tenant, &resource, &label, digest, allow_draft, None).await)
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

/// Check only the selected immutable variant closure and explicit material withdrawal.
pub async fn execution_admitted_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: &str,
    version: &str,
    digest: [u8; 32],
    selection: (r::Platform, r::Architecture, &str, bool),
) -> Result<bool> {
    Ok(
        resolve_on(c, tenant, resource, version, digest, false, Some(selection))
            .await?
            .is_some(),
    )
}
