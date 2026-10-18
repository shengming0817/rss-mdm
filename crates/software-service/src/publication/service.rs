use super::{
    config::{Driver, Sources},
    spec::{self, PreparedContent},
    storage::{self as db, Subject, Target},
    *,
};
use rss_contract::Timepoint;
use rss_mdm_brew_source as brew;
use rss_mdm_resource as resource;
use rss_mdm_resource_postgres::ResourceStore;
use rss_mdm_software_release as rel;
use rss_mdm_software_release_postgres::ReleaseStore;
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[derive(Clone)]
pub struct PublishInput {
    pub actor: rel::ActorId,
    pub record: rel::PublicationKey,
    pub request: rel::RequestId,
    pub resource: resource::Id,
    pub version: resource::Id,
    pub expected_resource_revision: u64,
    pub resource_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub as_of: Timepoint,
}
#[derive(Clone)]
pub struct ServiceRequest {
    pub actor: rel::ActorId,
    pub id: rel::RequestId,
    pub expected_revision: u64,
    pub as_of: Timepoint,
}
impl ServiceRequest {
    pub(super) fn core(&self, actor: &rel::ActorId, operation: rel::Operation) -> rel::Request {
        rel::Request {
            id: self.id.clone(),
            actor: actor.clone(),
            expected_revision: self.expected_revision,
            as_of: self.as_of,
            operation,
        }
    }
}
pub struct PublicationService {
    pub(super) runtime: Arc<PgRuntime>,
    pub(super) audit_store: Arc<dyn crate::AuditPort>,
    pub(super) resources: ResourceStore,
    pub(super) catalog: crate::catalog::Catalog,
    pub(super) releases: ReleaseStore,
    pub(super) sources: Sources,
    pub(super) content: Arc<dyn crate::catalog::ContentPort>,
    pub(super) actors: ServiceIdentity,
}
impl PublicationService {
    pub fn exports(&self) -> super::ExportReader {
        super::ExportReader::new(self.sources.exports())
    }

    pub async fn connect(
        host: crate::Host,
        tenant: TenantId,
        logical_source: String,
        config: SourceConfig,
        actors: ServiceIdentity,
        cutoff: Deadline,
    ) -> Result<Self> {
        let crate::Host {
            runtime,
            audit: audit_store,
            credentials,
            content,
        } = host;
        actors.check(tenant)?;
        let sources = tokio::time::timeout_at(
            cutoff.instant().into(),
            Sources::new(tenant, logical_source, config, credentials.as_ref()),
        )
        .await
        .map_err(|cause| Error::Source.context("service::connect", cause))??;
        let resources = ResourceStore::new(runtime.clone(), tenant, budget(cutoff)).await?;
        let releases = ReleaseStore::new(runtime.clone(), tenant, budget(cutoff)).await?;
        let head = if let Driver::Brew { repo, .. } = &sources.binding.driver {
            tokio::time::timeout_at(cutoff.instant().into(), repo.head())
                .await
                .map_err(|_| Error::Source)?
                .map_err(|_| Error::Source)?
                .map(|c| c.as_str().to_owned())
        } else {
            None
        };
        settle(
            runtime
                .local_tx_with_context(
                    tenant,
                    budget(cutoff),
                    (&audit_store, &sources, &head, &actors.backend),
                    |(audit, s, h, a), tx| {
                        Box::pin(async move {
                            audit
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            db::register(audit.as_ref(), tx, s, h, a).await
                        })
                    },
                )
                .await,
        )?;
        Ok(Self {
            catalog: crate::catalog::Catalog::new(runtime.clone(), tenant, audit_store.clone()),
            runtime,
            audit_store,
            resources,
            releases,
            sources,
            content,
            actors,
        })
    }
    pub fn target(&self) -> serde_json::Value {
        serde_json::json!({"id":self.sources.logical,"digest":self.sources.digest,"protocol":match self.sources.binding.driver {Driver::Winget{..}=>"winget",Driver::Brew{..}=>"brew"}})
    }
    pub fn tenant(&self) -> TenantId {
        self.sources.tenant
    }
    pub async fn record(
        &self,
        id: &rel::PublicationKey,
        cutoff: Deadline,
    ) -> Result<Option<rel::Publication>> {
        Ok(self.releases.get(id, budget(cutoff)).await?)
    }
    /// Public, credential-free document retained with the immutable record.
    /// The product caller authorizes disclosure before invoking this reader.
    pub async fn document(
        &self,
        id: &rel::PublicationKey,
        cutoff: Deadline,
    ) -> Result<ExportDocument> {
        let (_, subject, _) = self.context(id, cutoff).await?;
        Ok(subject.document)
    }
    /// Validate and persist the complete publication and first source intent atomically.
    pub async fn submit(
        &self,
        i: &PublishInput,
        access: &dyn PublishAccess,
        cutoff: Deadline,
    ) -> Result<(rss_mdm_software_release_postgres::OperationReceipt, bool)> {
        if i.actor.tenant() != self.tenant()
            || i.record.tenant() != self.tenant()
            || i.request.tenant() != self.tenant()
        {
            return Err(Error::Identity);
        }
        if i.target_digest != self.sources.digest {
            return Err(Error::Conflict);
        }
        // Read the original accepted record before any mutable source/Resource preflight.
        if let Some(c) = self.record(&i.record, cutoff).await? {
            return settle(
                self.runtime
                    .local_tx_with_context(
                        self.tenant(),
                        budget(cutoff),
                        (self, i, &c, access),
                        |(s, i, c, access), tx| {
                            Box::pin(async move {
                                input!(access.check(tx).await);
                                let subject = db::subject(tx, i.record.value())
                                    .await?
                                    .ok_or_else(db::fault)?;
                                let b = &c.snapshot().attempt.binding;
                                if subject.resource != i.resource.as_str()
                                    || subject.version != i.version.as_str()
                                    || subject.resource_digest != i.resource_digest
                                    || subject.expected_resource_revision
                                        != i.expected_resource_revision
                                    || b.actor != i.actor
                                    || b.at != i.as_of
                                    || b.target_digest.bytes() != i.target_digest
                                {
                                    return Ok(Err(Error::Conflict));
                                }
                                let receipt = input!(
                                    s.releases
                                        .operation_in(tx, &i.request)
                                        .await?
                                        .map_err(|_| Error::Conflict)
                                )
                                .ok_or_else(db::fault)?;
                                if receipt.publication != i.record {
                                    return Ok(Err(Error::Conflict));
                                }
                                Ok(Ok((receipt, true)))
                            })
                        },
                    )
                    .await,
            );
        }
        let resource = self
            .resources
            .get(&i.resource, budget(cutoff))
            .await?
            .ok_or(Error::Content)?;
        if resource.storage_revision != i.expected_resource_revision {
            return Err(Error::Conflict);
        }
        let version = self
            .resources
            .version(&i.resource, &i.version, budget(cutoff))
            .await?
            .ok_or(Error::Content)?;
        if version.digest().bytes() != i.resource_digest {
            return Err(Error::Content);
        }
        let dependencies = self.export_dependencies(&version, cutoff).await?;
        let prepared = spec::prepare(&self.sources.exports(), &version, &dependencies)?;
        let pins = self.verify(&prepared, cutoff).await?;
        let lifecycle = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, &version, access),
                    |(s, v, access), tx| {
                        Box::pin(async move {
                            input!(access.check(tx).await);
                            Ok(s.catalog
                                .reader()
                                .publication_binding_in(tx, v, true)
                                .await
                                .map_err(|_| Error::Content))
                        })
                    },
                )
                .await,
        )?;
        let binding = rel::PublicationBinding {
            publication: i.record.clone(),
            content: prepared.content.digest(),
            target: rel::TargetId::new(self.tenant(), &self.sources.logical)
                .map_err(|_| Error::Input)?,
            target_digest: rel::Digest::from_bytes(self.sources.digest),
            lifecycle: rel::Digest::from_bytes(lifecycle),
            evidence: rel::Evidence {
                actor: i.actor.clone(),
                digest: prepared.content.digest(),
                at: i.as_of,
            },
            actor: i.actor.clone(),
            at: i.as_of,
        };
        let c =
            rel::Publication::new(prepared.content.clone(), binding).map_err(|_| Error::Content)?;
        let subject = Subject {
            target: self.sources.logical.clone(),
            format: 1,
            resource: i.resource.as_str().into(),
            version: i.version.as_str().into(),
            resource_digest: i.resource_digest,
            expected_resource_revision: i.expected_resource_revision,
            coordinate: prepared.coordinate,
            document: prepared.document,
        };
        let target = tokio::time::timeout_at(
            cutoff.instant().into(),
            self.prepare_target(&subject, &c.snapshot().attempt, cutoff),
        )
        .await
        .map_err(|_| Error::Source)??;
        let rejection = std::sync::Mutex::new(None);
        let result = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (
                        self, i, &c, &subject, &version, &pins, &target, access, &rejection,
                    ),
                    |(s, i, c, subject, version, pins, target, access, rejection), tx| {
                        Box::pin(async move {
                            let result: InTransaction<_> = async {
                                s.audit_store
                                    .lock_in(tx)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                                tx.prepare_outbox_partitions(&[
                                    s.releases.partition(i.record.value())?,
                                    input!(
                                        s.catalog
                                            .publication_partition(version)
                                            .map_err(|_| Error::Content)
                                    ),
                                ])
                                .await?;
                                let allow = input!(access.check(tx).await);
                                input!(
                                    s.catalog
                                        .reader()
                                        .lock_in(tx)
                                        .await
                                        .map_err(|_| Error::Content)
                                );
                                if let Some(old) = db::subject(tx, i.record.value()).await? {
                                    if db::encode(&old)? != db::encode(subject)? {
                                        return Ok(Err(Error::Conflict));
                                    }
                                    let receipt = input!(
                                        s.releases
                                            .create_in(tx, &i.request, c)
                                            .await?
                                            .map_err(|_| Error::Conflict)
                                    );
                                    return Ok(Ok((receipt, true)));
                                }
                                let (v, state, revision) = input!(
                                    s.resources
                                        .lock_version_in(tx, &i.resource, &i.version)
                                        .await?
                                        .map_err(|_| Error::Content)
                                );
                                if v.digest().bytes() != i.resource_digest
                                    || revision != i.expected_resource_revision
                                    || state == resource::State::Archived
                                {
                                    return Ok(Err(Error::Conflict));
                                }
                                let key = db::software_key(&c.snapshot().content)?;
                                db::lock(tx, "authority", &hex(&key)).await?;
                                let material = Sha256::digest(db::encode(&serde_json::json!([
                                    v.digest().bytes(),
                                    c.snapshot().content.manifest().bytes()
                                ]))?)
                                .to_vec();
                                if let Some((owner, old)) = db::authority(tx, &key).await? {
                                    if old != material {
                                        return Ok(Err(Error::Content));
                                    }
                                    input!(s.retired_owner(tx, &owner).await?);
                                }
                                db::lock(
                                    tx,
                                    "source",
                                    &format!("{}:{}", hex(&target.binding), target.slot),
                                )
                                .await?;
                                let slot = db::slot(tx, &target.binding, &target.slot).await?;
                                if slot.operation.is_some() || slot.cursor != target.base {
                                    return Ok(Err(Error::Blocked));
                                }
                                let current = input!(
                                    s.catalog
                                        .reader()
                                        .publication_binding_in(tx, version, allow)
                                        .await
                                        .map_err(|_| Error::Identity)
                                );
                                if current != target.lifecycle {
                                    return Ok(Err(Error::Conflict));
                                }
                                let pin = input!(
                                    pins.iter()
                                        .find(|p| p.resource_digest() == version.digest().bytes())
                                        .ok_or(Error::Content)
                                );
                                let operation = input!(
                                    uuid::Uuid::parse_str(i.request.value())
                                        .map_err(|_| Error::Input)
                                );
                                input!(
                                    s.catalog
                                        .enable_for_publication_in(
                                            tx,
                                            version,
                                            pin.as_ref(),
                                            i.actor.value(),
                                            operation
                                        )
                                        .await
                                        .map_err(|_| Error::Content)
                                );
                                input!(
                                    s.exports()
                                        .resource_usable(tx, subject, target.lifecycle)
                                        .await?
                                );
                                let receipt = input!(
                                    s.releases
                                        .create_in(tx, &i.request, c)
                                        .await?
                                        .map_err(|_| Error::Conflict)
                                );
                                db::insert_subject(tx, i.record.value(), subject).await?;
                                db::set_authority(tx, key, material, i.record.value()).await?;
                                db::reserve(tx, target, &target.key()).await?;
                                db::insert_call(tx, db::Table::Publish, target).await?;
                                let fact = db::fact(
                                    tx.tenant_id(),
                                    &i.actor,
                                    i.record.value(),
                                    "software_publish",
                                    db::request_fact(i.request.value(), "publish"),
                                    &db::encode(&(
                                        i.request.value(),
                                        i.record.value(),
                                        subject,
                                        target,
                                    ))?,
                                )?;
                                s.audit_store
                                    .append_in(tx, &fact, false)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                                input!(access.check(tx).await);
                                Ok(Ok((receipt, false)))
                            }
                            .await;
                            match result {
                                Ok(Err(e)) => {
                                    *rejection.lock().expect("publication rejection") = Some(e);
                                    Err(db::fault())
                                }
                                other => other,
                            }
                        })
                    },
                )
                .await,
        );
        match result {
            Err(Error::RolledBack(e)) => Err(rejection
                .into_inner()
                .expect("publication rejection")
                .unwrap_or(Error::RolledBack(e))),
            other => other,
        }
    }
    async fn retired_owner(&self, tx: &mut PgTransaction<'_>, owner: &str) -> InTransaction<()> {
        let id = db::required(
            "publication owner",
            rel::PublicationKey::new(self.tenant(), owner),
        )?;
        let c = input!(
            self.releases
                .get_in(tx, &id)
                .await?
                .map_err(|_| Error::Conflict)
        )
        .ok_or_else(db::fault)?;
        if !c.snapshot().withdrawn {
            return Ok(Err(Error::Conflict));
        }
        let p = &c.snapshot().attempt;
        if !matches!(
            p.outcome,
            rel::PublicationOutcome::Reported(
                rel::PublicationResult::Applied(_) | rel::PublicationResult::NotApplied(_)
            )
        ) {
            return Ok(Err(Error::Blocked));
        }
        let key = format!("w:{}:{}", hex(&p.id().digest().bytes()), p.attempt);
        if !db::call(tx, db::Table::Withdraw, &key)
            .await?
            .is_some_and(|c| c.complete)
        {
            return Ok(Err(Error::Blocked));
        }
        Ok(Ok(()))
    }
    pub async fn retry(
        &self,
        id: &rel::PublicationKey,
        attempt: u64,
        request: &ServiceRequest,
        access: &dyn PublishAccess,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        if let Some(replay) = self
            .replay_service(id, request, Some(attempt), access, cutoff)
            .await?
        {
            return Ok(replay);
        }
        let (c, subject, prepared) = self.context(id, cutoff).await?;
        let _pins = if self
            .releases
            .operation(&request.id, budget(cutoff))
            .await?
            .is_none()
        {
            self.verify(&prepared, cutoff).await?
        } else {
            Vec::new()
        };
        let p = &c.snapshot().attempt;
        let r = request.core(
            &request.actor,
            rel::Operation::Retry {
                publication: p.id(),
                attempt,
            },
        );
        self.commit_publication(&c, &subject, &r, access, cutoff)
            .await
    }
    async fn commit_publication(
        &self,
        c: &rel::Publication,
        subject: &Subject,
        r: &rel::Request,
        access: &dyn PublishAccess,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        let old = self.releases.operation(&r.id, budget(cutoff)).await?;
        let preview = c
            .transition(r.clone(), old.as_ref().and_then(|r| r.transition.as_ref()))
            .map_err(|cause| Error::Conflict.context("service::publish_request", cause))?;
        let rel::Transition::Applied {
            decision: rel::Decision::Publish(p),
            ..
        } = &preview
        else {
            return self
                .transition_audited(c, subject, r, "software_publish", access, cutoff)
                .await;
        };
        let target = tokio::time::timeout_at(
            cutoff.instant().into(),
            self.prepare_target(subject, p, cutoff),
        )
        .await
        .map_err(|cause| Error::Source.context("service::publish_request", cause))??;
        let rejection = std::sync::Mutex::new(None);
        let result = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, c, subject, r, &target, access, &rejection),
                    |(s, c, subject, r, target, access, rejection), tx| {
                        Box::pin(async move {
                            let outcome: InTransaction<_> = async {
                                s.audit_store
                                    .lock_in(tx)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                                tx.prepare_outbox_partitions(&[s
                                    .releases
                                    .partition(c.snapshot().id.value())?])
                                    .await?;
                                input!(access.check(tx).await);
                                input!(
                                    s.catalog
                                        .reader()
                                        .lock_in(tx)
                                        .await
                                        .map_err(|_| Error::Content)
                                );
                                if db::required(
                                    "publish replay",
                                    s.releases.operation_in(tx, &r.id).await?,
                                )?
                                .is_some()
                                {
                                    let result = db::required(
                                        "publish replay",
                                        s.releases.transition_in(tx, &c.snapshot().id, r).await?,
                                    )?;
                                    let fact = db::fact(
                                        tx.tenant_id(),
                                        &r.actor,
                                        &target.record,
                                        "software_publish",
                                        db::transition_fact(r, "software_publish"),
                                        &db::request_fingerprint(&target.record, r)?,
                                    )?;
                                    s.audit_store.append_in(tx, &fact, true).await.map_err(
                                        rss_transactional_messaging_postgres::PgError::from,
                                    )?;
                                    return Ok(Ok(result));
                                }
                                db::lock(
                                    tx,
                                    "source",
                                    &format!("{}:{}", hex(&target.binding), target.slot),
                                )
                                .await?;
                                let slot = db::slot(tx, &target.binding, &target.slot).await?;
                                if slot.operation.is_some() || slot.cursor != target.base {
                                    return Ok(Err(Error::Blocked));
                                }
                                let current = input!(
                                    s.releases
                                        .lock_publication_in(tx, &c.snapshot().id)
                                        .await?
                                        .map_err(|cause| Error::Conflict
                                            .context("service::publish_request", cause))
                                );
                                let previous = &current.snapshot().attempt;
                                if db::call(
                                    tx,
                                    db::Table::Withdraw,
                                    &format!(
                                        "w:{}:{}",
                                        hex(&previous.id().digest().bytes()),
                                        previous.attempt
                                    ),
                                )
                                .await?
                                .is_some()
                                {
                                    return Ok(Err(Error::Blocked));
                                }
                                input!(current.transition((*r).clone(), None).map_err(|cause| {
                                    Error::Conflict.context("service::publish_request", cause)
                                }));
                                let key = db::software_key(&c.snapshot().content)?;
                                if db::authority(tx, &key)
                                    .await?
                                    .is_none_or(|(owner, _)| owner != target.record)
                                {
                                    return Ok(Err(Error::Conflict));
                                }
                                input!(
                                    s.exports()
                                        .resource_usable(tx, subject, target.lifecycle)
                                        .await?
                                );
                                let result = db::required(
                                    "service::publish_request",
                                    s.releases.transition_in(tx, &c.snapshot().id, r).await?,
                                )?;
                                db::reserve(tx, target, &target.key()).await?;
                                db::insert_call(tx, db::Table::Publish, target).await?;
                                let fact = db::fact(
                                    tx.tenant_id(),
                                    &r.actor,
                                    &target.record,
                                    "software_publish",
                                    db::transition_fact(r, "software_publish"),
                                    &db::request_fingerprint(&target.record, r)?,
                                )?;
                                s.audit_store
                                    .append_in(
                                        tx,
                                        &fact,
                                        matches!(result, rel::Transition::Replayed(_)),
                                    )
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                                Ok(Ok(result))
                            }
                            .await;
                            match outcome {
                                Ok(Err(error)) => {
                                    *rejection.lock().expect("publication rejection") = Some(error);
                                    Err(db::fault())
                                }
                                other => other,
                            }
                        })
                    },
                )
                .await,
        );
        match result {
            Err(Error::RolledBack(cause)) => Err(rejection
                .into_inner()
                .expect("publication rejection")
                .unwrap_or(Error::RolledBack(cause))),
            other => other,
        }
    }
    async fn prepare_target(
        &self,
        subject: &Subject,
        p: &rel::Attempt,
        cutoff: Deadline,
    ) -> Result<Target> {
        let binding = self.sources.binding();
        let slot = match &binding.driver {
            Driver::Winget { .. } => subject.coordinate.clone(),
            Driver::Brew { .. } => "tap".into(),
        };
        let state = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (&binding.identity, &slot),
                    |(b, s), tx| Box::pin(async move { Ok(Ok(db::slot(tx, b, s).await?)) }),
                )
                .await,
        )?;
        if state.operation.is_some() {
            return Err(Error::Blocked);
        }
        let mut target = Target {
            lifecycle: p.binding.lifecycle.bytes(),
            format: 1,
            record: p.binding.publication.value().into(),
            publication: p.id().digest().bytes(),
            attempt: p.attempt,
            binding: binding.identity.clone(),
            coordinate: subject.coordinate.clone(),
            slot,
            base: state.cursor,
            commit: None,
            snapshot: None,
            at: p.requested_at.unix_seconds(),
            commit_at: p.requested_at.unix_seconds(),
        };
        if let Driver::Brew { repo, tap, .. } = &binding.driver {
            let ExportDocument::Brew { recipe } = &subject.document else {
                return Err(Error::Content);
            };
            if repo
                .head()
                .await
                .map_err(|cause| Error::Source.context("service::prepare_target", cause))?
                .as_ref()
                .map(|c| c.as_str())
                != target.base.as_deref()
            {
                return Err(Error::Blocked);
            }
            let base = target
                .base
                .as_deref()
                .map(brew::CommitId::parse)
                .transpose()
                .map_err(|cause| Error::Content.context("service::prepare_target", cause))?;
            let prepared = repo
                .prepare_snapshot(
                    base,
                    recipe.documents(self.tenant(), tap)?,
                    &operation(&target),
                    p.requested_at,
                )
                .await
                .map_err(|cause| Error::Source.context("service::prepare_target", cause))?;
            target.commit = Some(prepared.target().as_str().into());
            target.snapshot = target.commit.clone();
        }
        Ok(target)
    }
    async fn replay_service(
        &self,
        id: &rel::PublicationKey,
        r: &ServiceRequest,
        attempt: Option<u64>,
        access: &dyn PublishAccess,
        cutoff: Deadline,
    ) -> Result<Option<rel::Transition>> {
        if self
            .releases
            .operation(&r.id, budget(cutoff))
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let (owner, original) = self
            .releases
            .original_request(&r.id, budget(cutoff))
            .await?
            .ok_or(Error::Conflict)?;
        match &original.operation {
            rel::Operation::Retry { .. } if attempt.is_some() => (),
            _ => return Err(Error::Conflict),
        }
        if owner != *id
            || original.id != r.id
            || original.actor != r.actor
            || original.expected_revision != r.expected_revision
            || original.as_of != r.as_of
        {
            return Err(Error::Conflict);
        }
        let action = "software_publish";
        let result = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, id, &original, access),
                    move |(s, id, r, access), tx| {
                        Box::pin(async move {
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(access.check(tx).await);
                            input!(
                                s.catalog
                                    .reader()
                                    .lock_in(tx)
                                    .await
                                    .map_err(|_| Error::Content)
                            );
                            tx.prepare_outbox_partitions(&[s.releases.partition(id.value())?])
                                .await?;
                            let transition = input!(
                                s.releases
                                    .transition_in(tx, id, r)
                                    .await?
                                    .map_err(|_| Error::Conflict)
                            );
                            let fact = db::fact(
                                tx.tenant_id(),
                                &r.actor,
                                id.value(),
                                action,
                                db::transition_fact(r, action),
                                &db::request_fingerprint(id.value(), r)?,
                            )?;
                            s.audit_store
                                .append_in(tx, &fact, true)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            Ok(Ok(transition))
                        })
                    },
                )
                .await,
        )?;
        Ok(Some(result))
    }
    pub(super) async fn context(
        &self,
        id: &rel::PublicationKey,
        cutoff: Deadline,
    ) -> Result<(rel::Publication, Subject, PreparedContent)> {
        if id.tenant() != self.tenant() {
            return Err(Error::Identity);
        }
        let (c, subject, version) = settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, id), |(s, id), tx| {
                    Box::pin(async move {
                        s.audit_store
                            .lock_in(tx)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        input!(
                            s.catalog
                                .reader()
                                .lock_in(tx)
                                .await
                                .map_err(|_| Error::Content)
                        );
                        let Some(c) = input!(s.releases.get_in(tx, id).await?.map_err(|cause| {
                            Error::Conflict.context("service::context", cause)
                        })) else {
                            return Ok(Err(Error::PublicationNotFound));
                        };
                        let subject = db::subject(tx, id.value()).await?.ok_or_else(db::fault)?;
                        let resource =
                            db::required("service::context", resource::Id::new(&subject.resource))?;
                        let version =
                            db::required("service::context", resource::Id::new(&subject.version))?;
                        let (v, _, _) = input!(
                            s.resources
                                .lock_version_in(tx, &resource, &version)
                                .await?
                                .map_err(|cause| Error::Content.context("service::context", cause))
                        );
                        if v.digest().bytes() != subject.resource_digest {
                            return Err(db::fault());
                        }
                        Ok(Ok((c, subject, v)))
                    })
                })
                .await,
        )?;
        let dependencies = self.export_dependencies(&version, cutoff).await?;
        let prepared = spec::prepare(&self.sources.exports(), &version, &dependencies)?;
        if serde_json::to_vec(&prepared.document).map_err(|_| Error::Content)?
            != serde_json::to_vec(&subject.document).map_err(|_| Error::Content)?
        {
            return Err(Error::Content);
        }
        if prepared.content != c.snapshot().content || prepared.coordinate != subject.coordinate {
            return Err(Error::Content);
        }
        Ok((c, subject, prepared))
    }
    pub(super) async fn export_dependencies(
        &self,
        root: &resource::Version,
        cutoff: Deadline,
    ) -> Result<Vec<resource::Version>> {
        let mut pending = vec![root.clone()];
        let mut seen = std::collections::BTreeMap::new();
        while let Some(version) = pending.pop() {
            for variant in version.variants() {
                let resource::Declaration::Software { definition } = variant.declaration() else {
                    return Err(Error::Content);
                };
                for dependency in &definition.spec().dependencies {
                    let key = (dependency.resource.clone(), dependency.version.clone());
                    if seen.get(&key).is_some_and(|v: &resource::Version| {
                        v.digest().bytes() != dependency.sha256
                    }) {
                        return Err(Error::Content);
                    }
                    if seen.contains_key(&key) {
                        continue;
                    }
                    if seen.len() >= 256 {
                        return Err(Error::Content);
                    }
                    let child = self
                        .resources
                        .version(
                            &resource::Id::new(&dependency.resource).map_err(|_| Error::Content)?,
                            &resource::Id::new(&dependency.version).map_err(|_| Error::Content)?,
                            budget(cutoff),
                        )
                        .await?
                        .ok_or(Error::Content)?;
                    if child.digest().bytes() != dependency.sha256 {
                        return Err(Error::Content);
                    }
                    seen.insert(key, child.clone());
                    pending.push(child);
                }
            }
        }
        Ok(seen.into_values().collect())
    }
    pub(super) async fn verify(
        &self,
        p: &PreparedContent,
        cutoff: Deadline,
    ) -> Result<Vec<Box<dyn crate::catalog::VerifiedContent>>> {
        tokio::time::timeout_at(cutoff.instant().into(), async {
            let mut pins = Vec::new();
            for resource in &p.resources {
                pins.push(
                    self.content
                        .verify(resource)
                        .await
                        .map_err(|_| Error::Content)?,
                );
            }
            Ok(pins)
        })
        .await
        .map_err(|cause| Error::ArtifactTimeout.context("service::verify", cause))?
    }

    pub(super) async fn transition_audited(
        &self,
        c: &rel::Publication,
        subject: &Subject,
        r: &rel::Request,
        action: &'static str,
        access: &dyn PublishAccess,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, c, subject, r, access),
                    move |(s, c, subject, r, access), tx| {
                        Box::pin(async move {
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(access.check(tx).await);
                            input!(
                                s.catalog
                                    .reader()
                                    .lock_in(tx)
                                    .await
                                    .map_err(|_| Error::Content)
                            );
                            tx.prepare_outbox_partitions(&[s
                                .releases
                                .partition(c.snapshot().id.value())?])
                                .await?;
                            let replay = db::required(
                                "service::transition_audited",
                                s.releases.operation_in(tx, &r.id).await?,
                            )?
                            .is_some();
                            if !replay {
                                let lifecycle = c.snapshot().attempt.binding.lifecycle.bytes();
                                input!(s.exports().resource_usable(tx, subject, lifecycle).await?);
                            }
                            let result = input!(
                                s.releases
                                    .transition_in(tx, &c.snapshot().id, r)
                                    .await?
                                    .map_err(|cause| Error::Conflict
                                        .context("service::transition_audited", cause))
                            );
                            let fact = db::fact(
                                tx.tenant_id(),
                                &r.actor,
                                c.snapshot().id.value(),
                                action,
                                db::transition_fact(r, action),
                                &db::request_fingerprint(c.snapshot().id.value(), r)?,
                            )?;
                            s.audit_store
                                .append_in(
                                    tx,
                                    &fact,
                                    matches!(result, rel::Transition::Replayed(_)),
                                )
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            Ok(Ok(result))
                        })
                    },
                )
                .await,
        )
    }
}
pub(super) fn operation(t: &Target) -> String {
    format!("p-{}-a-{}", hex(&t.publication), t.attempt)
}
