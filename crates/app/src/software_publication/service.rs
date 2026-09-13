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
pub struct CandidateInput {
    pub candidate: rel::CandidateId,
    pub request: rel::RequestId,
    pub resource: resource::Id,
    pub version: resource::Id,
    pub expected_resource_revision: u64,
    pub submission: Submission,
    pub as_of: Timepoint,
}
#[derive(Clone)]
pub struct ServiceRequest {
    pub id: rel::RequestId,
    pub expected_revision: u64,
    pub as_of: Timepoint,
}
impl ServiceRequest {
    fn core(&self, actor: &rel::ActorId, operation: rel::Operation) -> rel::Request {
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
    pub(super) resources: ResourceStore,
    pub(super) releases: ReleaseStore,
    pub(super) sources: Sources,
    pub(super) artifacts: ArtifactReader,
    pub(super) actors: ServiceActors,
}
impl PublicationService {
    pub async fn connect(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        logical_source: String,
        config: [SourceConfig; 3],
        artifacts: ArtifactReader,
        actors: ServiceActors,
        cutoff: Deadline,
    ) -> Result<Self> {
        actors.check(tenant)?;
        let sources = Sources::new(tenant, logical_source, config).await?;
        let resources = ResourceStore::new(runtime.clone(), tenant, budget(cutoff)).await?;
        let releases = ReleaseStore::new(runtime.clone(), tenant, budget(cutoff)).await?;
        let mut heads = [None, None, None];
        for (i, b) in sources.bindings.iter().enumerate() {
            if let Driver::Brew { repo, .. } = &b.driver {
                heads[i] = repo
                    .head()
                    .await
                    .map_err(|_| Error::Source)?
                    .map(|c| c.as_str().into());
            }
        }
        settle(
            runtime
                .local_tx_with_context(
                    tenant,
                    budget(cutoff),
                    (&sources, &heads, &actors.backend),
                    |(s, h, a), tx| Box::pin(async move { db::register(tx, s, h, a).await }),
                )
                .await,
        )?;
        Ok(Self {
            runtime,
            resources,
            releases,
            sources,
            artifacts,
            actors,
        })
    }
    pub fn tenant(&self) -> TenantId {
        self.sources.tenant
    }
    pub async fn candidate(
        &self,
        id: &rel::CandidateId,
        cutoff: Deadline,
    ) -> Result<Option<rel::Candidate>> {
        Ok(self.releases.get(id, budget(cutoff)).await?)
    }
    pub async fn create_candidate(
        &self,
        input: &CandidateInput,
        cutoff: Deadline,
    ) -> Result<rss_mdm_software_release_postgres::OperationReceipt> {
        if input.candidate.tenant() != self.tenant() || input.request.tenant() != self.tenant() {
            return Err(Error::Identity);
        }
        let version = self
            .resources
            .version(&input.resource, &input.version, budget(cutoff))
            .await?
            .ok_or(Error::Content)?;
        let prepared = spec::prepare(&self.sources, &version, &input.submission)?;
        if self
            .releases
            .operation(&input.request, budget(cutoff))
            .await?
            .is_none()
        {
            self.verify(&prepared, cutoff).await?;
        }
        let candidate = rel::Candidate::new(
            input.candidate.clone(),
            prepared.content.clone(),
            input.as_of,
        );
        let subject = Subject {
            format: 1,
            resource: input.resource.as_str().into(),
            version: input.version.as_str().into(),
            resource_digest: version.digest().bytes(),
            coordinate: prepared.coordinate,
            submission: prepared.submission,
        };
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, input, &candidate, &subject),
                    |(s, i, c, subject), tx| {
                        Box::pin(async move { s.create_in(tx, i, c, subject).await })
                    },
                )
                .await,
        )
    }
    async fn create_in(
        &self,
        tx: &mut PgTransaction<'_>,
        i: &CandidateInput,
        c: &rel::Candidate,
        subject: &Subject,
    ) -> InTransaction<rss_mdm_software_release_postgres::OperationReceipt> {
        let key = db::software_key(&c.snapshot().content)?;
        db::lock(tx, "authority", &hex(&key)).await?;
        if let Some(old) = db::subject(tx, i.candidate.value()).await? {
            if db::encode(&old)? != db::encode(subject)? {
                return Ok(Err(Error::Conflict));
            }
            return Ok(Ok(db::required(
                self.releases.create_in(tx, &i.request, c).await?,
            )?));
        }
        let (v, state, revision) = input!(
            self.resources
                .lock_version_in(tx, &i.resource, &i.version)
                .await?
                .map_err(|_| Error::Content)
        );
        if v.digest().bytes() != subject.resource_digest
            || revision != i.expected_resource_revision
            || !matches!(state, resource::State::Frozen | resource::State::Active)
        {
            return Ok(Err(Error::Conflict));
        }
        let material = Sha256::digest(db::encode(&serde_json::json!([
            v.digest().bytes(),
            c.snapshot().content.manifest().bytes()
        ]))?)
        .to_vec();
        if let Some((owner, old)) = db::authority(tx, &key).await? {
            if old != material {
                return Ok(Err(Error::Content));
            }
            input!(self.retired_owner(tx, &owner).await?);
        }
        let receipt = db::required(self.releases.create_in(tx, &i.request, c).await?)?;
        db::insert_subject(tx, i.candidate.value(), subject).await?;
        db::set_authority(tx, key, material, i.candidate.value()).await?;
        db::audit(
            tx,
            &self.actors.publisher,
            i.candidate.value(),
            "software_candidate",
        )
        .await?;
        Ok(Ok(receipt))
    }
    async fn retired_owner(&self, tx: &mut PgTransaction<'_>, owner: &str) -> InTransaction<()> {
        let id = db::required(rel::CandidateId::new(self.tenant(), owner))?;
        let c = input!(
            self.releases
                .get_in(tx, &id)
                .await?
                .map_err(|_| Error::Conflict)
        )
        .ok_or_else(db::fault)?;
        if c.snapshot().disposition == rel::Disposition::Active {
            return Ok(Err(Error::Conflict));
        }
        for ring in rel::Ring::ALL {
            if let rel::RingState::Publication(p) = c.snapshot().ring_state(ring) {
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
            }
        }
        Ok(Ok(()))
    }
    pub async fn validate(
        &self,
        id: &rel::CandidateId,
        ring: rel::Ring,
        request: &ServiceRequest,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        if let Some(replay) = self
            .replay_service(id, ring, request, "validate", None, cutoff)
            .await?
        {
            return Ok(replay);
        }

        let (c, subject, prepared) = self.context(id, cutoff).await?;
        if self
            .releases
            .operation(&request.id, budget(cutoff))
            .await?
            .is_none()
        {
            self.verify(&prepared, cutoff).await?;
        }
        let at = request.as_of;
        let evidence = rel::Evidence {
            actor: self.actors.validator.clone(),
            digest: rel::Digest::of(
                &db::encode(&serde_json::json!([
                    c.snapshot().content.digest().bytes(),
                    prepared
                        .artifacts
                        .iter()
                        .map(|a| serde_json::json!([a.key, a.length, a.sha256]))
                        .collect::<Vec<_>>()
                ]))
                .map_err(Error::RolledBack)?,
            ),
            at,
        };
        let r = request.core(
            &self.actors.validator,
            rel::Operation::Validate(rel::Validation {
                candidate: id.clone(),
                content: c.snapshot().content.digest(),
                ring,
                evidence,
                verdict: rel::Verdict::Passed,
            }),
        );
        self.transition_audited(&c, &subject, &r, "software_validate", cutoff)
            .await
    }
    pub async fn approve(
        &self,
        id: &rel::CandidateId,
        ring: rel::Ring,
        request: &ServiceRequest,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        if let Some(replay) = self
            .replay_service(id, ring, request, "approve", None, cutoff)
            .await?
        {
            return Ok(replay);
        }
        let (c, subject, _) = self.context(id, cutoff).await?;
        let r = request.core(
            &self.actors.approver,
            rel::Operation::Approve {
                ring,
                publisher: self.actors.publisher.clone(),
                policy: rel::ActorPolicy::Separate,
            },
        );
        self.transition_audited(&c, &subject, &r, "software_approve", cutoff)
            .await
    }
    pub async fn authorize(
        &self,
        id: &rel::CandidateId,
        ring: rel::Ring,
        request: &ServiceRequest,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        if let Some(replay) = self
            .replay_service(id, ring, request, "authorize", None, cutoff)
            .await?
        {
            return Ok(replay);
        }

        let (c, subject, prepared) = self.context(id, cutoff).await?;
        if self
            .releases
            .operation(&request.id, budget(cutoff))
            .await?
            .is_none()
        {
            self.verify(&prepared, cutoff).await?;
        }
        let approval = match c.snapshot().ring_state(ring) {
            rel::RingState::Approved(a) => a.digest(),
            rel::RingState::Publication(p) => p.approval.digest(),
            _ => return Err(Error::Conflict),
        };
        let r = request.core(
            &self.actors.publisher,
            rel::Operation::Authorize { ring, approval },
        );
        self.authorize_request(&c, &subject, &r, cutoff).await
    }
    pub async fn retry(
        &self,
        id: &rel::CandidateId,
        ring: rel::Ring,
        attempt: u64,
        request: &ServiceRequest,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        if let Some(replay) = self
            .replay_service(id, ring, request, "retry", Some(attempt), cutoff)
            .await?
        {
            return Ok(replay);
        }
        let (c, subject, prepared) = self.context(id, cutoff).await?;
        if self
            .releases
            .operation(&request.id, budget(cutoff))
            .await?
            .is_none()
        {
            self.verify(&prepared, cutoff).await?;
        }
        let rel::RingState::Publication(p) = c.snapshot().ring_state(ring) else {
            return Err(Error::Conflict);
        };
        let r = request.core(
            &self.actors.publisher,
            rel::Operation::Retry {
                ring,
                publication: p.id(),
                attempt,
            },
        );
        self.authorize_request(&c, &subject, &r, cutoff).await
    }
    async fn authorize_request(
        &self,
        c: &rel::Candidate,
        subject: &Subject,
        r: &rel::Request,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        let old = self.releases.operation(&r.id, budget(cutoff)).await?;
        let preview = c
            .transition(r.clone(), old.as_ref().and_then(|r| r.transition.as_ref()))
            .map_err(|_| Error::Conflict)?;
        let rel::Transition::Applied {
            decision: rel::Decision::Publish(p),
            ..
        } = &preview
        else {
            return self
                .transition_audited(c, subject, r, "software_authorize", cutoff)
                .await;
        };
        let target = self.prepare_target(subject, p, cutoff).await?;
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, c, subject, r, &target),
                    |(s, c, subject, r, target), tx| {
                        Box::pin(async move {
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
                            input!(s.resource_usable(tx, subject).await?);
                            let current = input!(
                                s.releases
                                    .lock_candidate_in(tx, &c.snapshot().id)
                                    .await?
                                    .map_err(|_| Error::Conflict)
                            );
                            input!(
                                current
                                    .transition((*r).clone(), None)
                                    .map_err(|_| Error::Conflict)
                            );
                            let key = db::software_key(&c.snapshot().content)?;
                            if db::authority(tx, &key)
                                .await?
                                .is_none_or(|(owner, _)| owner != target.candidate)
                            {
                                return Ok(Err(Error::Conflict));
                            }
                            let result = db::required(
                                s.releases.transition_in(tx, &c.snapshot().id, r).await?,
                            )?;
                            db::reserve(tx, target, &target.key()).await?;
                            db::insert_call(tx, db::Table::Publish, target).await?;
                            db::audit(
                                tx,
                                &s.actors.publisher,
                                &target.candidate,
                                "software_authorize",
                            )
                            .await?;
                            Ok(Ok(result))
                        })
                    },
                )
                .await,
        )
    }
    async fn prepare_target(
        &self,
        subject: &Subject,
        p: &rel::Publication,
        cutoff: Deadline,
    ) -> Result<Target> {
        let ring = p.approval.validation.ring;
        let binding = self.sources.binding(ring);
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
            format: 1,
            candidate: p.approval.validation.candidate.value().into(),
            publication: p.id().digest().bytes(),
            attempt: p.attempt,
            ring: config::index(ring) as u8,
            binding: binding.identity.clone(),
            coordinate: subject.coordinate.clone(),
            slot,
            base: state.cursor,
            commit: None,
            at: p.authorized_at.unix_seconds(),
            commit_at: p.authorized_at.unix_seconds(),
        };
        if let Driver::Brew { repo, tap } = &binding.driver {
            let Submission::Brew { recipe } = &subject.submission else {
                return Err(Error::Content);
            };
            if repo
                .head()
                .await
                .map_err(|_| Error::Source)?
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
                .map_err(|_| Error::Content)?;
            let prepared = repo
                .prepare(
                    base,
                    recipe.render(self.tenant(), tap)?,
                    &operation(&target),
                    p.authorized_at,
                )
                .await
                .map_err(|_| Error::Source)?;
            target.commit = Some(prepared.target().as_str().into());
        }
        Ok(target)
    }
    async fn replay_service(
        &self,
        id: &rel::CandidateId,
        ring: rel::Ring,
        r: &ServiceRequest,
        kind: &str,
        attempt: Option<u64>,
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
        let (actual, actual_ring, actor) = match &original.operation {
            rel::Operation::Validate(v) => ("validate", v.ring, &self.actors.validator),
            rel::Operation::Approve { ring, .. } => ("approve", *ring, &self.actors.approver),
            rel::Operation::Authorize { ring, .. } => ("authorize", *ring, &self.actors.publisher),
            rel::Operation::Retry {
                ring, attempt: a, ..
            } if Some(*a) == attempt => ("retry", *ring, &self.actors.publisher),
            _ => return Err(Error::Conflict),
        };
        if owner != *id
            || original.id != r.id
            || original.actor != *actor
            || actual != kind
            || actual_ring != ring
            || original.expected_revision != r.expected_revision
            || original.as_of != r.as_of
        {
            return Err(Error::Conflict);
        }
        Ok(Some(
            self.releases
                .transition(id, &original, budget(cutoff))
                .await?,
        ))
    }
    pub(super) async fn context(
        &self,
        id: &rel::CandidateId,
        cutoff: Deadline,
    ) -> Result<(rel::Candidate, Subject, PreparedContent)> {
        if id.tenant() != self.tenant() {
            return Err(Error::Identity);
        }
        let (c, subject, version) = settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, id), |(s, id), tx| {
                    Box::pin(async move {
                        let c = input!(
                            s.releases
                                .get_in(tx, id)
                                .await?
                                .map_err(|_| Error::Conflict)
                        )
                        .ok_or_else(db::fault)?;
                        let subject = db::subject(tx, id.value()).await?.ok_or_else(db::fault)?;
                        let resource = db::required(resource::Id::new(&subject.resource))?;
                        let version = db::required(resource::Id::new(&subject.version))?;
                        let (v, _, _) = input!(
                            s.resources
                                .lock_version_in(tx, &resource, &version)
                                .await?
                                .map_err(|_| Error::Content)
                        );
                        if v.digest().bytes() != subject.resource_digest {
                            return Err(db::fault());
                        }
                        Ok(Ok((c, subject, v)))
                    })
                })
                .await,
        )?;
        let prepared = spec::prepare(&self.sources, &version, &subject.submission)?;
        if prepared.content != c.snapshot().content || prepared.coordinate != subject.coordinate {
            return Err(Error::Content);
        }
        Ok((c, subject, prepared))
    }
    pub(super) async fn verify(&self, p: &PreparedContent, cutoff: Deadline) -> Result<()> {
        tokio::time::timeout_at(cutoff.instant().into(), async {
            for a in &p.artifacts {
                self.artifacts.verify(&a.url, a.length, a.sha256).await?;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::ArtifactTimeout)?
    }
    pub(super) fn request(
        &self,
        c: &rel::Candidate,
        actor: &rel::ActorId,
        at: Timepoint,
        operation: rel::Operation,
    ) -> Result<rel::Request> {
        Ok(rel::Request {
            id: rel::RequestId::new(self.tenant(), uuid::Uuid::new_v4().simple().to_string())
                .map_err(|_| Error::Identity)?,
            actor: actor.clone(),
            expected_revision: c.snapshot().revision,
            as_of: at,
            operation,
        })
    }
    pub(super) async fn resource_usable(
        &self,
        tx: &mut PgTransaction<'_>,
        subject: &Subject,
    ) -> InTransaction<()> {
        let id = db::required(resource::Id::new(&subject.resource))?;
        let version = db::required(resource::Id::new(&subject.version))?;
        let (v, state, _) = input!(
            self.resources
                .lock_version_in(tx, &id, &version)
                .await?
                .map_err(|_| Error::Content)
        );
        if v.digest().bytes() != subject.resource_digest
            || !matches!(state, resource::State::Frozen | resource::State::Active)
        {
            return Ok(Err(Error::Content));
        }
        Ok(Ok(()))
    }
    pub(super) async fn transition_audited(
        &self,
        c: &rel::Candidate,
        subject: &Subject,
        r: &rel::Request,
        action: &'static str,
        cutoff: Deadline,
    ) -> Result<rel::Transition> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, c, subject, r),
                    move |(s, c, subject, r), tx| {
                        Box::pin(async move {
                            let replay =
                                db::required(s.releases.operation_in(tx, &r.id).await?)?.is_some();
                            if !replay {
                                input!(s.resource_usable(tx, subject).await?);
                            }
                            let result = input!(
                                s.releases
                                    .transition_in(tx, &c.snapshot().id, r)
                                    .await?
                                    .map_err(|_| Error::Conflict)
                            );
                            if matches!(result, rel::Transition::Applied { .. }) {
                                db::audit(tx, &r.actor, c.snapshot().id.value(), action).await?;
                            }
                            Ok(Ok(result))
                        })
                    },
                )
                .await,
        )
    }
    /// Historical references are retained; only a never-referenced version can be archived here.
    pub async fn archive_resource(
        &self,
        r: &rss_mdm_resource_postgres::Request,
        cutoff: Deadline,
    ) -> Result<rss_mdm_resource_postgres::Receipt> {
        let rss_mdm_resource_postgres::Command::Archive { version, .. } = &r.command else {
            return Err(Error::Input);
        };
        settle(self.runtime.local_tx_with_context(self.tenant(),budget(cutoff),(self,r,version),|(s,r,v),tx|Box::pin(async move{input!(s.resources.lock_version_in(tx,&r.resource,v).await?.map_err(|_|Error::Content));let(t,id,v)=(s.tenant().to_string(),r.resource.as_str().to_owned(),v.as_str().to_owned());let count:i64=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT count(*) FROM mdm_software_composition.subjects WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3").bind(t).bind(id).bind(v).fetch_one(c).await})).await?;if count!=0{return Ok(Err(Error::Blocked));}let receipt=input!(s.resources.execute_in(tx,r).await?.map_err(|_|Error::Conflict));db::audit(tx,&s.actors.publisher,r.resource.as_str(),"software_archive").await?;Ok(Ok(receipt))})).await)
    }
}
pub(super) fn operation(t: &Target) -> String {
    format!("p-{}-a-{}", hex(&t.publication), t.attempt)
}
