use super::{
    config::Driver,
    service::operation,
    storage::{self as db, Call, Table, Target},
    *,
};
use rss_contract::Timepoint;
use rss_mdm_brew_source as brew;
use rss_mdm_software_release as rel;
use rss_mdm_winget_source as winget;
use rss_request_context::Deadline;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Withdrawal {
    NotPublished,
    /// Publication is unresolved; reconcile publication before attempting withdrawal.
    WaitingPublication,
    /// No source write was submitted; a caller may retry withdrawal preflight.
    PreflightRetryable,
    /// WinGet DELETE may have applied; source-owner reconciliation is required.
    SourceOutcomeUnknown,
    /// Acknowledged or Git-fenced mutation awaits read-back confirmation.
    AwaitingConfirmation,
    Complete,
}
#[derive(Clone, Copy)]
enum WriteObservation {
    Acknowledged,
    NotSubmitted,
    Uncertain,
}
#[derive(Clone, Copy)]
enum Observation {
    Applied,
    NotSubmitted,
    Unknown,
}
impl Observation {
    fn tag(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::NotSubmitted => "not-applied",
            Self::Unknown => "unknown",
        }
    }
    fn result(self, evidence: rel::Evidence) -> rel::PublicationResult {
        match self {
            Self::Applied => rel::PublicationResult::Applied(evidence),
            Self::NotSubmitted => rel::PublicationResult::NotApplied(evidence),
            Self::Unknown => rel::PublicationResult::Unknown(evidence),
        }
    }
}
impl PublicationService {
    #[tracing::instrument(skip_all, fields(tenant = %self.tenant(), publication = %hex(&id.digest().bytes()), attempt))]
    pub async fn publish(
        &self,
        id: rel::PublicationId,
        attempt: u64,
        at: Timepoint,
        cutoff: Deadline,
    ) -> Result<rel::PublicationOutcome> {
        let key = format!("p:{}:{attempt}", hex(&id.digest().bytes()));
        let call = self.load_call(Table::Publish, &key, cutoff).await?;
        let candidate = rel::CandidateId::new(self.tenant(), &call.target.candidate)
            .map_err(|cause| Error::Identity.context("driver::publish", cause))?;
        let (c, subject, prepared) = self.context(&candidate, cutoff).await?;
        let p = db::core_publication(&c, &call.target)?;
        if matches!(
            p.outcome,
            rel::PublicationOutcome::Reported(
                rel::PublicationResult::Applied(_) | rel::PublicationResult::NotApplied(_)
            )
        ) {
            return Ok(p.outcome);
        }
        if !call.attempted {
            self.verify(&prepared, cutoff).await?;
            if self
                .start_call(Table::Publish, &call.target, cutoff)
                .await?
            {
                let response = tokio::time::timeout_at(
                    cutoff.instant().into(),
                    self.write_source(&call.target, &subject, false),
                )
                .await;
                if matches!(response, Ok(Ok(WriteObservation::NotSubmitted))) {
                    return self
                        .record_result(&call.target, Observation::NotSubmitted, at, cutoff)
                        .await;
                }
                if matches!(response, Ok(Ok(WriteObservation::Acknowledged))) {
                    self.acknowledge(Table::Publish, &call.target, cutoff)
                        .await?;
                }
            }
        }
        self.reconcile(id, attempt, at, cutoff).await
    }
    #[tracing::instrument(skip_all, fields(tenant = %self.tenant(), publication = %hex(&id.digest().bytes()), attempt))]
    pub async fn reconcile(
        &self,
        id: rel::PublicationId,
        attempt: u64,
        at: Timepoint,
        cutoff: Deadline,
    ) -> Result<rel::PublicationOutcome> {
        let call = self
            .load_call(
                Table::Publish,
                &format!("p:{}:{attempt}", hex(&id.digest().bytes())),
                cutoff,
            )
            .await?;
        let candidate = rel::CandidateId::new(self.tenant(), &call.target.candidate)
            .map_err(|cause| Error::Identity.context("driver::reconcile", cause))?;
        let (c, subject, _) = self.context(&candidate, cutoff).await?;
        let p = db::core_publication(&c, &call.target)?;
        if matches!(
            p.outcome,
            rel::PublicationOutcome::Reported(
                rel::PublicationResult::Applied(_) | rel::PublicationResult::NotApplied(_)
            )
        ) || !call.attempted
        {
            return Ok(p.outcome);
        }
        let inspection = tokio::time::timeout_at(
            cutoff.instant().into(),
            self.inspect_source(&call.target, &subject, false),
        )
        .await;
        let matched = match inspection {
            Ok(Ok(value)) => value,
            Ok(Err(_)) => false,
            Err(_) => {
                tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&call.target.publication),
                    attempt = call.target.attempt,
                    ring = call.target.ring,
                    source_binding = %hex(&call.target.binding),
                    stage = "reconcile",
                    reason = "deadline",
                    "software source inspection failed"
                );
                false
            }
        };
        self.record_result(
            &call.target,
            if matched {
                Observation::Applied
            } else {
                Observation::Unknown
            },
            at,
            cutoff,
        )
        .await
    }
    async fn load_call(&self, table: Table, key: &str, cutoff: Deadline) -> Result<Call> {
        let call = settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), key, move |key, tx| {
                    Box::pin(
                        async move { Ok(db::call(tx, table, key).await?.ok_or(Error::Conflict)) },
                    )
                })
                .await,
        )?;
        let t = &call.target;
        if t.binding != self.sources.binding(t.ring()?).identity
            || if matches!(table, Table::Publish) {
                t.key() != key
            } else {
                t.withdrawal_key() != key
            }
        {
            return Err(Error::Identity);
        }
        Ok(call)
    }
    async fn start_call(&self, table: Table, t: &Target, cutoff: Deadline) -> Result<bool> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, t),
                    move |(s, t), tx| {
                        Box::pin(async move {
                            db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                .await?;
                            let key = if matches!(table, Table::Publish) {
                                t.key()
                            } else {
                                t.withdrawal_key()
                            };
                            let call = db::call(tx, table, &key).await?.ok_or_else(db::fault)?;
                            if call.attempted || call.complete {
                                return Ok(Ok(false));
                            }
                            if !call.prepared {
                                return Ok(Err(Error::Blocked));
                            }
                            let slot = db::slot(tx, &t.binding, &t.slot).await?;
                            if slot.operation.as_deref() != Some(&key) {
                                return Ok(Err(Error::Blocked));
                            }
                            if matches!(table, Table::Publish) {
                                let subject =
                                    db::subject(tx, &t.candidate).await?.ok_or_else(db::fault)?;
                                input!(s.resource_usable(tx, &subject).await?);
                            }
                            let id = db::required(
                                "driver::start_call",
                                rel::CandidateId::new(s.tenant(), &t.candidate),
                            )?;
                            let c = input!(s.releases.lock_candidate_in(tx, &id).await?.map_err(
                                |cause| Error::Conflict.context("driver::start_call", cause)
                            ));
                            let p = input!(db::core_publication(&c, t));
                            if matches!(table, Table::Publish) {
                                if c.snapshot().disposition != rel::Disposition::Active
                                    || !matches!(p.outcome, rel::PublicationOutcome::Pending)
                                {
                                    return Ok(Err(Error::Blocked));
                                }
                            } else if !matches!(
                                p.outcome,
                                rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(
                                    _
                                ))
                            ) {
                                return Ok(Err(Error::Blocked));
                            }
                            db::mark(tx, table, &key, false, false).await?;
                            db::audit(
                                tx,
                                &s.actors.backend,
                                &t.candidate,
                                "software_call",
                                db::target_fact(t, table, "start_call", "attempted"),
                            )
                            .await?;
                            Ok(Ok(true))
                        })
                    },
                )
                .await,
        )
    }
    async fn acknowledge(&self, table: Table, t: &Target, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, t),
                    move |(s, t), tx| {
                        Box::pin(async move {
                            let key = if matches!(table, Table::Publish) {
                                t.key()
                            } else {
                                t.withdrawal_key()
                            };
                            db::mark(tx, table, &key, true, false).await?;
                            db::audit(
                                tx,
                                &s.actors.backend,
                                &t.candidate,
                                "software_call",
                                db::target_fact(t, table, "acknowledge", "acknowledged"),
                            )
                            .await?;
                            Ok(Ok(()))
                        })
                    },
                )
                .await,
        )
    }
    async fn write_source(
        &self,
        t: &Target,
        s: &db::Subject,
        remove: bool,
    ) -> Result<WriteObservation> {
        match &self.sources.binding(t.ring()?).driver {
            Driver::Winget { publisher, access } => {
                self.write_winget(publisher, access, t, s, remove).await
            }
            Driver::Brew { repo, tap } => self.write_brew(repo, tap, t, s, remove).await,
        }
    }
    async fn write_winget(
        &self,
        publisher: &winget::Publisher,
        access: &winget::WriteAccess,
        t: &Target,
        s: &db::Subject,
        remove: bool,
    ) -> Result<WriteObservation> {
        let Submission::Winget { manifest } = &s.submission else {
            return Err(Error::Content);
        };
        let m = winget::VersionManifest::parse(
            self.tenant(),
            &self.sources.logical,
            &serde_json::to_vec(manifest)
                .map_err(|cause| Error::Content.context("driver::write_winget", cause))?,
        )
        .map_err(|cause| Error::Content.context("driver::write_winget", cause))?;
        let result = if remove {
            publisher.withdraw(&m, access).await
        } else {
            publisher.submit(&m, access).await
        };
        if !matches!(result, Ok(winget::WriteResponse::Accepted)) {
            tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                backend = "winget",
                stage = if remove { "withdraw" } else { "publish" },
                ?result,
                "software source write observation"
            );
        }
        Ok(match result {
            Ok(winget::WriteResponse::Accepted) => WriteObservation::Acknowledged,
            // The information request precedes POST/DELETE. Failure here proves no write was sent.
            Err(
                winget::Error::HttpStatus {
                    stage: winget::RequestStage::Information,
                    ..
                }
                | winget::Error::Transport(winget::RequestStage::Information)
                | winget::Error::Timeout(winget::RequestStage::Information),
            ) => WriteObservation::NotSubmitted,
            _ => WriteObservation::Uncertain,
        })
    }
    async fn write_brew(
        &self,
        repo: &brew::Repository,
        tap: &str,
        t: &Target,
        s: &db::Subject,
        remove: bool,
    ) -> Result<WriteObservation> {
        let Submission::Brew { recipe } = &s.submission else {
            return Err(Error::Content);
        };
        let base = t
            .base
            .as_deref()
            .map(brew::CommitId::parse)
            .transpose()
            .map_err(|cause| Error::Content.context("driver::write_brew", cause))?;
        let at = Timepoint::try_from(t.commit_at)
            .map_err(|cause| Error::Content.context("driver::write_brew", cause))?;
        let document = recipe.render(self.tenant(), tap)?;
        let prepared = if remove {
            repo.prepare_remove(
                base.ok_or(Error::Content)?,
                document,
                &withdraw_operation(t),
                at,
            )
            .await
        } else {
            repo.prepare(base, document, &operation(t), at).await
        }
        .map_err(|reason| {
            tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                ?reason,
                stage = "source",
                "software source operation failed"
            );
            Error::Source.context("driver::write_brew", reason)
        })?;
        if Some(prepared.target().as_str()) != t.commit.as_deref() {
            return Err(Error::Content);
        }
        let result = repo.apply(&prepared).await;
        if let Err(reason) = &result {
            tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                backend = "brew",
                ?reason,
                "software source write observation"
            );
        }
        Ok(if result.is_ok() {
            WriteObservation::Acknowledged
        } else {
            WriteObservation::Uncertain
        })
    }
    async fn inspect_source(&self, t: &Target, s: &db::Subject, remove: bool) -> Result<bool> {
        match &self.sources.binding(t.ring()?).driver {
            Driver::Winget { publisher, access } => {
                let Submission::Winget { manifest } = &s.submission else {
                    return Err(Error::Content);
                };
                let m = winget::VersionManifest::parse(
                    self.tenant(),
                    &self.sources.logical,
                    &serde_json::to_vec(manifest)
                        .map_err(|cause| Error::Content.context("driver::inspect_source", cause))?,
                )
                .map_err(|cause| Error::Content.context("driver::inspect_source", cause))?;
                let result = publisher.inspect(&m, access).await.map_err(|reason| {
                    tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                        ?reason,
                        stage = "source",
                        "software source operation failed"
                    );
                    Error::Source.context("driver::inspect_source", reason)
                })?;
                tracing::debug!(
                    backend = "winget",
                    stage = "reconcile",
                    ?result,
                    "software source inspection"
                );
                Ok(result
                    == if remove {
                        winget::Inspection::Absent
                    } else {
                        winget::Inspection::Matching
                    })
            }
            Driver::Brew { repo, tap } => {
                let Submission::Brew { recipe } = &s.submission else {
                    return Err(Error::Content);
                };
                let target = brew::CommitId::parse(t.commit.as_deref().ok_or(Error::Content)?)
                    .map_err(|cause| Error::Content.context("driver::inspect_source", cause))?;
                if !repo.contains_commit(&target).await.map_err(|reason| {
                    tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                        ?reason,
                        stage = "source",
                        "software source operation failed"
                    );
                    Error::Source.context("driver::inspect_source", reason)
                })? {
                    return Ok(false);
                }
                let result = repo
                    .presence(&target, &recipe.render(self.tenant(), tap)?)
                    .await
                    .map_err(|reason| {
                        tracing::warn!(
                        tenant = %self.tenant(),
                        publication = %hex(&t.publication),
                        attempt = t.attempt,
                        ring = t.ring,
                        source_binding = %hex(&t.binding),
                                ?reason,
                                stage = "source",
                                "software source operation failed"
                            );
                        Error::Source.context("driver::inspect_source", reason)
                    })?;
                Ok(result
                    == if remove {
                        brew::DocumentPresence::Absent
                    } else {
                        brew::DocumentPresence::Matching
                    })
            }
        }
    }
    async fn record_result(
        &self,
        t: &Target,
        observed: Observation,
        at: Timepoint,
        cutoff: Deadline,
    ) -> Result<rel::PublicationOutcome> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, t),
                    move |(s, t), tx| {
                        Box::pin(async move {
                            db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                .await?;
                            let id = db::required(
                                "driver::record_result",
                                rel::CandidateId::new(s.tenant(), &t.candidate),
                            )?;
                            let c = input!(s.releases.lock_candidate_in(tx, &id).await?.map_err(
                                |cause| Error::Conflict.context("driver::record_result", cause)
                            ));
                            let current = input!(db::core_publication(&c, t));
                            if matches!(
                                current.outcome,
                                rel::PublicationOutcome::Reported(
                                    rel::PublicationResult::Applied(_)
                                        | rel::PublicationResult::NotApplied(_)
                                )
                            ) {
                                return Ok(Ok(current.outcome));
                            }
                            let slot = db::slot(tx, &t.binding, &t.slot).await?;
                            if slot.operation.as_deref() != Some(&t.key()) {
                                return Ok(Err(Error::Blocked));
                            }
                            let evidence = rel::Evidence {
                                actor: s.actors.backend.clone(),
                                digest: rel::Digest::of(&db::encode(&serde_json::json!([
                                    1,
                                    t,
                                    observed.tag()
                                ]))?),
                                at,
                            };
                            let result = observed.result(evidence);
                            let request = input!(db::record_request(
                                &c,
                                t,
                                &s.actors.backend,
                                result.clone(),
                                at
                            ));
                            db::required(
                                "driver::record_result",
                                s.releases.transition_in(tx, &id, &request).await?,
                            )?;
                            if matches!(observed, Observation::Applied) {
                                db::project(tx, t, false).await?;
                                db::release_slot(tx, t, &t.key(), t.commit.clone()).await?;
                            } else if matches!(observed, Observation::NotSubmitted) {
                                db::release_slot(tx, t, &t.key(), None).await?;
                            }
                            db::audit(
                                tx,
                                &s.actors.backend,
                                &t.candidate,
                                "software_result",
                                db::target_fact(t, Table::Publish, "record_result", observed.tag()),
                            )
                            .await?;
                            Ok(Ok(rel::PublicationOutcome::Reported(result)))
                        })
                    },
                )
                .await,
        )
    }
    pub async fn withdraw(
        &self,
        id: &rel::CandidateId,
        ring: rel::Ring,
        request: &ServiceRequest,
        cutoff: Deadline,
    ) -> Result<Withdrawal> {
        let at = request.as_of;
        let r = request.core(&self.actors.publisher, rel::Operation::Quarantine);
        {
            settle(
                self.runtime
                    .local_tx_with_context(
                        self.tenant(),
                        budget(cutoff),
                        (self, id, &r),
                        |(s, id, r), tx| {
                            Box::pin(async move {
                                let result =
                                    input!(s.releases.transition_in(tx, id, r).await?.map_err(
                                        |cause| Error::Conflict.context("driver::withdraw", cause)
                                    ));
                                if matches!(result, rel::Transition::Applied { .. }) {
                                    db::audit(
                                        tx,
                                        &s.actors.publisher,
                                        id.value(),
                                        "software_withdraw",
                                        db::request_fact(
                                            r.id.value(),
                                            Some(ring),
                                            "withdraw-request",
                                        ),
                                    )
                                    .await?;
                                }
                                Ok(Ok(()))
                            })
                        },
                    )
                    .await,
            )?;
        }
        let c = self
            .releases
            .get(id, budget(cutoff))
            .await?
            .ok_or(Error::Conflict)?;
        let rel::RingState::Publication(p) = c.snapshot().ring_state(ring) else {
            return Ok(Withdrawal::NotPublished);
        };
        let publish = self
            .load_call(
                Table::Publish,
                &format!("p:{}:{}", hex(&p.id().digest().bytes()), p.attempt),
                cutoff,
            )
            .await?;
        let mut intent = publish.target.clone();
        intent.base = None;
        intent.commit = None;
        intent.commit_at = at.unix_seconds();
        self.queue_withdrawal(&intent, cutoff).await?;
        if !publish.attempted {
            self.cancel_unstarted(&publish.target, at, cutoff).await?;
        }
        self.drive_withdrawal(p.id(), p.attempt, cutoff, true).await
    }
    #[tracing::instrument(skip_all, fields(tenant = %self.tenant(), publication = %hex(&id.digest().bytes()), attempt))]
    pub async fn reconcile_withdrawal(
        &self,
        id: rel::PublicationId,
        attempt: u64,
        cutoff: Deadline,
    ) -> Result<Withdrawal> {
        self.drive_withdrawal(id, attempt, cutoff, false).await
    }
    /// Read durable withdrawal progress without source I/O or starting a mutation.
    /// `None` means no withdrawal intent exists for this publication attempt.
    /// Unknown DELETE outcomes must be resolved by the source owner, never retried blindly.
    #[tracing::instrument(skip_all, fields(tenant = %self.tenant(), publication = %hex(&id.digest().bytes()), attempt))]
    pub async fn withdrawal_status(
        &self,
        id: rel::PublicationId,
        attempt: u64,
        cutoff: Deadline,
    ) -> Result<Option<Withdrawal>> {
        let key = format!("w:{}:{attempt}", hex(&id.digest().bytes()));
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, &key),
                    |(s, key), tx| {
                        Box::pin(async move {
                            let Some(call) = db::call(tx, Table::Withdraw, key).await? else {
                                return Ok(Ok(None));
                            };
                            if call.complete {
                                return Ok(Ok(Some(Withdrawal::Complete)));
                            }
                            let candidate = input!(
                                rel::CandidateId::new(s.tenant(), &call.target.candidate)
                                    .map_err(|cause| Error::Identity
                                        .context("driver::withdrawal_status", cause))
                            );
                            let c =
                                input!(s.releases.get_in(tx, &candidate).await?.map_err(|cause| {
                                    Error::Conflict.context("driver::withdrawal_status", cause)
                                }))
                                .ok_or_else(db::fault)?;
                            let publication = input!(db::core_publication(&c, &call.target));
                            let status = match publication.outcome {
                                rel::PublicationOutcome::Reported(
                                    rel::PublicationResult::Applied(_),
                                ) => withdrawal_progress(
                                    &call,
                                    matches!(
                                        s.sources.binding(input!(call.target.ring())).driver,
                                        Driver::Winget { .. }
                                    ),
                                ),
                                rel::PublicationOutcome::Reported(
                                    rel::PublicationResult::NotApplied(_),
                                ) => Withdrawal::NotPublished,
                                _ => Withdrawal::WaitingPublication,
                            };
                            Ok(Ok(Some(status)))
                        })
                    },
                )
                .await,
        )
    }
    async fn queue_withdrawal(&self, t: &Target, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, t), |(s, t), tx| {
                    Box::pin(async move {
                        db::lock(tx, "withdrawal", &t.withdrawal_key()).await?;
                        if db::call(tx, Table::Withdraw, &t.withdrawal_key())
                            .await?
                            .is_none()
                        {
                            db::insert_call(tx, Table::Withdraw, t).await?;
                            db::audit(
                                tx,
                                &s.actors.publisher,
                                &t.candidate,
                                "software_withdraw",
                                db::target_fact(t, Table::Withdraw, "queue_withdrawal", "queued"),
                            )
                            .await?;
                        }
                        Ok(Ok(()))
                    })
                })
                .await,
        )
    }
    async fn cancel_unstarted(&self, t: &Target, at: Timepoint, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, t),
                    move |(s, t), tx| {
                        Box::pin(async move {
                            db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                .await?;
                            let call = db::call(tx, Table::Publish, &t.key())
                                .await?
                                .ok_or_else(db::fault)?;
                            if call.attempted {
                                return Ok(Ok(()));
                            }
                            let id = db::required(
                                "driver::cancel_unstarted",
                                rel::CandidateId::new(s.tenant(), &t.candidate),
                            )?;
                            let c = input!(s.releases.lock_candidate_in(tx, &id).await?.map_err(
                                |cause| Error::Conflict.context("driver::cancel_unstarted", cause)
                            ));
                            if c.snapshot().disposition == rel::Disposition::Active {
                                return Ok(Err(Error::Blocked));
                            }
                            let p = input!(db::core_publication(&c, t));
                            if matches!(p.outcome, rel::PublicationOutcome::Pending) {
                                let evidence = rel::Evidence {
                                    actor: s.actors.backend.clone(),
                                    digest: rel::Digest::of(&db::encode(&serde_json::json!([
                                        "closed-before-call",
                                        t
                                    ]))?),
                                    at,
                                };
                                let r = input!(db::record_request(
                                    &c,
                                    t,
                                    &s.actors.backend,
                                    rel::PublicationResult::NotApplied(evidence),
                                    at
                                ));
                                db::required(
                                    "driver::cancel_unstarted",
                                    s.releases.transition_in(tx, &id, &r).await?,
                                )?;
                                db::release_slot(tx, t, &t.key(), None).await?;
                                db::audit(
                                    tx,
                                    &s.actors.backend,
                                    &t.candidate,
                                    "software_result",
                                    db::target_fact(
                                        t,
                                        Table::Publish,
                                        "cancel_unstarted",
                                        "not-applied",
                                    ),
                                )
                                .await?;
                            }
                            db::complete_noop(tx, &t.withdrawal_key()).await?;
                            Ok(Ok(()))
                        })
                    },
                )
                .await,
        )
    }
    async fn drive_withdrawal(
        &self,
        id: rel::PublicationId,
        attempt: u64,
        cutoff: Deadline,
        allow_start: bool,
    ) -> Result<Withdrawal> {
        let key = format!("w:{}:{attempt}", hex(&id.digest().bytes()));
        let mut call = self.load_call(Table::Withdraw, &key, cutoff).await?;
        if call.complete {
            return Ok(Withdrawal::Complete);
        }
        let candidate = rel::CandidateId::new(self.tenant(), &call.target.candidate)
            .map_err(|cause| Error::Identity.context("driver::drive_withdrawal", cause))?;
        let (c, subject, _) = self.context(&candidate, cutoff).await?;
        let p = db::core_publication(&c, &call.target)?;
        if matches!(
            p.outcome,
            rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_))
        ) {
            self.complete_unpublished(&key, cutoff).await?;
            return Ok(Withdrawal::Complete);
        }
        if !matches!(
            p.outcome,
            rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
        ) {
            return Ok(Withdrawal::WaitingPublication);
        }
        if !allow_start && (!call.prepared || !call.attempted) {
            return Ok(Withdrawal::PreflightRetryable);
        }
        if !call.prepared {
            if !self
                .prepare_withdrawal_bounded(&call.target, &subject, cutoff)
                .await?
            {
                return Ok(Withdrawal::Complete);
            }
            call = self.load_call(Table::Withdraw, &key, cutoff).await?;
        }
        if allow_start {
            self.run_withdrawal_call(&call.target, &subject, cutoff)
                .await?;
        }
        self.settle_withdrawal(&key, &subject, cutoff).await
    }
    async fn complete_unpublished(&self, key: &str, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, key),
                    |(s, key), tx| {
                        Box::pin(async move {
                            db::complete_noop(tx, key).await?;
                            let call = db::call(tx, Table::Withdraw, key)
                                .await?
                                .ok_or_else(db::fault)?;
                            db::audit(
                                tx,
                                &s.actors.backend,
                                &call.target.candidate,
                                "software_withdraw",
                                db::target_fact(
                                    &call.target,
                                    Table::Withdraw,
                                    "complete_unpublished",
                                    "applied",
                                ),
                            )
                            .await?;
                            Ok(Ok(()))
                        })
                    },
                )
                .await,
        )
    }
    async fn run_withdrawal_call(
        &self,
        target: &Target,
        subject: &db::Subject,
        cutoff: Deadline,
    ) -> Result<()> {
        if !self.start_call(Table::Withdraw, target, cutoff).await? {
            return Ok(());
        }
        match tokio::time::timeout_at(
            cutoff.instant().into(),
            self.write_source(target, subject, true),
        )
        .await
        {
            Ok(Ok(WriteObservation::Acknowledged)) => {
                self.acknowledge(Table::Withdraw, target, cutoff).await?
            }
            Ok(Ok(WriteObservation::NotSubmitted)) => {
                self.reset_withdrawal_preflight(target, cutoff).await?
            }
            _ => tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&target.publication),
                    attempt = target.attempt,
                    ring = target.ring,
                    source_binding = %hex(&target.binding),
                stage = "withdraw",
                reason = "unknown",
                "software source write needs reconciliation"
            ),
        }
        Ok(())
    }
    async fn reset_withdrawal_preflight(&self, t: &Target, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, t), |(s, t), tx| {
                    Box::pin(async move {
                        db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot)).await?;
                        db::reset_withdrawal_preflight(tx, &t.withdrawal_key()).await?;
                        db::audit(
                            tx,
                            &s.actors.backend,
                            &t.candidate,
                            "software_preflight",
                            db::target_fact(
                                t,
                                Table::Withdraw,
                                "reset_withdrawal_preflight",
                                "not-applied",
                            ),
                        )
                        .await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )
    }
    async fn settle_withdrawal(
        &self,
        key: &str,
        subject: &db::Subject,
        cutoff: Deadline,
    ) -> Result<Withdrawal> {
        let call = self.load_call(Table::Withdraw, key, cutoff).await?;
        if call.complete {
            return Ok(Withdrawal::Complete);
        }
        // No operation lookup in WinGet 1.0: absence alone cannot settle a lost DELETE.
        let can_settle = call.acknowledged
            || matches!(
                self.sources.binding(call.target.ring()?).driver,
                Driver::Brew { .. }
            );
        if can_settle
            && matches!(
                tokio::time::timeout_at(
                    cutoff.instant().into(),
                    self.inspect_source(&call.target, subject, true)
                )
                .await,
                Ok(Ok(true))
            )
        {
            self.finish_withdrawal(&call.target, cutoff).await?;
            Ok(Withdrawal::Complete)
        } else {
            Ok(withdrawal_progress(
                &call,
                matches!(
                    self.sources.binding(call.target.ring()?).driver,
                    Driver::Winget { .. }
                ),
            ))
        }
    }
    async fn prepare_withdrawal_bounded(
        &self,
        t: &Target,
        subject: &db::Subject,
        cutoff: Deadline,
    ) -> Result<bool> {
        tokio::time::timeout_at(
            cutoff.instant().into(),
            self.prepare_withdrawal(t, subject, cutoff),
        )
        .await
        .map_err(|reason| {
            tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                stage = "withdraw_prepare",
                reason = "deadline",
                "software source preparation failed"
            );
            Error::Source.context("driver::prepare_withdrawal_bounded", reason)
        })?
    }
    async fn prepare_withdrawal(
        &self,
        t: &Target,
        subject: &db::Subject,
        cutoff: Deadline,
    ) -> Result<bool> {
        let (slot, current) = settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), t, |t, tx| {
                    Box::pin(async move {
                        Ok(Ok((
                            db::slot(tx, &t.binding, &t.slot).await?,
                            db::projection(tx, t).await?,
                        )))
                    })
                })
                .await,
        )?;
        if current.as_deref() != Some(&t.publication) {
            settle(
                self.runtime
                    .local_tx_with_context(
                        self.tenant(),
                        budget(cutoff),
                        (self, t),
                        |(s, t), tx| {
                            Box::pin(async move {
                                db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                    .await?;
                                if db::projection(tx, t).await?.as_deref() == Some(&t.publication) {
                                    return Ok(Err(Error::Conflict));
                                }
                                db::complete_noop(tx, &t.withdrawal_key()).await?;
                                db::audit(
                                    tx,
                                    &s.actors.backend,
                                    &t.candidate,
                                    "software_withdraw",
                                    db::target_fact(
                                        t,
                                        Table::Withdraw,
                                        "prepare_withdrawal",
                                        "applied",
                                    ),
                                )
                                .await?;
                                Ok(Ok(()))
                            })
                        },
                    )
                    .await,
            )?;
            return Ok(false);
        }
        if slot.operation.is_some() {
            return Err(Error::Blocked);
        }
        let mut prepared = t.clone();
        prepared.base = slot.cursor;
        if let Driver::Brew { repo, tap } = &self.sources.binding(t.ring()?).driver {
            let Submission::Brew { recipe } = &subject.submission else {
                return Err(Error::Content);
            };
            if repo
                .head()
                .await
                .map_err(|reason| {
                    tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                        ?reason,
                        stage = "source",
                        "software source operation failed"
                    );
                    Error::Source.context("driver::prepare_withdrawal", reason)
                })?
                .as_ref()
                .map(|c| c.as_str())
                != prepared.base.as_deref()
            {
                return Err(Error::Blocked);
            }
            let base = brew::CommitId::parse(prepared.base.as_deref().ok_or(Error::Content)?)
                .map_err(|cause| Error::Content.context("driver::prepare_withdrawal", cause))?;
            let p = repo
                .prepare_remove(
                    base,
                    recipe.render(self.tenant(), tap)?,
                    &withdraw_operation(t),
                    Timepoint::try_from(t.commit_at).map_err(|cause| {
                        Error::Content.context("driver::prepare_withdrawal", cause)
                    })?,
                )
                .await
                .map_err(|reason| {
                    tracing::warn!(
                    tenant = %self.tenant(),
                    publication = %hex(&t.publication),
                    attempt = t.attempt,
                    ring = t.ring,
                    source_binding = %hex(&t.binding),
                        ?reason,
                        stage = "source",
                        "software source operation failed"
                    );
                    Error::Source.context("driver::prepare_withdrawal", reason)
                })?;
            prepared.commit = Some(p.target().as_str().into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), &prepared, |t, tx| {
                    Box::pin(async move {
                        db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot)).await?;
                        let slot = db::slot(tx, &t.binding, &t.slot).await?;
                        if slot.operation.is_some()
                            || slot.cursor != t.base
                            || db::projection(tx, t).await?.as_deref() != Some(&t.publication)
                        {
                            return Ok(Err(Error::Blocked));
                        }
                        db::prepare_withdrawal(tx, t).await?;
                        db::reserve(tx, t, &t.withdrawal_key()).await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )?;
        Ok(true)
    }
    async fn finish_withdrawal(&self, t: &Target, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, t), |(s, t), tx| {
                    Box::pin(async move {
                        db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot)).await?;
                        let call = db::call(tx, Table::Withdraw, &t.withdrawal_key())
                            .await?
                            .ok_or_else(db::fault)?;
                        if call.complete {
                            return Ok(Ok(()));
                        }
                        db::mark(
                            tx,
                            Table::Withdraw,
                            &t.withdrawal_key(),
                            call.acknowledged,
                            true,
                        )
                        .await?;
                        db::project(tx, t, true).await?;
                        db::release_slot(tx, t, &t.withdrawal_key(), t.commit.clone()).await?;
                        db::audit(
                            tx,
                            &s.actors.backend,
                            &t.candidate,
                            "software_withdraw",
                            db::target_fact(t, Table::Withdraw, "finish_withdrawal", "applied"),
                        )
                        .await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )
    }
}
fn withdraw_operation(t: &Target) -> String {
    format!("w-{}-a-{}", hex(&t.publication), t.attempt)
}

fn withdrawal_progress(call: &Call, winget: bool) -> Withdrawal {
    if call.complete {
        Withdrawal::Complete
    } else if !call.prepared || !call.attempted {
        Withdrawal::PreflightRetryable
    } else if winget && !call.acknowledged {
        Withdrawal::SourceOutcomeUnknown
    } else {
        Withdrawal::AwaitingConfirmation
    }
}
