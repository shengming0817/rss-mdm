use super::{
    config::Driver,
    service::operation,
    storage::{self as db, Call, Table, Target},
    *,
};
use rss_contract::Timepoint;
use rss_mdm_brew_source as brew;
use rss_mdm_software_release as rel;
use rss_request_context::Deadline;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Withdrawal {
    NotPublished,
    /// Publication is unresolved; reconcile publication before attempting withdrawal.
    WaitingPublication,
    /// No source write was submitted; a caller may retry withdrawal preflight.
    PreflightRetryable,
    /// Acknowledged or Git-fenced mutation awaits read-back confirmation.
    AwaitingConfirmation,
    Complete,
}
/// Settled quarantine operation and external withdrawal status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WithdrawalExecution {
    /// Current external withdrawal outcome; unresolved outcomes must not imply completion.
    pub outcome: Withdrawal,
    /// True only when both the quarantine request and terminal withdrawal were replayed.
    pub replayed: bool,
}
#[derive(Clone, Copy)]
enum WriteObservation {
    Acknowledged,
    Uncertain,
}
#[derive(Clone, Copy)]
enum Observation {
    Applied,
    Unknown,
}
impl Observation {
    fn tag(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Unknown => "unknown",
        }
    }
    fn result(self, evidence: rel::Evidence) -> rel::PublicationResult {
        match self {
            Self::Applied => rel::PublicationResult::Applied(evidence),
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
            return self.recover_result(&call.target, cutoff).await;
        }
        if matches!(
            self.sources.binding(call.target.ring()?).driver,
            Driver::Winget { .. }
        ) {
            if !call.attempted {
                self.verify(&prepared, cutoff).await?;
                self.start_call(Table::Publish, &call.target, cutoff)
                    .await?;
            }
            // The served projection and terminal receipt are one local transaction.
            return self
                .record_result(&call.target, Observation::Applied, at, cutoff)
                .await;
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
        ) {
            return self.recover_result(&call.target, cutoff).await;
        }
        if !call.attempted {
            return Box::pin(self.publish(id, attempt, at, cutoff)).await;
        }
        if matches!(
            self.sources.binding(call.target.ring()?).driver,
            Driver::Winget { .. }
        ) {
            return self
                .record_result(&call.target, Observation::Applied, at, cutoff)
                .await;
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
        let matched = if !matched {
            self.start_call(Table::Publish, &call.target, cutoff)
                .await?;
            let write = tokio::time::timeout_at(
                cutoff.instant().into(),
                self.write_source(&call.target, &subject, false),
            )
            .await;
            if matches!(write, Ok(Ok(WriteObservation::Acknowledged))) {
                self.acknowledge(Table::Publish, &call.target, cutoff)
                    .await?;
                tokio::time::timeout_at(
                    cutoff.instant().into(),
                    self.inspect_source(&call.target, &subject, false),
                )
                .await
                .is_ok_and(|result| result.is_ok_and(|matched| matched))
            } else {
                false
            }
        } else {
            true
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
    async fn recover_result(
        &self,
        t: &Target,
        cutoff: Deadline,
    ) -> Result<rel::PublicationOutcome> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, t), |(s, t), tx| {
                    Box::pin(async move {
                        s.audit_store
                            .lock_in(tx)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                        tx.prepare_outbox_partitions(&[s.releases.partition(&t.candidate)?])
                            .await?;
                        let id = db::required(
                            "recover_result",
                            rel::CandidateId::new(s.tenant(), &t.candidate),
                        )?;
                        let c = input!(
                            s.releases
                                .lock_candidate_in(tx, &id)
                                .await?
                                .map_err(|_| Error::Conflict)
                        );
                        let p = input!(db::core_publication(&c, t));
                        let rel::PublicationOutcome::Reported(result) = &p.outcome else {
                            return Err(db::fault());
                        };
                        s.recover_record_in(tx, &c, t, result).await?;
                        Ok(Ok(p.outcome))
                    })
                })
                .await,
        )
    }
    async fn recover_record_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        c: &rel::Candidate,
        t: &Target,
        result: &rel::PublicationResult,
    ) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
        let mut request = db::required(
            "recover_record",
            db::record_request(
                c,
                t,
                &self.actors.backend,
                result.clone(),
                result.evidence().at,
            ),
        )?;
        let old = db::required(
            "recover_record",
            self.releases.operation_in(tx, &request.id).await?,
        )?
        .ok_or_else(db::fault)?;
        request.expected_revision = old.transition.ok_or_else(db::fault)?.before_revision;
        db::required(
            "recover_record",
            self.releases
                .transition_in(tx, &c.snapshot().id, &request)
                .await?,
        )?;
        let outcome = match result {
            rel::PublicationResult::Applied(_) => "applied",
            rel::PublicationResult::NotApplied(_) => "not-applied",
            rel::PublicationResult::Unknown(_) => "unknown",
        };
        let standard = rel::Digest::of(&db::encode(&serde_json::json!([1, t, outcome]))?);
        let closed = rel::Digest::of(&db::encode(&serde_json::json!(["closed-before-call", t]))?);
        let stage = if result.evidence().digest == standard {
            "record_result"
        } else if outcome == "not-applied" && result.evidence().digest == closed {
            "cancel_unstarted"
        } else {
            return Err(db::fault());
        };
        let fact = db::fact(
            tx.tenant_id(),
            &self.actors.backend,
            &t.candidate,
            "software_result",
            db::record_fact(&request, t, stage, outcome),
            &db::request_fingerprint(&t.candidate, &request)?,
        )?;
        self.audit_store
            .append_in(tx, &fact, true)
            .await
            .map_err(rss_transactional_messaging_postgres::PgError::from)
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
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                .await?;
                            let key = if matches!(table, Table::Publish) {
                                t.key()
                            } else {
                                t.withdrawal_key()
                            };
                            let call = db::call(tx, table, &key).await?.ok_or_else(db::fault)?;
                            if call.complete {
                                return Ok(Ok(false));
                            }
                            let generation =
                                call.generation.checked_add(1).ok_or_else(db::fault)?;
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
                                    || !(matches!(p.outcome, rel::PublicationOutcome::Pending)
                                        || call.attempted
                                            && matches!(
                                                p.outcome,
                                                rel::PublicationOutcome::Reported(
                                                    rel::PublicationResult::Unknown(_)
                                                )
                                            ))
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
                            if call.attempted {
                                let fact = db::fact(
                                    tx.tenant_id(),
                                    &s.actors.backend,
                                    &t.candidate,
                                    "software_call",
                                    db::call_fact(
                                        t,
                                        table,
                                        call.generation,
                                        "start_call",
                                        "attempted",
                                    ),
                                    &db::encode(&(t, call.generation))?,
                                )?;
                                s.audit_store
                                    .append_in(tx, &fact, true)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                                return Ok(Ok(false));
                            }
                            db::mark(tx, table, &key, false, false).await?;
                            let fact = db::fact(
                                tx.tenant_id(),
                                &s.actors.backend,
                                &t.candidate,
                                "software_call",
                                db::call_fact(t, table, generation, "start_call", "attempted"),
                                &db::encode(&(t, generation))?,
                            )?;
                            s.audit_store
                                .append_in(tx, &fact, false)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            let key = if matches!(table, Table::Publish) {
                                t.key()
                            } else {
                                t.withdrawal_key()
                            };
                            let call = db::call(tx, table, &key).await?.ok_or_else(db::fault)?;
                            if !call.attempted {
                                return Err(db::fault());
                            }
                            db::mark(tx, table, &key, true, false).await?;
                            let fact = db::fact(
                                tx.tenant_id(),
                                &s.actors.backend,
                                &t.candidate,
                                "software_call",
                                db::call_fact(
                                    t,
                                    table,
                                    call.generation,
                                    "acknowledge",
                                    "acknowledged",
                                ),
                                &db::encode(&(t, call.generation))?,
                            )?;
                            s.audit_store
                                .append_in(tx, &fact, call.acknowledged)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
            Driver::Winget { .. } => Err(Error::Unsupported),
            Driver::Brew { repo, tap, .. } => self.write_brew(repo, tap, t, s, remove).await,
        }
    }
    async fn write_brew(
        &self,
        repo: &brew::Repository,
        tap: &str,
        t: &Target,
        s: &db::Subject,
        remove: bool,
    ) -> Result<WriteObservation> {
        let ExportDocument::Brew { recipe } = &s.document else {
            return Err(Error::Content);
        };
        if remove {
            let snapshot = brew::CommitId::parse(t.snapshot.as_deref().ok_or(Error::Content)?)
                .map_err(|_| Error::Content)?;
            repo.withdraw_snapshot(&snapshot)
                .await
                .map_err(|cause| Error::Source.context("driver::withdraw_snapshot", cause))?;
            return Ok(WriteObservation::Acknowledged);
        }
        let base = t
            .base
            .as_deref()
            .map(brew::CommitId::parse)
            .transpose()
            .map_err(|_| Error::Content)?;
        let at = Timepoint::try_from(t.commit_at).map_err(|_| Error::Content)?;
        let prepared = repo
            .prepare_snapshot(
                base,
                recipe.documents(self.tenant(), tap)?,
                &operation(t),
                at,
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
            Driver::Winget { .. } => Err(Error::Unsupported),
            Driver::Brew { repo, tap, .. } => {
                let ExportDocument::Brew { recipe } = &s.document else {
                    return Err(Error::Content);
                };
                let target = brew::CommitId::parse(t.snapshot.as_deref().ok_or(Error::Content)?)
                    .map_err(|_| Error::Content)?;
                let present = repo
                    .snapshot_exists(&target)
                    .await
                    .map_err(|cause| Error::Source.context("driver::inspect_snapshot", cause))?;
                if remove {
                    return Ok(!present);
                }
                if !present {
                    return Ok(false);
                }
                for document in recipe.documents(self.tenant(), tap)? {
                    if repo
                        .presence(&target, &document)
                        .await
                        .map_err(|cause| Error::Source.context("driver::inspect_snapshot", cause))?
                        != brew::DocumentPresence::Matching
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
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
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            tx.prepare_outbox_partitions(&[s.releases.partition(&t.candidate)?])
                                .await?;
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
                            let mut request = input!(db::record_request(
                                &c,
                                t,
                                &s.actors.backend,
                                result.clone(),
                                at
                            ));
                            let old = db::required(
                                "driver::record_result",
                                s.releases.operation_in(tx, &request.id).await?,
                            )?;
                            let replayed = old.is_some();
                            if let Some(old) = old {
                                request.expected_revision =
                                    old.transition.ok_or_else(db::fault)?.before_revision;
                            } else {
                                if matches!(
                                    current.outcome,
                                    rel::PublicationOutcome::Reported(
                                        rel::PublicationResult::Applied(_)
                                            | rel::PublicationResult::NotApplied(_)
                                    )
                                ) {
                                    let rel::PublicationOutcome::Reported(result) =
                                        &current.outcome
                                    else {
                                        unreachable!()
                                    };
                                    s.recover_record_in(tx, &c, t, result).await?;
                                    return Ok(Ok(current.outcome));
                                }
                                if matches!(observed, Observation::Applied) {
                                    let subject = db::subject(tx, &t.candidate)
                                        .await?
                                        .ok_or_else(db::fault)?;
                                    input!(s.resource_usable(tx, &subject).await?);
                                }
                                let slot = db::slot(tx, &t.binding, &t.slot).await?;
                                if slot.operation.as_deref() != Some(&t.key()) {
                                    return Ok(Err(Error::Blocked));
                                }
                            }
                            db::required(
                                "driver::record_result",
                                s.releases.transition_in(tx, &id, &request).await?,
                            )?;
                            if !replayed && matches!(observed, Observation::Applied) {
                                db::project(tx, t, false).await?;
                                db::release_slot(tx, t, &t.key(), t.commit.clone()).await?;
                            }
                            let fact = db::fact(
                                tx.tenant_id(),
                                &s.actors.backend,
                                &t.candidate,
                                "software_result",
                                db::record_fact(&request, t, "record_result", observed.tag()),
                                &db::request_fingerprint(&t.candidate, &request)?,
                            )?;
                            s.audit_store
                                .append_in(tx, &fact, replayed)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
    ) -> Result<WithdrawalExecution> {
        let at = request.as_of;
        let r = request.core(&request.actor, rel::Operation::Quarantine);
        let replayed = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, id, &r),
                    |(s, id, r), tx| {
                        Box::pin(async move {
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            tx.prepare_outbox_partitions(&[s.releases.partition(id.value())?])
                                .await?;
                            let result =
                                input!(s.releases.transition_in(tx, id, r).await?.map_err(
                                    |cause| Error::Conflict.context("driver::withdraw", cause)
                                ));
                            {
                                let fact = db::fact(
                                    tx.tenant_id(),
                                    &r.actor,
                                    id.value(),
                                    "software_withdraw",
                                    db::request_fact(r.id.value(), Some(ring), "withdraw-request"),
                                    &db::encode(&(
                                        db::request_fingerprint(id.value(), r)?,
                                        ring as u8,
                                    ))?,
                                )?;
                                s.audit_store
                                    .append_in(
                                        tx,
                                        &fact,
                                        matches!(result, rel::Transition::Replayed(_)),
                                    )
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            }
                            Ok(Ok(matches!(result, rel::Transition::Replayed(_))))
                        })
                    },
                )
                .await,
        )?;
        let c = self
            .releases
            .get(id, budget(cutoff))
            .await?
            .ok_or(Error::Conflict)?;
        let rel::RingState::Publication(p) = c.snapshot().ring_state(ring) else {
            return Ok(WithdrawalExecution {
                outcome: Withdrawal::NotPublished,
                replayed,
            });
        };
        let replayed = replayed
            && self.withdrawal_status(p.id(), p.attempt, cutoff).await?
                == Some(Withdrawal::Complete);
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
        let outcome = self.drive_withdrawal(p.id(), p.attempt, cutoff).await?;
        Ok(WithdrawalExecution { outcome, replayed })
    }
    #[tracing::instrument(skip_all, fields(tenant = %self.tenant(), publication = %hex(&id.digest().bytes()), attempt))]
    pub async fn reconcile_withdrawal(
        &self,
        id: rel::PublicationId,
        attempt: u64,
        cutoff: Deadline,
    ) -> Result<Withdrawal> {
        self.drive_withdrawal(id, attempt, cutoff).await
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
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
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
                                ) => withdrawal_progress(&call),
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
                        s.audit_store
                            .lock_in(tx)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                        db::lock(tx, "withdrawal", &t.withdrawal_key()).await?;
                        let replayed = db::call(tx, Table::Withdraw, &t.withdrawal_key())
                            .await?
                            .is_some();
                        if !replayed {
                            db::insert_call(tx, Table::Withdraw, t).await?;
                        }
                        {
                            let fact = db::fact(
                                tx.tenant_id(),
                                &s.actors.backend,
                                &t.candidate,
                                "software_withdraw",
                                db::target_fact(t, Table::Withdraw, "queue_withdrawal", "queued"),
                                &db::encode(t)?,
                            )?;
                            s.audit_store
                                .append_in(tx, &fact, replayed)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            tx.prepare_outbox_partitions(&[s.releases.partition(&t.candidate)?])
                                .await?;
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
                                let fact = db::fact(
                                    tx.tenant_id(),
                                    &s.actors.backend,
                                    &t.candidate,
                                    "software_result",
                                    db::record_fact(&r, t, "cancel_unstarted", "not-applied"),
                                    &db::request_fingerprint(&t.candidate, &r)?,
                                )?;
                                s.audit_store
                                    .append_in(tx, &fact, false)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
        if !call.prepared {
            if !self
                .prepare_withdrawal_bounded(&call.target, &subject, cutoff)
                .await?
            {
                return Ok(Withdrawal::Complete);
            }
            call = self.load_call(Table::Withdraw, &key, cutoff).await?;
        }
        if matches!(
            self.sources.binding(call.target.ring()?).driver,
            Driver::Winget { .. }
        ) {
            if !call.attempted {
                self.start_call(Table::Withdraw, &call.target, cutoff)
                    .await?;
            }
            self.finish_withdrawal(&call.target, cutoff).await?;
            return Ok(Withdrawal::Complete);
        }
        self.run_withdrawal_call(&call.target, &subject, cutoff)
            .await?;
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
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            let call = db::call(tx, Table::Withdraw, key)
                                .await?
                                .ok_or_else(db::fault)?;
                            db::complete_noop(tx, key).await?;
                            let fact = db::fact(
                                tx.tenant_id(),
                                &s.actors.backend,
                                &call.target.candidate,
                                "software_withdraw",
                                db::target_fact(
                                    &call.target,
                                    Table::Withdraw,
                                    "complete_unpublished",
                                    "applied",
                                ),
                                &db::encode(&call.target)?,
                            )?;
                            s.audit_store
                                .append_in(tx, &fact, call.complete)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
        self.start_call(Table::Withdraw, target, cutoff).await?;
        match tokio::time::timeout_at(
            cutoff.instant().into(),
            self.write_source(target, subject, true),
        )
        .await
        {
            Ok(Ok(WriteObservation::Acknowledged)) => {
                self.acknowledge(Table::Withdraw, target, cutoff).await?
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
        if matches!(
            self.sources.binding(call.target.ring()?).driver,
            Driver::Winget { .. }
        ) {
            if !call.attempted {
                return Ok(Withdrawal::PreflightRetryable);
            }
            self.finish_withdrawal(&call.target, cutoff).await?;
            return Ok(Withdrawal::Complete);
        }
        // Git revocation is resolved against the same immutable snapshot reference.
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
            Ok(withdrawal_progress(&call))
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
        _subject: &db::Subject,
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
                                s.audit_store
                                    .lock_in(tx)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                                input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                                db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                    .await?;
                                if db::projection(tx, t).await?.as_deref() == Some(&t.publication) {
                                    return Ok(Err(Error::Conflict));
                                }
                                let call = db::call(tx, Table::Withdraw, &t.withdrawal_key())
                                    .await?
                                    .ok_or_else(db::fault)?;
                                db::complete_noop(tx, &t.withdrawal_key()).await?;
                                let fact = db::fact(
                                    tx.tenant_id(),
                                    &s.actors.backend,
                                    &t.candidate,
                                    "software_withdraw",
                                    db::target_fact(
                                        t,
                                        Table::Withdraw,
                                        "prepare_withdrawal",
                                        "applied",
                                    ),
                                    &db::encode(t)?,
                                )?;
                                s.audit_store
                                    .append_in(tx, &fact, call.complete)
                                    .await
                                    .map_err(rss_transactional_messaging_postgres::PgError::from)?;
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
        if let Driver::Brew { repo, .. } = &self.sources.binding(t.ring()?).driver {
            if repo
                .head()
                .await
                .map_err(|cause| Error::Source.context("driver::prepare_withdrawal", cause))?
                .as_ref()
                .map(|c| c.as_str())
                != prepared.base.as_deref()
            {
                return Err(Error::Blocked);
            }
            // Revocation changes the immutable snapshot reference, not a later publication's main.
            prepared.commit = prepared.base.clone();
        }

        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, &prepared),
                    |(s, t), tx| {
                        Box::pin(async move {
                            s.audit_store
                                .lock_in(tx)
                                .await
                                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                            input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
                            db::lock(tx, "source", &format!("{}:{}", hex(&t.binding), t.slot))
                                .await?;
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
                    },
                )
                .await,
        )?;
        Ok(true)
    }
    async fn finish_withdrawal(&self, t: &Target, cutoff: Deadline) -> Result<()> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant(), budget(cutoff), (self, t), |(s, t), tx| {
                    Box::pin(async move {
                        s.audit_store
                            .lock_in(tx)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        input!(s.catalog.lock_in(tx).await.map_err(|_| Error::Content));
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
                        let fact = db::fact(
                            tx.tenant_id(),
                            &s.actors.backend,
                            &t.candidate,
                            "software_withdraw",
                            db::target_fact(t, Table::Withdraw, "finish_withdrawal", "applied"),
                            &db::encode(t)?,
                        )?;
                        s.audit_store
                            .append_in(tx, &fact, false)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )
    }
}
fn withdrawal_progress(call: &Call) -> Withdrawal {
    if call.complete {
        Withdrawal::Complete
    } else if !call.prepared || !call.attempted {
        Withdrawal::PreflightRetryable
    } else {
        Withdrawal::AwaitingConfirmation
    }
}
