use crate::{
    codec,
    event::ChangeKind,
    model::*,
    storage::{self as db, *},
    store::{GroupStore, core_rejection, dynamic, input},
};
use rss_contract::Timepoint;
use rss_mdm_group::{ObjectKey, Recalculation, Rule, Snapshot};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

pub(crate) fn run_digest(
    tenant: rss_request_context::TenantId,
    group: GroupId,
    base: i64,
    rule: &str,
    at: i64,
    trigger: &[u8],
    snapshot: &[u8],
) -> Vec<u8> {
    fingerprint(&[
        tenant.to_string().as_bytes(),
        group.to_string().as_bytes(),
        &base.to_be_bytes(),
        rule.as_bytes(),
        &at.to_be_bytes(),
        trigger,
        snapshot,
    ])
}
fn run(op: StoredOperation) -> Result<Run, PgError> {
    if op.kind != "recalculation" {
        return Err(stored_shape());
    }
    Ok(Run {
        id: op.id,
        group: op.group,
        state: op.state,
        trigger: data(codec::decode(&op.trigger.ok_or_else(stored_shape)?))?,
        as_of: data(Timepoint::try_from(op.as_of))?,
        duration_micros: op.duration,
    })
}
struct Prepared {
    op: StoredOperation,
    rule: Rule,
    snapshot: Snapshot,
    old: Vec<ObjectKey>,
}
enum Preparation {
    Ready(Box<Prepared>),
    Terminal(Box<Run>),
}
impl GroupStore {
    /// Validate and commit complete frozen input for later resume; replay requires identical input.
    /// This admits work but neither schedules nor evaluates it in a background worker.
    pub async fn start_recalculation(
        &self,
        r: &RecalculationRequest,
        deadline: OperationDeadline,
    ) -> Result<Run, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, (self, r), |ctx, tx| {
                    Box::pin(async move { ctx.0.start_recalculation_in(tx, ctx.1).await })
                })
                .await,
            Some(r.id),
        )
    }
    /// Persist immutable input only; scheduling and process ownership stay with the host.
    pub async fn start_recalculation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        r: &RecalculationRequest,
    ) -> InTransaction<Run> {
        input!(self.check_transaction(tx)?);
        if r.snapshot.tenant != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let g = db::group(tx, r.group, true).await?;
        let old = db::operation(tx, r.id, true).await?;
        if let Some(old) = &old {
            if old.group != r.group
                || old.kind != "recalculation"
                || old.base != r.expected.get()
                || old.rule_version.as_deref() != Some(&r.rule_version)
                || old.as_of != r.as_of.unix_seconds()
            {
                return Ok(Err(Rejection::IdentityConflict));
            }
        } else {
            let g = input!(g.ok_or(Rejection::NotFound));
            input!(dynamic(&g, r.expected));
            if g.rule_version.as_deref() != Some(&r.rule_version) {
                return Ok(Err(Rejection::VersionConflict));
            }
        }
        let rule = db::rule(tx, r.group, r.rule_version.clone()).await?;
        // Validate every original object/fact BEFORE cloning or serializing it.
        // Replays use their immutable original rule even after a current-rule change.
        input!(
            rule.recalculate(&r.snapshot, r.as_of, &[])
                .map_err(core_rejection)
        );
        let valid_trigger = match &r.trigger {
            Trigger::Manual => true,
            Trigger::Periodic { slot } => trigger_text(slot),
            Trigger::Change { source, event } => trigger_text(source) && trigger_text(event),
        };
        if !valid_trigger {
            return Ok(Err(Rejection::InvalidInput));
        }
        let snapshot =
            input!(codec::encode_snapshot(&r.snapshot).map_err(|_| Rejection::InvalidInput));
        let trigger = input!(codec::encode(&r.trigger).map_err(|_| Rejection::InvalidInput));
        if trigger.len() > 16384 {
            return Ok(Err(Rejection::InvalidInput));
        }
        let hash = run_digest(
            self.tenant,
            r.group,
            r.expected.get(),
            &r.rule_version,
            r.as_of.unix_seconds(),
            &trigger,
            &snapshot,
        );
        if let Some(old) = old {
            if old.digest != hash {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return Ok(Ok(run(old)?));
        }
        db::insert_operation(
            tx,
            NewOperation {
                id: r.id,
                group: r.group,
                digest: hash,
                request: snapshot,
                trigger: Some(trigger),
                base: r.expected.get(),
                rule_version: Some(r.rule_version.clone()),
                as_of: r.as_of.unix_seconds(),
                receipt: None,
            },
        )
        .await?;
        Ok(Ok(run(db::operation(tx, r.id, false)
            .await?
            .ok_or_else(stored_shape)?)?))
    }
    /// Read run state/provenance; missing, command or foreign-tenant identities return None.
    pub async fn get_run(
        &self,
        id: OperationId,
        deadline: OperationDeadline,
    ) -> Result<Option<Run>, Error> {
        settle(
            self.runtime
                .local_tx(self.tenant, deadline, move |tx| {
                    Box::pin(async move {
                        let op = db::operation(tx, id, false).await?;
                        match op {
                            Some(op) if op.kind == "recalculation" => Ok(Ok(Some(run(op)?))),
                            _ => Ok(Ok(None)),
                        }
                    })
                })
                .await,
            Some(id),
        )
    }
    /// Ordered work discovery; no claim/lease, automatic retry, or scheduler.
    /// Limit is 1..=1000; after is an exclusive UUID cursor. Concurrent admissions with
    /// lower UUIDs require a later scan from None; this is not a stable queue watermark.
    pub async fn recoverable(
        &self,
        after: Option<OperationId>,
        limit: usize,
        deadline: OperationDeadline,
    ) -> Result<Vec<OperationId>, Error> {
        if !(1..=1000).contains(&limit) {
            return Err(Rejection::InvalidInput.into());
        }
        settle(self.runtime.local_tx(self.tenant,deadline,move |tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            let rows=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_group.operations WHERE tenant_id=$1::uuid AND state='pending' AND ($2::uuid IS NULL OR id>$2::uuid) ORDER BY id LIMIT $3")
                .bind(tenant).bind(after.map(|id|id.to_string())).bind(limit as i64).fetch_all(c).await
            })).await?;
            Ok(Ok(rows.iter().map(|s|data(OperationId::parse(s))).collect::<Result<_,_>>()?))
        })).await,None)
    }
    /// Resume durable input without caller facts, or return a terminal run unchanged.
    /// Reads base members under the group lock, evaluates outside SQL, then applies under CAS.
    /// An intervening revision or deletion persists a terminal rejection; concurrent resumes
    /// return the one durable result. Transient or unknown outcomes retain the original identity.
    pub async fn resume(&self, id: OperationId, deadline: OperationDeadline) -> Result<Run, Error> {
        let prepared = settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, self, move |store, tx| {
                    Box::pin(async move { store.prepare_in(tx, id).await })
                })
                .await,
            Some(id),
        )?;
        let Preparation::Ready(prepared) = prepared else {
            let Preparation::Terminal(run) = prepared else {
                unreachable!()
            };
            return Ok(*run);
        };
        let calculated = prepared
            .rule
            .recalculate(
                &prepared.snapshot,
                data_time(prepared.op.as_of)?,
                &prepared.old,
            )
            .map_err(core_rejection);
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant,
                    deadline,
                    (self, &prepared, &calculated),
                    move |ctx, tx| Box::pin(async move { ctx.0.finish_in(tx, ctx.1, ctx.2).await }),
                )
                .await,
            Some(id),
        )
    }
    /// Complete a bounded recalculation in the caller transaction, retaining the
    /// runtime/tenant check and group-before-operation lock order. This enables
    /// product input validation and success audit to commit with member changes.
    pub async fn resume_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<Run> {
        let prepared = input!(self.prepare_in(tx, id).await?);
        match prepared {
            Preparation::Terminal(run) => Ok(Ok(*run)),
            Preparation::Ready(prepared) => {
                let calculated = prepared
                    .rule
                    .recalculate(
                        &prepared.snapshot,
                        data(Timepoint::try_from(prepared.op.as_of))?,
                        &prepared.old,
                    )
                    .map_err(core_rejection);
                self.finish_in(tx, &prepared, &calculated).await
            }
        }
    }

    async fn prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<Preparation> {
        input!(self.check_transaction(tx)?);
        // Nonlocking discovery only. Every actual lock is group -> operation.
        let discovered = input!(
            db::operation(tx, id, false)
                .await?
                .ok_or(Rejection::NotFound)
        );
        if discovered.kind != "recalculation" {
            return Ok(Err(Rejection::NotFound));
        }
        let g = db::group(tx, discovered.group, true)
            .await?
            .ok_or_else(stored_shape)?;
        let op = db::operation(tx, id, true)
            .await?
            .ok_or_else(stored_shape)?;
        if !matches!(op.state, RunState::Pending) {
            return Ok(Ok(Preparation::Terminal(Box::new(run(op)?))));
        }
        if let Err(reason) = dynamic(&g, data(Revision::new(op.base))?) {
            db::complete(tx, id, &RunState::Rejected(reason), None).await?;
            return Ok(Ok(Preparation::Terminal(Box::new(run(db::operation(
                tx, id, false,
            )
            .await?
            .ok_or_else(stored_shape)?)?))));
        }
        let version = op.rule_version.as_ref().ok_or_else(stored_shape)?;
        if g.rule_version.as_ref() != Some(version) {
            return Err(stored_shape());
        }
        let hash = run_digest(
            self.tenant,
            op.group,
            op.base,
            version,
            op.as_of,
            op.trigger.as_ref().ok_or_else(stored_shape)?,
            &op.request,
        );
        if hash != op.digest {
            return Err(StorageFault::DocumentDigest.error());
        }
        let snapshot = data(codec::decode_snapshot(&op.request))?;
        if snapshot.tenant != self.tenant {
            return Err(stored_shape());
        }
        let rule = db::rule(tx, op.group, version.clone()).await?;
        let old = db::members(tx, op.group).await?;
        if old.len() != g.member_count {
            return Err(StorageFault::RowCount.error());
        }
        Ok(Ok(Preparation::Ready(Box::new(Prepared {
            op,
            rule,
            snapshot,
            old,
        }))))
    }
    async fn finish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &Prepared,
        result: &CommandOutcome<Recalculation>,
    ) -> InTransaction<Run> {
        let mut g = db::group(tx, p.op.group, true)
            .await?
            .ok_or_else(stored_shape)?;
        let current = db::operation(tx, p.op.id, true)
            .await?
            .ok_or_else(stored_shape)?;
        if !matches!(current.state, RunState::Pending) {
            return Ok(Ok(run(current)?));
        }
        let failure = dynamic(&g, data(Revision::new(p.op.base))?)
            .err()
            .or_else(|| result.as_ref().err().copied());
        if let Some(code) = failure {
            db::complete(tx, p.op.id, &RunState::Rejected(code), None).await?;
        } else {
            if g.rule_version != p.op.rule_version || current.digest != p.op.digest {
                return Err(stored_shape());
            }
            let calculated = result.as_ref().map_err(|_| stored_shape())?;
            let difference = &calculated.difference;
            let changed = !difference.added.is_empty() || !difference.removed.is_empty();
            let revision = match g.revision.next() {
                Ok(v) => v,
                Err(reason) => {
                    db::complete(tx, p.op.id, &RunState::Rejected(reason), None).await?;
                    return Ok(Ok(run(db::operation(tx, p.op.id, false)
                        .await?
                        .ok_or_else(stored_shape)?)?));
                }
            };
            g.revision = revision;
            if changed {
                g.member_version = revision.get();
            }
            g.member_count = difference.added.len() + difference.unchanged.len();
            let receipt = Receipt {
                operation: p.op.id,
                group: g,
                added: difference.added.len(),
                removed: difference.removed.len(),
            };
            if changed {
                self.append(
                    tx,
                    data(Timepoint::try_from(p.op.as_of))?,
                    ChangeKind::MembersChanged,
                    &receipt,
                )
                .await?;
            }
            db::save_group(tx, &receipt.group, false).await?;
            db::apply_delta(
                tx,
                p.op.group,
                p.op.id,
                &difference.added,
                &difference.removed,
            )
            .await?;
            db::complete(
                tx,
                p.op.id,
                &RunState::Completed(receipt),
                Some(data(codec::encode_result(calculated))?),
            )
            .await?;
        }
        Ok(Ok(run(db::operation(tx, p.op.id, false)
            .await?
            .ok_or_else(stored_shape)?)?))
    }
    /// Load historical decisions and explanations without running the current evaluator.
    pub async fn result(
        &self,
        id: OperationId,
        deadline: OperationDeadline,
    ) -> Result<Option<Recalculation>, Error> {
        settle(
            self.runtime
                .local_tx(self.tenant, deadline, move |tx| {
                    Box::pin(async move {
                        let op = input!(
                            db::operation(tx, id, false)
                                .await?
                                .ok_or(Rejection::NotFound)
                        );
                        if op.kind != "recalculation" {
                            return Ok(Err(Rejection::NotFound));
                        }
                        let Some(bytes) = op.result else {
                            return Ok(Ok(None));
                        };
                        let rule =
                            db::rule(tx, op.group, op.rule_version.ok_or_else(stored_shape)?)
                                .await?;
                        let snapshot = data(codec::decode_snapshot(&op.request))?;
                        Ok(Ok(Some(data(codec::decode_result(
                            &bytes,
                            &rule,
                            &snapshot,
                            data(Timepoint::try_from(op.as_of))?,
                        ))?)))
                    })
                })
                .await,
            Some(id),
        )
    }
}
fn data_time(t: i64) -> Result<Timepoint, Error> {
    Timepoint::try_from(t).map_err(|_| Rejection::InvalidStoredDocument.into())
}

fn trigger_text(s: &str) -> bool {
    !s.trim().is_empty()
        && s.len() <= rss_mdm_group::limits::STRING_BYTES
        && !s.chars().any(char::is_control)
}
