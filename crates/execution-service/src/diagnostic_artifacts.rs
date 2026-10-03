//! Three phase diagnostic materialization: claim-fenced snapshot, external content I/O,
//! claim-fenced immutable association. No file work belongs to a PG transaction.
//! ref: sqlx transaction.rs@003b698e99e024f3621b8043a2426fde5b741171;
//! Tokio blocking.rs@75fef53d0a8590c2d1dbb63672aa7b7d1ef51155 (started work cannot abort).
use crate::native::diagnostic::{State, Transfer};
use crate::*;
use rss_mdm_audit_integration::Fact;
use rss_mdm_content_service::{Verified, diagnostic::Identity};
use rss_mdm_windows_mdm::native::diagnostic::Step;
use sha2::{Digest as _, Sha256};
use sqlx::Row;
struct Block {
    attempt: Uuid,
    command: i64,
    item: i32,
    value: Vec<u8>,
}
#[derive(Clone, Copy)]
enum Publication<'a> {
    Ready(&'a Snapshot, &'a Verified),
    Failed(&'a Snapshot, &'static str),
}
impl Publication<'_> {
    fn snapshot(&self) -> &Snapshot {
        match self {
            Self::Ready(s, _) | Self::Failed(s, _) => s,
        }
    }
}
struct Snapshot {
    identity: Identity,
    blocks: Vec<Block>,
    length: u64,
    deadline: i64,
    prepared_at: i64,
}
fn content(error: rss_mdm_content_service::Error) -> Fault {
    Error::from(error).into()
}
impl ExecutionService {
    pub(crate) async fn materialize_diagnostics<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), Error> {
        let Some(store) = &self.content else {
            return Ok(());
        };
        let audit = RequestAudit::new(self.tenant.to_string(), "command_diagnostic_store");
        audit.identify_service("command-recovery");
        let result = async {
            let Some(snapshot) = self.diagnostic_tx(claim, control, None, &audit).await? else {
                return Ok(());
            };
            let bytes = match assemble(&self.protection, self.tenant, &snapshot) {
                Ok(v) => v,
                Err(_) => {
                    self.diagnostic_tx(
                        claim,
                        control,
                        Some(Publication::Failed(
                            &snapshot,
                            "diagnostic_source_integrity",
                        )),
                        &audit,
                    )
                    .await?;
                    return Ok(());
                }
            };
            control
                .check()
                .map_err(|_| Error::Unavailable(Failure::ContentDeadline))?;
            let now = snapshot.prepared_at;
            let remaining = snapshot
                .deadline
                .min(snapshot.identity.expires_at)
                .saturating_sub(now);
            if remaining <= 0 {
                return Ok(());
            }
            // One absolute budget covers begin/resume/append/finish/verify, including permit waits.
            // A dropped spawn_blocking may leave orphan content; only the fenced third phase associates it.
            let publication = tokio::time::timeout(
                control
                    .remaining()
                    .min(Duration::from_secs(remaining as u64)),
                store.promote_diagnostic(&snapshot.identity, &bytes, now),
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::ContentDeadline))?;
            let verified = match publication {
                Ok(v) => v,
                Err(
                    rss_mdm_content_service::Error::Invariant
                    | rss_mdm_content_service::Error::Metadata
                    | rss_mdm_content_service::Error::Malformed,
                ) => {
                    self.diagnostic_tx(
                        claim,
                        control,
                        Some(Publication::Failed(
                            &snapshot,
                            "diagnostic_content_integrity",
                        )),
                        &audit,
                    )
                    .await?;
                    return Ok(());
                }
                Err(e) => return Err(Error::from(e)),
            };
            #[cfg(feature = "integration")]
            if let Some(fault) = self
                .diagnostic_commit_fault
                .lock()
                .expect("diagnostic fault")
                .take()
            {
                self.runtime.inject_next_transaction_fault(fault);
            }
            self.diagnostic_tx(
                claim,
                control,
                Some(Publication::Ready(&snapshot, &verified)),
                &audit,
            )
            .await?;
            // The Verified pin remains alive until local_tx reports its commit/rollback outcome.
            drop(verified);
            Ok(())
        }
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
    async fn diagnostic_tx<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
        publication: Option<Publication<'_>>,
        audit: &RequestAudit,
    ) -> std::result::Result<Option<Snapshot>, Error> {
        control.check().map_err(|_| Error::Conflict)?;
        // Each PG phase owns one settlement. The orchestration audit never inherits
        // a prior phase's Committed state, while request coordinates stay shared.
        let transaction_audit = audit.transaction_copy();
        let audit = &transaction_audit;
        let error = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (
                    self,
                    claim,
                    (self, claim.target().entity(), publication, audit, &error),
                ),
                |(service, claim, context), tx| {
                    Box::pin(async move {
                        if let Err(e) = service.audit_store.lock_in(tx).await {
                            return Err(rejection(Error::from(e).into(), context.4));
                        }
                        rss_reconcile_postgres::messaging::protect_in(
                            tx,
                            claim,
                            context,
                            |ctx, tx| {
                                Box::pin(async move {
                                    let (service, entity, publication, audit, error) = *ctx;
                                    match advance(service, tx, entity, *publication, audit).await {
                                        Ok(value) => {
                                            audit.mark_commit_started();
                                            Ok(value)
                                        }
                                        Err(e) => Err(rejection(e, error)),
                                    }
                                })
                            },
                        )
                        .await
                    })
                },
            )
            .await;
        let result = settle(attempt, audit, error);
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
async fn advance(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    publication: Option<Publication<'_>>,
    audit: &RequestAudit,
) -> Result<Option<Snapshot>> {
    storage::admit(tx).await?;
    let tenant = service.tenant;
    let mut after = Uuid::nil();
    loop {
        let entity = entity.to_owned();
        let target = publication.map(|v| v.snapshot().identity.operation);
        // Snapshot discovery advances through waiting requests. Association always targets
        // its original operation, even when new lower UUIDs arrive during file work.
        let ids=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND encode(sha256(convert_to(o.device,'UTF8')),'hex')=$2 AND o.diagnostic_progress->>'transfer'='pending' AND (($3::uuid IS NOT NULL AND o.id=$3) OR ($3::uuid IS NULL AND o.id>$4)) ORDER BY o.id LIMIT 64")
                .bind(tenant.to_string()).bind(entity).bind(target).bind(after).fetch_all(c).await
        })).await?;
        if ids.is_empty() {
            return Ok(None);
        }
        for id in ids {
            after = id;
            let op = storage::load(tx, &service.protection, id).await?;
            storage::lock(tx, &op.device).await?;
            let mut state = tx
                .with_connection(move |c| {
                    Box::pin(async move { Ok(native::diagnostic::load(c, tenant, id).await) })
                })
                .await??;
            if !state.pending() {
                continue;
            }
            let command = service.required_command(tx, &op).await?;
            let now = storage::now(tx).await?;
            let eligible = matches!(
                command.status(),
                dc::Status::Queued
                    | dc::Status::Published
                    | dc::Status::Received
                    | dc::Status::Applied
            ) && now < op.request.deadline
                && state.expires_at.is_none_or(|expiry| expiry > now)
                && storage::approval_valid(&service.source, &service.protection, tx, &op, now)
                    .await?;
            if !eligible {
                state.transfer = Transfer::Abandoned;
                state.reason = Some("diagnostic_no_longer_eligible".into());
                save(tx, tenant, id, &state).await?;
                fact(service, tx, audit, &op, &state, false).await?;
                continue;
            }
            if state.native.step != Step::Complete || command.status() != dc::Status::Applied {
                continue;
            }
            let snapshot = match snapshot(service, tx, &op, &state, now).await {
                Ok(v) => v,
                Err(Fault::Request(Error::Unavailable(Failure::NativeInputIntegrity))) => {
                    state.transfer = Transfer::Blocked;
                    state.reason = Some("diagnostic_source_integrity".into());
                    save(tx, tenant, id, &state).await?;
                    fact(service, tx, audit, &op, &state, false).await?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if let Some(publication) = publication {
                let expected = publication.snapshot();
                if snapshot.identity != expected.identity || snapshot.length != expected.length {
                    return Err(Error::Conflict.into());
                }
                if let Publication::Failed(_, reason) = publication {
                    state.transfer = Transfer::Blocked;
                    state.reason = Some(reason.into());
                    save(tx, tenant, id, &state).await?;
                    fact(service, tx, audit, &op, &state, false).await?;
                    return Ok(None);
                }
                let Publication::Ready(_, verified) = publication else {
                    unreachable!("failure settled above")
                };
                let identity = snapshot.identity.clone();
                let artifact = verified.artifact.clone();
                let (_, fresh) = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(rss_mdm_content_service::diagnostic::record_in(
                                c, tenant, &identity, &artifact,
                            )
                            .await)
                        })
                    })
                    .await?
                    .map_err(content)?;
                state.transfer = Transfer::Ready;
                state.reason = None;
                save(tx, tenant, id, &state).await?;
                fact(service, tx, audit, &op, &state, !fresh).await?;
                return Ok(None);
            }
            return Ok(Some(snapshot));
        }
        if publication.is_some() {
            return Ok(None);
        }
    }
}
async fn save(tx: &mut PgTransaction<'_>, tenant: TenantId, id: Uuid, state: &State) -> Result<()> {
    let state = state.clone();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(native::diagnostic::save(c, tenant, id, &state).await) })
    })
    .await??;
    Ok(())
}
async fn fact(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    audit: &RequestAudit,
    op: &storage::Operation,
    state: &State,
    replayed: bool,
) -> Result<()> {
    let a = audit.transaction_copy();
    a.operation(op.id, "command_diagnostic_store");
    a.target(&op.device);
    a.registration(op.registration);
    let details = serde_json::json!({"transfer":state.transfer,"reason":state.reason,"length":state.native.length,"expiresAt":state.expires_at});
    let bytes = checked_input(serde_json::to_vec(&details))?;
    let fact = Fact::business(
        &a,
        &format!("command:{}:diagnostic:{:?}", op.id, state.transfer),
        &bytes,
        200,
        "success",
        None,
    )?
    .with_details(details)?;
    a.finalize(None);
    service.audit_store.append_in(tx, &fact, replayed).await?;
    Ok(())
}
async fn snapshot(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
    state: &State,
    prepared_at: i64,
) -> Result<Snapshot> {
    let tenant = service.tenant;
    let id = op.id;
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT DISTINCT ON((a.diagnostic_step->>'index')::int) (a.diagnostic_step->>'index')::int AS block_index,a.id,a.ordinal,i.command,i.item_ordinal,i.value FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND a.diagnostic_step->>'kind'='block' AND i.kind='get' AND i.uri LIKE '%/BlockData' AND i.result_accepted AND i.receipt_accepted AND NOT EXISTS(SELECT 1 FROM mdm_commands.attempt_items e WHERE e.tenant_id=a.tenant_id AND e.attempt=a.id AND (NOT coalesce(e.receipt_accepted,false) OR (e.status IS NULL OR e.status NOT IN(200,214)) OR (e.kind='get' AND NOT coalesce(e.result_accepted,false)))) ORDER BY (a.diagnostic_step->>'index')::int,a.ordinal")
            .bind(tenant.to_string()).bind(id).fetch_all(c).await
    })).await?;
    if rows.len()
        != state
            .native
            .count
            .ok_or(Error::Unavailable(Failure::CommandInvariant))? as usize
    {
        return Err(Error::Unavailable(Failure::NativeInputIntegrity).into());
    }
    let mut digest = Sha256::new();
    let mut blocks = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        if row.try_get::<i32, _>("block_index")? != index as i32 {
            return Err(Error::Unavailable(Failure::NativeInputIntegrity).into());
        }
        let block = Block {
            attempt: row.try_get("id")?,
            command: row.try_get("command")?,
            item: row.try_get("item_ordinal")?,
            value: row.try_get("value")?,
        };
        digest.update(checked_input(serde_json::to_vec(&(
            index,
            block.attempt,
            block.command,
            block.item,
            &block.value,
        )))?);
        blocks.push(block);
    }
    Ok(Snapshot {
        identity: Identity {
            operation: id,
            registration: op.registration,
            generation: op.registration_generation,
            input_version: op.request.input_version.clone(),
            input_digest: *op
                .request
                .digest(&service.protection, tenant, &op.device)?
                .as_bytes(),
            sources_digest: digest.finalize().into(),
            accepted_at: state
                .accepted_at
                .ok_or(Error::Unavailable(Failure::CommandInvariant))?,
            expires_at: state
                .expires_at
                .ok_or(Error::Unavailable(Failure::CommandInvariant))?,
        },
        blocks,
        length: state.native.length,
        deadline: op.request.deadline,
        prepared_at,
    })
}

fn assemble(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    snapshot: &Snapshot,
) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(snapshot.length as usize));
    for block in &snapshot.blocks {
        let aad = native::result_aad(
            tenant,
            snapshot.identity.registration,
            snapshot.identity.generation,
            block.attempt,
            block.command,
            block.item,
        )?;
        let plain = protection
            .open_bytes(&block.value, &aad)
            .map_err(|_| Error::Unavailable(Failure::NativeInputIntegrity))?;
        use base64::Engine;
        let decoded = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(plain.expose())
                .map_err(|_| Error::Unavailable(Failure::NativeInputIntegrity))?,
        );
        bytes.extend_from_slice(&decoded);
        if bytes.len() as u64 > snapshot.length {
            return Err(Error::Unavailable(Failure::NativeInputIntegrity));
        }
    }
    if bytes.len() as u64 != snapshot.length {
        return Err(Error::Unavailable(Failure::NativeInputIntegrity));
    }
    Ok(bytes)
}
