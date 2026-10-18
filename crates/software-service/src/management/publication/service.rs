use super::{
    model::{Change, Query},
    wire,
};
use crate::{
    catalog::Operation,
    management::{Error, Failure, transaction::checked_input},
    publication as service,
};
use rss_contract::Timepoint;
use rss_mdm_audit_integration::{ManagementResult as Effect, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_software_release as rel;
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging_postgres::PgRuntime;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
fn failure(e: service::Error) -> Error {
    match e {
        service::Error::Diagnostic { category, .. } => failure(*category),
        service::Error::Unsupported => Error::Unsupported,
        service::Error::Input
        | service::Error::Content
        | service::Error::ArtifactAddress
        | service::Error::ArtifactBudget
        | service::Error::ArtifactDigest => Error::Malformed,
        service::Error::PublicationNotFound => {
            Error::Publication(super::error::PublicationError::MissingPublication)
        }
        service::Error::Identity => Error::Forbidden,
        service::Error::Conflict | service::Error::Blocked => Error::Conflict,
        service::Error::CommitUnknown(_) => Error::CommitUnknown,
        service::Error::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Unavailable(Failure::Runtime),
    }
}
fn cutoff() -> Deadline {
    Deadline::from_timeout(
        &rss_mdm_audit_integration::budget::RuntimeTimer,
        Duration::from_secs(6),
    )
    .expect("constant budget")
}
async fn authorize(
    store: &rss_mdm_authorization_service::Store,
    proof: &AuthorizedPrincipal,
    permission: Permission,
) -> Result<(), Error> {
    proof.manage(permission)?;
    let current =
        rss_mdm_authorization_service::store::authorization_snapshot(store, proof).await?;
    current.require(proof, permission, None)?;
    proof.check_live()?;
    Ok(())
}
pub async fn read(
    directory: &PublicationDirectory,
    authorization: &rss_mdm_authorization_service::Store,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
) -> Result<wire::Publication, Error> {
    authorize(authorization, proof, Permission::ReleaseRead).await?;
    audit.set_action("management_read");
    audit.target(&id);
    let view = read_view(directory, id, true).await?;
    authorize(authorization, proof, Permission::ReleaseRead).await?;
    Ok(view)
}
async fn read_view(
    directory: &PublicationDirectory,
    id: String,
    include_document: bool,
) -> Result<wire::Publication, Error> {
    let (target, resource, version) = directory.coordinate(&id).await?;
    let service = directory.services.get(&target).ok_or(Error::Publication(
        super::error::PublicationError::MissingSource,
    ))?;
    let key = rel::PublicationKey::new(directory.tenant, &id).map_err(|_| Error::Malformed)?;
    let record = service
        .record(&key, cutoff())
        .await
        .map_err(failure)?
        .ok_or(Error::Publication(
            super::error::PublicationError::MissingPublication,
        ))?;
    let snapshot = record.snapshot();
    let p = &snapshot.attempt;
    if p.binding.target.value() != target {
        return Err(Error::Conflict);
    }
    let withdrawal = service
        .withdrawal_status(p.id(), p.attempt, cutoff())
        .await
        .map_err(failure)?
        .map(|w| {
            match w {
                service::Withdrawal::Complete => "withdrawn",
                service::Withdrawal::NotPublished => "not_published",
                service::Withdrawal::WaitingPublication => "waiting_publication",
                service::Withdrawal::PreflightRetryable => "preflight_retryable",
                service::Withdrawal::AwaitingConfirmation => "unknown",
            }
            .to_owned()
        });
    let document = if include_document {
        Some(service.document(&key, cutoff()).await.map_err(failure)?)
    } else {
        None
    };
    Ok(wire::Publication {
        id,
        revision: snapshot.revision,
        target,
        resource,
        version,
        publication: p.id().digest().bytes(),
        content_digest: snapshot.content.digest().bytes(),
        manifest_digest: snapshot.content.manifest().bytes(),
        target_digest: p.binding.target_digest.bytes(),
        attempt: p.attempt,
        outcome: match p.outcome {
            rel::PublicationOutcome::Pending => "pending",
            rel::PublicationOutcome::Reported(rel::PublicationResult::Unknown(_)) => "unknown",
            rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_)) => {
                "not_applied"
            }
            rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_)) => "published",
        }
        .into(),
        withdrawn: snapshot.withdrawn || withdrawal.is_some(),
        withdrawal,
        document,
    })
}
pub async fn write(
    directory: &PublicationDirectory,
    authorization: &rss_mdm_authorization_service::Store,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    path_id: Option<String>,
    request: Operation<Change>,
) -> Result<wire::Publication, Error> {
    let permission = match request.input {
        Change::Publish { .. } => Permission::ReleasePublish,
        Change::Recover | Change::Retry => Permission::ReleaseRecover,
        Change::Withdraw => Permission::ReleaseWithdraw,
    };
    authorize(authorization, proof, permission).await?;
    let (id, target) = match (&request.input, path_id) {
        (Change::Publish { target, .. }, None) if request.expected_revision == 0 => {
            (request.operation_id.to_string(), target.clone())
        }
        (Change::Publish { .. }, _) => return Err(Error::Malformed),
        (_, Some(id)) => {
            let (target, _, _) = directory.coordinate(&id).await?;
            (id, target)
        }
        _ => return Err(Error::Malformed),
    };
    let service = directory.services.get(&target).ok_or(Error::Publication(
        super::error::PublicationError::MissingSource,
    ))?;
    let key = rel::PublicationKey::new(directory.tenant, &id).map_err(|_| Error::Malformed)?;
    let actor = rel::ActorId::new(
        directory.tenant,
        json!([proof.instance_id(), proof.principal_id()]).to_string(),
    )
    .map_err(|_| Error::Malformed)?;
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(request.operation_id, "management_write");
    let intent_audit = audit.transaction_copy();
    intent_audit.set_action("software_preflight");
    intent_audit.software(rss_mdm_audit_integration::SoftwareFact {
        operation: request.operation_id.to_string(),
        publication: None,
        attempt: None,
        binding: Some(target.clone()),
        stage: "management_admission",
        outcome: "accepted",
    });
    let intent = directory
        .authorize_intent(&target, &id, &request, &intent_audit, proof, permission)
        .await;
    intent_audit.finalize(intent.as_ref().err().and_then(|e| {
        e.is_audit_transaction_failure()
            .then_some(rss_mdm_audit_integration::FailureReason::Transaction)
    }));
    let (intent, replayed) = intent?;
    let at = Timepoint::try_from(intent["as_of"].as_i64().ok_or(Error::Conflict)?)
        .map_err(|_| Error::Conflict)?;
    let call = service::ServiceRequest {
        actor: actor.clone(),
        id: rel::RequestId::new(directory.tenant, request.operation_id.to_string())
            .map_err(|_| Error::Malformed)?,
        expected_revision: request.expected_revision,
        as_of: at,
    };
    let access = service::ManagementAccess { proof, permission };
    audit.require_request_settlement();
    audit.mark_commit_started();
    let result: Result<Effect, Error> = async {
        match &request.input {
            Change::Publish {
                resource,
                version,
                expected_resource_revision,
                resource_digest,
                target_digest,
                ..
            } => {
                let (_, replayed) = service
                    .submit(
                        &service::PublishInput {
                            actor,
                            record: key.clone(),
                            request: call.id.clone(),
                            resource: rss_mdm_resource::Id::new(resource)
                                .map_err(|_| Error::Malformed)?,
                            version: rss_mdm_resource::Id::new(version)
                                .map_err(|_| Error::Malformed)?,
                            expected_resource_revision: *expected_resource_revision,
                            resource_digest: *resource_digest,
                            target_digest: *target_digest,
                            as_of: at,
                        },
                        &access,
                        cutoff(),
                    )
                    .await
                    .map_err(failure)?;
                Ok(if replayed {
                    Effect::Replayed
                } else {
                    Effect::Performed
                })
            }
            Change::Retry => {
                let c = service
                    .record(&key, cutoff())
                    .await
                    .map_err(failure)?
                    .ok_or(Error::Conflict)?;
                let result = service
                    .retry(&key, c.snapshot().attempt.attempt, &call, &access, cutoff())
                    .await
                    .map_err(failure)?;
                Ok(if matches!(result, rel::Transition::Replayed(_)) {
                    Effect::Replayed
                } else {
                    Effect::Performed
                })
            }
            Change::Withdraw => {
                let result = service
                    .withdraw(&key, &call, &access, cutoff())
                    .await
                    .map_err(failure)?;
                Ok(
                    if matches!(
                        result.outcome,
                        service::Withdrawal::Complete | service::Withdrawal::NotPublished
                    ) {
                        if result.replayed {
                            Effect::Replayed
                        } else {
                            Effect::Performed
                        }
                    } else {
                        Effect::Unknown
                    },
                )
            }
            Change::Recover => {
                let recovery = &intent["recovery"];
                let digest: [u8; 32] = serde_json::from_value(recovery["publication"].clone())
                    .map_err(|_| Error::Conflict)?;
                let publication = rel::PublicationId::from_digest(rel::Digest::from_bytes(digest));
                let attempt = recovery["attempt"].as_u64().ok_or(Error::Conflict)?;
                let current = service
                    .record(&key, cutoff())
                    .await
                    .map_err(failure)?
                    .ok_or(Error::Conflict)?;
                // Retry is permitted only after a terminal NotApplied result. A newer attempt
                // proves the accepted attempt settled; never redirect recovery to the retry.
                if current.snapshot().attempt.attempt > attempt {
                    return Ok(Effect::Replayed);
                }
                // A later withdrawal takes precedence over recovery of a publish call.
                let withdrawing = recovery["withdrawn"].as_bool().ok_or(Error::Conflict)?
                    || service
                        .withdrawal_status(publication, attempt, cutoff())
                        .await
                        .map_err(failure)?
                        .is_some();
                let complete = if withdrawing {
                    matches!(
                        service
                            .reconcile_withdrawal(publication, attempt, cutoff())
                            .await
                            .map_err(failure)?,
                        service::Withdrawal::Complete | service::Withdrawal::NotPublished
                    )
                } else {
                    matches!(
                        service
                            .reconcile(publication, attempt, at, cutoff())
                            .await
                            .map_err(failure)?,
                        rel::PublicationOutcome::Reported(
                            rel::PublicationResult::Applied(_)
                                | rel::PublicationResult::NotApplied(_)
                        )
                    )
                };
                Ok(if !complete {
                    Effect::Unknown
                } else if replayed {
                    Effect::Replayed
                } else {
                    Effect::Performed
                })
            }
        }
    }
    .await;
    match result {
        Ok(effect) => {
            audit.management_result(effect);
            if matches!(effect, Effect::Unknown) {
                return Err(Error::CommitUnknown);
            }
            audit.mark_committed();
        }
        Err(e) => {
            if matches!(e, Error::RollbackFailed) {
                audit.mark_rollback_failed();
            }
            return Err(e);
        }
    }
    authorize(authorization, proof, permission).await?;
    read_view(directory, id, true).await
}
pub struct PublicationDirectory {
    pub services: std::collections::BTreeMap<String, Arc<service::PublicationService>>,
    pub tenant: TenantId,
    pub runtime: Arc<PgRuntime>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub clock: Arc<dyn crate::management::Clock>,
}
impl PublicationDirectory {
    async fn authorize_intent(
        &self,
        source: &str,
        id: &str,
        request: &Operation<Change>,
        audit: &RequestAudit,
        proof: &AuthorizedPrincipal,
        permission: Permission,
    ) -> std::result::Result<(Value, bool), Error> {
        proof.manage(permission)?;
        crate::management::transaction::run(
            &self.audit_store, &self.runtime, self.tenant, audit,
            (self, source, id, request, audit, proof),
            |ctx, tx| Box::pin(async move {
                let (s, source, id, request, audit, proof) = *ctx;
                crate::management::transaction::lock(tx).await?;
                crate::management::transaction::current(tx, proof).await?.require(proof, permission, None)?;
                if request.operation_id.is_nil() { return Err(Error::Malformed.into()); }
                use sha2::Digest;
                let hash = sha2::Sha256::digest(checked_input(serde_json::to_vec(&(
                    "direct-publication", audit.tenant(), audit.snapshot().actor,
                    audit.snapshot().instance, source, id, request,
                )))?).to_vec();
                if let Some(old) = super::receipts::replay(tx, audit, request.operation_id, &hash).await? {
                    super::receipts::audit(tx, &*s.audit_store, audit, Some((request.operation_id, &hash)), true).await?;
                    proof.check_live()?;
                    return Ok((old, true));
                }
                let mut value = json!({"record": id, "as_of": s.clock.unix_seconds().ok_or(Error::Unavailable(Failure::Clock))?});
                if matches!(request.input, Change::Recover) {
                    let key = rel::PublicationKey::new(s.tenant, id).map_err(|_| Error::Malformed)?;
                    let record = rss_mdm_software_release_postgres::lock_publication_reference_in(tx, &key)
                        .await?.map_err(|_| Error::Conflict)?;
                    let snapshot = record.snapshot();
                    if snapshot.revision != request.expected_revision || snapshot.attempt.binding.target.value() != source {
                        return Err(Error::Conflict.into());
                    }
                    value["recovery"] = json!({"publication": snapshot.attempt.id().digest().bytes(),
                        "attempt": snapshot.attempt.attempt, "withdrawn": snapshot.withdrawn});
                }
                super::receipts::receipt(tx, audit, request.operation_id, &hash, &value).await?;
                super::receipts::audit(tx, &*s.audit_store, audit, Some((request.operation_id, &hash)), false).await?;
                proof.check_live()?;
                Ok((value, false))
            }), crate::management::transaction::TransactionOwner::Publication,
        ).await
    }
}

impl PublicationDirectory {
    async fn coordinate(&self, id: &str) -> Result<(String, String, String), Error> {
        let key = rel::PublicationKey::new(self.tenant, id).map_err(|_| Error::Malformed)?;
        crate::management::transaction::inspect(&self.runtime,self.tenant,key,|key,tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();let key=key.value().to_owned();
            let row=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_as::<_,(String,String,String)>("SELECT convert_from(document,'UTF8')::jsonb->>'target',resource,version FROM mdm_software_composition.subjects WHERE tenant_id=$1::uuid AND record=$2")
                    .bind(tenant).bind(key).fetch_optional(c).await
            })).await?;
            Ok(row.ok_or(Error::Publication(super::error::PublicationError::MissingPublication))?)
        }),crate::management::transaction::TransactionOwner::Publication).await
    }
}
pub async fn list(
    directory: &PublicationDirectory,
    authorization: &rss_mdm_authorization_service::Store,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<Value, Error> {
    if !q.validate() {
        return Err(Error::Malformed);
    }
    authorize(authorization, proof, Permission::ReleaseRead).await?;
    audit.set_action("management_read");
    let limit = q.limit;
    let ids=crate::management::transaction::inspect(&directory.runtime,directory.tenant,q,|q,tx|Box::pin(async move {
        let tenant=tx.tenant_id().to_string();let after=q.after.clone();let target=q.target.clone();let resource=q.resource.clone();let version=q.version.clone();let operation=q.operation_id.map(|id|id.to_string());let limit=q.limit;
        Ok(tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT record FROM mdm_software_composition.subjects s WHERE tenant_id=$1::uuid AND ($2::text IS NULL OR record COLLATE \"C\">$2) AND ($3::text IS NULL OR convert_from(document,'UTF8')::jsonb->>'target'=$3) AND ($4::text IS NULL OR resource=$4) AND ($5::text IS NULL OR version=$5) AND ($6::text IS NULL OR EXISTS(SELECT 1 FROM mdm_publication.operations o WHERE o.tenant_id=s.tenant_id AND o.id::text=$6 AND o.response->>'record'=s.record)) ORDER BY record COLLATE \"C\" LIMIT $7")
                .bind(tenant).bind(after).bind(target).bind(resource).bind(version).bind(operation).bind((limit+1)as i64).fetch_all(c).await
        })).await?)
    }),crate::management::transaction::TransactionOwner::Publication).await?;
    let next = if ids.len() > limit {
        ids.get(limit - 1).cloned()
    } else {
        None
    };
    let mut items = Vec::new();
    for id in ids.into_iter().take(limit) {
        let view = read_view(directory, id, false).await?;
        items.push(view);
    }
    authorize(authorization, proof, Permission::ReleaseRead).await?;
    Ok(json!({"items":items,"nextCursor":next}))
}
pub async fn targets(
    directory: &PublicationDirectory,
    authorization: &rss_mdm_authorization_service::Store,
    proof: &AuthorizedPrincipal,
    q: Query,
) -> Result<Value, Error> {
    if !q.validate() {
        return Err(Error::Malformed);
    }
    authorize(authorization, proof, Permission::ReleaseRead).await?;
    let mut values = directory
        .services
        .iter()
        .filter(|(id, _)| q.after.as_ref().is_none_or(|a| *id > a))
        .take(q.limit + 1)
        .map(|(id, s)| (id.clone(), s.target()))
        .collect::<Vec<_>>();
    let next = if values.len() > q.limit {
        values.truncate(q.limit);
        values.last().map(|(id, _)| id.clone())
    } else {
        None
    };
    Ok(json!({"items":values.into_iter().map(|(_,v)|v).collect::<Vec<_>>(),"nextCursor":next}))
}
