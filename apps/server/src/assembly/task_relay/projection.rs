//! The fixed RSS projection commits the business effect, its audit, the Inbox receipt and the source together.
use super::lanes::*;
use crate::{Error, Failure};
use futures::{Stream, StreamExt};
use rss_mdm_audit_integration::{AuditStore, StorageProfile};
use rss_mdm_native_protection::Protector;
use rss_mdm_recovery_observation::{RelayMessage, RelayScope};
use rss_mdm_work_page::relay::Dispatch;
use rss_reconcile::ErrorKind;
use rss_transactional_messaging::{
    fence::{ExecutionBinding, StorageIdentity},
    inbox::ConsumerGroup,
    message::{MessageEnvelope, MessageFingerprint, MessageId, MessagingDomain},
    observability::TransactionalMessagingTransactionStatus as Status,
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline},
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, RejectKind,
        TerminalDisposition, VerifiedIngress,
    },
};
use rss_transactional_messaging_postgres::{
    PgConsumerEffect, PgConsumerEffectFailure as EffectFailure, PgError, PgLocalProjection,
    PgProjectionOutcome, PgRecoveryCapture, PgRuntime, PgTransaction,
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use uuid::Uuid;

struct Effect {
    lane: Lane,
    audit: AuditStore,
    protection: Arc<Protector>,
    storage: StorageIdentity,
    collection_wake: Option<rss_reconcile_postgres::PgMessagingStore>,
}
struct Validator {
    binding: ExecutionBinding,
    originals: std::sync::Mutex<std::collections::HashMap<MessageId, RelayMessage>>,
}

impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        if challenge.message().metadata().tenant_id() != self.binding.tenant() {
            return Err(EnvelopeValidationFailure::ExecutionMismatch);
        }
        // The owner's immutable fingerprint authenticates the complete original envelope in apply.
        let envelope = challenge.message();
        let original = RelayMessage {
            domain: envelope.metadata().domain().clone(),
            id: envelope.id().clone(),
            fingerprint: Some(MessageFingerprint::of(envelope)),
        };
        self.originals
            .lock()
            .expect("batch identities")
            .insert(original.id.clone(), original);
        Ok(challenge.verified(self.binding))
    }
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, EffectFailure> {
        let reject = TerminalDisposition::Rejected(RejectKind::Permanent);
        let Some((prefix, id)) = message.id().as_str().split_once('.') else {
            return Ok(reject);
        };
        let Ok(id) = Uuid::parse_str(id) else {
            return Ok(reject);
        };
        let binding = ExecutionBinding::new(self.storage, tx.tenant_id(), tx.expected_epoch());
        let dispatch = Dispatch {
            binding,
            id,
            fingerprint: MessageFingerprint::of(message),
        };
        let audit = &self.audit;
        let protection = self.protection.as_ref();
        let accepted = match (self.lane, prefix) {
            (DEVICE,"dispatch")=> {
                rss_mdm_device_service::control::Service::project_native_in(tx,&dispatch,audit,protection).await.map_err(EffectFailure::infrastructure)?
            },
            (DEVICE,"action")=> {
                rss_mdm_device_service::control::Service::project_action_in(tx,&dispatch,audit).await.map_err(EffectFailure::infrastructure)?
            },
            (POLICY,"dispatch")=> {
                rss_mdm_policy_service::configuration::Transactions::project_native_in(tx,&dispatch,audit,protection).await.map_err(EffectFailure::infrastructure)?
            },
            (SOFTWARE,"dispatch")=> {
                rss_mdm_software_service::deployment::SoftwareService::project_native_in(tx,&dispatch,audit,protection).await.map_err(EffectFailure::infrastructure)?
            },
            (SOFTWARE,"action")=> {
                rss_mdm_software_service::deployment::SoftwareService::project_action_in(tx,&dispatch,audit).await.map_err(EffectFailure::infrastructure)?
            },
            (INSTALLATION,"dispatch")=> {
                rss_mdm_registration_service::installation::Service::project_native_in(tx,&dispatch,audit,protection).await.map_err(EffectFailure::infrastructure)?
            },
            (NATIVE_CREDENTIALS,"dispatch")=> {
                rss_mdm_recovery_credentials::native::Service::project_native_in(tx,&dispatch,audit,protection).await.map_err(EffectFailure::infrastructure)?
            },
            (SCRIPT,"script")=> {
                rss_mdm_script_service::ScriptService::project_action_in(tx,&dispatch,audit).await.map_err(EffectFailure::infrastructure)?
            },
            (INVENTORY,"collection")=> {
                rss_mdm_inventory_service::collection::execution::CollectionService::project_action_in(tx,&dispatch,audit,self.collection_wake.as_ref().expect("collection wake admitted")).await.map_err(EffectFailure::infrastructure)?
            },
            (ENROLLMENT,"enrollment")=> {
                rss_mdm_registration_service::enrollment::tasks::Service::project_action_in(tx,&dispatch,audit,StorageProfile::Mdm).await.map_err(EffectFailure::infrastructure)?
            },
            (CREDENTIALS | DA_CREDENTIALS,"credential")=> {
                rss_mdm_recovery_credentials::tasks::Service::project_action_in(tx,&dispatch,audit,if self.lane==CREDENTIALS {StorageProfile::Mdm} else {StorageProfile::Da}).await.map_err(EffectFailure::infrastructure)?
            },
            (ACCESS,"access")=> {
                rss_mdm_device_access_postgres::device_access::execution::Service::project_action_in(tx,&dispatch,audit).await.map_err(EffectFailure::infrastructure)?
            },
            _=>false,
        };
        Ok(if accepted {
            TerminalDisposition::Succeeded
        } else {
            reject
        })
    }
}
/// Results are bounded by the number of admitted slots. Every failed item is
/// observed with its source identity before the scheduler sees the batch.
#[derive(Default)]
pub(crate) struct Batch {
    pub(crate) advanced: usize,
    unresolved: Vec<ErrorKind>,
}
impl Batch {
    pub(super) fn next_delay(self) -> Result<Duration, super::SchedulingFailure<ErrorKind>> {
        if self.unresolved.contains(&ErrorKind::StorageContract) {
            return Err(super::SchedulingFailure::Fatal(ErrorKind::StorageContract));
        }
        if self.advanced > 0 {
            // RSS applies each original item's retry_after/lease even on an immediate rescan.
            return Ok(Duration::ZERO);
        }
        if self.unresolved.is_empty() {
            Ok(super::IDLE)
        } else {
            Err(super::SchedulingFailure::Retry)
        }
    }
}

pub(crate) struct Projection {
    pub(crate) lane: Lane,
    pub(crate) runtime: Arc<PgRuntime>,
    engine: PgLocalProjection<Effect, Protector>,
}
fn deadline(seconds: u64) -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(seconds))
}
impl Projection {
    pub(crate) async fn open(
        config: &crate::config::Config,
        binding: ExecutionBinding,
        audit: &AuditStore,
        protection: Arc<Protector>,
        lane: Lane,
    ) -> Result<Arc<Self>, Error> {
        let invalid = || Error::Configuration(crate::ConfigIssue::BusinessDatabase);
        let password_file = config
            .command_projection_password_files
            .get(lane.role)
            .ok_or_else(invalid)?;
        let db = crate::config::Database {
            user: lane.role.to_owned(),
            password_file: password_file.clone(),
            ..config.command_database.clone()
        };
        let runtime = crate::local_delivery::consumer_runtime(&db, binding.storage()).await?;
        let opened = async {
            let audit_budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
            let audit = audit
                .on_runtime(runtime.clone(), binding, &audit_budget.control())
                .await?;
            let unavailable = |_| Error::Unavailable(Failure::Database);
            let capture = PgRecoveryCapture::new(runtime.clone(), protection.clone(), deadline(6))
                .await
                .map_err(unavailable)?;
            let collection_wake = if lane == INVENTORY {
                Some(
                    rss_reconcile_postgres::PgMessagingStore::new(
                        runtime.clone(),
                        binding,
                        deadline(6),
                    )
                    .await
                    .map_err(|_| Error::Unavailable(Failure::Database))?,
                )
            } else {
                None
            };
            let effect = Effect {
                lane,
                audit,
                protection,
                storage: binding.storage(),
                collection_wake,
            };
            let ttl = Duration::from_secs(30);
            let io = Duration::from_secs(6);
            let engine = PgLocalProjection::new(
                capture,
                ConsumerGroup::parse(lane.role).expect("command group"),
                MessagingDomain::parse(lane.domain).expect("command domain"),
                effect,
                DeliveryBudget::new(ttl, io, io, io).map_err(|_| invalid())?,
                LeaseRenewalPolicy::from_ttl(ttl).map_err(|_| invalid())?,
                deadline(6),
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
            Ok(Arc::new(Self {
                lane,
                runtime: runtime.clone(),
                engine,
            }))
        }
        .await;
        if opened.is_err() {
            runtime.close().await;
        }
        opened
    }

    #[cfg(test)]
    pub(crate) fn inject(
        &self,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
    ) -> Result<(), PgError> {
        self.engine
            .inject_next_projection_fault(fault, std::future::ready(()))
    }
    pub(crate) async fn poll<S: Send>(
        &self,
        binding: ExecutionBinding,
        mut slots: Vec<S>,
        scope: Option<&RelayScope<'_>>,
    ) -> Result<Batch, ErrorKind> {
        let limit = NonZeroUsize::new(slots.len()).expect("admitted slots");
        let validator = Validator {
            binding,
            originals: Default::default(),
        };
        let batch = self
            .engine
            .project_batch(
                binding,
                &validator,
                limit,
                deadline(1),
                Duration::from_secs(12),
            )
            .await
            .map_err(|error| {
                let kind = provider_kind(&error);
                self.log(binding, None, "claim", kind, Some(&error));
                if let Some(scope) = scope {
                    scope.claim(Err(kind));
                    if kind == ErrorKind::StorageContract { scope.owner_failed(kind); }
                }
                kind
            })?;
        if let Some(scope) = scope {
            scope.claim(Ok(()));
        }
        let cap = batch.size_hint().1.unwrap_or(limit.get());
        slots.truncate(cap);
        let results = batch
            .map(|item| {
                let slot = slots.pop().expect("admitted source");
                let id = item.message_id().clone();
                // RSS invokes ingress with the original claim before starting a consumer transaction.
                let message = validator
                    .originals
                    .lock()
                    .expect("batch identities")
                    .remove(&id);
                async move {
                    let _slot = slot;
                    let message = match message {
                        Some(original) => original,
                        None => {
                            // Expiry and its fenced settlement run before ingress. The provider
                            // still returns the claimed ID even when a subsequent header read fails.
                            let mut original = RelayMessage {
                                domain: MessagingDomain::parse(self.lane.domain)
                                    .expect("command domain"),
                                id: id.clone(),
                                fingerprint: None,
                            };
                            original.fingerprint =
                                super::read_fingerprint(binding, &self.runtime, &original).await;
                            original
                        }
                    };
                    let result = match item.into_outcome() {
                        Ok(PgProjectionOutcome::InProgress) => return Ok(false),
                        Ok(PgProjectionOutcome::DeliveryExpired) => {
                            Err(("expired", ErrorKind::Deadline, true))
                        }
                        Ok(PgProjectionOutcome::Rejected(_)) => {
                            Err(("ingress", ErrorKind::Permanent, true))
                        }
                        Err(error) => {
                            let kind = provider_kind(&error);
                            self.log(binding, Some(&message), "projection", kind, Some(&error));
                            Err(("projection", kind, false))
                        }
                        Ok(PgProjectionOutcome::Attempt(attempt)) => {
                            let (outcome, recovery) = attempt.into_parts();
                            match outcome.status() {
                                Status::Committed => {
                                    let disposition = outcome.fold(
                                        |c| Some(c.into_parts().1.disposition()),
                                        |_| None,
                                        |_| None,
                                        || None,
                                        || None,
                                        || None,
                                    );
                                    match disposition {
                                        Some(TerminalDisposition::Succeeded) => Ok(()),
                                        Some(TerminalDisposition::Rejected(_)) => {
                                            Err(("owner", ErrorKind::Permanent, true))
                                        }
                                        None => unreachable!("committed outcome"),
                                    }
                                }
                                Status::CommitUnknown | Status::RollbackFailed => {
                                    let kind = if outcome.status() == Status::CommitUnknown {
                                        ErrorKind::CommitUnknown
                                    } else {
                                        ErrorKind::RollbackFailed
                                    };
                                    let receipt = self.engine.resolve(&recovery, deadline(1)).await;
                                    self.log(
                                        binding,
                                        Some(&message),
                                        "transaction",
                                        kind,
                                        receipt.as_ref().err(),
                                    );
                                    match receipt {
                                        Ok(Some(r))
                                            if r.disposition()
                                                == TerminalDisposition::Succeeded =>
                                        {
                                            Ok(())
                                        }
                                        Ok(Some(_)) => Err(("owner", ErrorKind::Permanent, true)),
                                        _ => Err(("transaction", kind, false)),
                                    }
                                }
                                Status::Fenced => Err(("transaction", ErrorKind::Fenced, false)),
                                Status::RejectedPermanent => {
                                    Err(("transaction", ErrorKind::Permanent, false))
                                }
                                _ => Err(("transaction", ErrorKind::Transient, false)),
                            }
                        }
                    };
                    if let Err((stage, kind, isolated)) = result {
                        self.log(binding, Some(&message), stage, kind, None);
                        if let Some(scope) = scope {
                            if kind == ErrorKind::StorageContract { scope.owner_failed(kind); }
                            if isolated {
                                scope.quarantined();
                            }
                            if !isolated || message.fingerprint.is_none() {
                                scope.message_failed(&message, kind);
                            }
                        }
                        return if isolated { Ok(true) } else { Err(kind) };
                    }
                    Ok(true)
                }
            })
            .buffer_unordered(limit.get());
        tokio::pin!(results);
        let mut batch = Batch::default();
        while let Some(item) = results.next().await {
            match item {
                Ok(advanced) => batch.advanced += usize::from(advanced),
                Err(kind) => batch.unresolved.push(kind),
            }
        }
        Ok(batch)
    }
    fn log(
        &self,
        binding: ExecutionBinding,
        message: Option<&RelayMessage>,
        stage: &str,
        kind: ErrorKind,
        provider: Option<&PgError>,
    ) {
        use base64::Engine;
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_command_relay_failure","owner":self.lane.owner,"domain":self.lane.domain,"tenant":binding.tenant().to_string(),"epoch":binding.epoch().get(),"messageId":message.map(|m|m.id.as_str()),"fingerprintBase64":message.and_then(|m|m.fingerprint).map(|digest|base64::engine::general_purpose::STANDARD.encode(digest.as_bytes())),"phase":stage,"reason":format!("{kind:?}"),"provider":provider.map(|e|e.kind().as_label())})
        );
    }
}
fn provider_kind(error: &PgError) -> ErrorKind {
    if matches!(error, PgError::IncompatibleStorageContract(_)) {
        return ErrorKind::StorageContract;
    }
    use rss_transactional_messaging::error::MessagingErrorKind as K;
    match error.kind() {
        K::Transient => ErrorKind::Transient,
        K::DeadlineElapsed => ErrorKind::Deadline,
        K::OwnershipLost => ErrorKind::Fenced,
        K::Conflict | K::Invariant => ErrorKind::Invariant,
        K::Permanent => ErrorKind::Permanent,
    }
}
