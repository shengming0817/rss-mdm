//! The browser actor authorizes work; the controlled driver owns external effects.
use super::*;
use crate::api::{App, RequestAuth};
use crate::audit::ManagementResult as Effect;
use crate::software_publication as service;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::get,
};
use rss_mdm_software_release as rel;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceConfig {
    pub name: String,
    pub rings: service::RingSources,
    pub artifacts: Vec<service::ArtifactOrigin>,
    pub max_artifact_bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum Change {
    Candidate {
        resource: String,
        version: String,
        expected_resource_revision: u64,
        submission: wire::Submission,
    },
    Validate {
        ring: Ring,
    },
    Approve {
        ring: Ring,
        publisher_subject: String,
    },
    Authorize {
        ring: Ring,
    },
    Publish {
        ring: Ring,
        publication: [u8; 32],
        attempt: u64,
    },
    Recover {
        ring: Ring,
        publication: [u8; 32],
        attempt: u64,
    },
    Retry {
        ring: Ring,
        attempt: u64,
    },
    Withdraw {
        ring: Ring,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Ring {
    Test,
    Pilot,
    Production,
}
impl Ring {
    fn core(self) -> rel::Ring {
        match self {
            Self::Test => rel::Ring::Test,
            Self::Pilot => rel::Ring::Pilot,
            Self::Production => rel::Ring::Production,
        }
    }
}
fn actor(
    tenant: TenantId,
    instance: &str,
    subject: &str,
) -> std::result::Result<rel::ActorId, Error> {
    rel::ActorId::new(tenant, json!([instance, subject]).to_string()).map_err(|_| Error::Malformed)
}
fn failure(e: service::Error) -> Error {
    match e {
        service::Error::Diagnostic { category, .. } => failure(*category),
        service::Error::Input
        | service::Error::Content
        | service::Error::ArtifactAddress
        | service::Error::ArtifactBudget
        | service::Error::ArtifactDigest => Error::Malformed,
        service::Error::CandidateNotFound => Error::ManagementNotFound(Missing::Candidate),
        service::Error::Identity => Error::Forbidden,
        service::Error::Conflict | service::Error::Blocked => Error::Conflict,
        service::Error::CommitUnknown(_) | service::Error::RollbackFailed(_) => {
            Error::CommitUnknown
        }
        _ => Error::Unavailable(Failure::Runtime),
    }
}
pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new().route(
        "/software-sources/{source}/candidates/{id}",
        get(read).post(write),
    )
}
async fn read(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((source, id)): Path<(String, String)>,
) -> std::result::Result<Json<wire::Candidate>, Error> {
    audit.set_action("management_read");
    audit.target(&id);
    app.policy.manage(&auth.proof, Permission::ReleaseRead)?;
    let service = app
        .management
        .publications
        .get(&source)
        .ok_or(Error::ManagementNotFound(Missing::Source))?;
    let id = rel::CandidateId::new(app.management.tenant, id).map_err(|_| Error::Malformed)?;
    let candidate = service
        .candidate(&id, cutoff())
        .await
        .map_err(failure)?
        .ok_or(Error::ManagementNotFound(Missing::Candidate))?;
    let mut view = summary(&candidate);
    view.submission = Some(
        service
            .submission(&id, cutoff())
            .await
            .map_err(failure)?
            .into(),
    );
    Ok(Json(view))
}
async fn write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((source, id)): Path<(String, String)>,
    Json(request): Json<Operation<Change>>,
) -> std::result::Result<Json<wire::Candidate>, Error> {
    let permission = match request.input {
        Change::Candidate { .. } => Permission::ReleaseWrite,
        Change::Validate { .. } => Permission::ReleaseValidate,
        Change::Approve { .. } => Permission::ReleaseApprove,
        Change::Authorize { .. } | Change::Publish { .. } => Permission::ReleasePublish,
        Change::Recover { .. } | Change::Retry { .. } => Permission::ReleaseRecover,
        Change::Withdraw { .. } => Permission::ReleaseWithdraw,
    };
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(request.operation_id, "management_write");
    app.policy.manage(&auth.proof, permission)?;
    let service = app
        .management
        .publications
        .get(&source)
        .ok_or(Error::ManagementNotFound(Missing::Source))?;
    let tenant = app.management.tenant;
    let candidate_id = rel::CandidateId::new(tenant, &id).map_err(|_| Error::Malformed)?;
    let operator = actor(tenant, auth.proof.instance_id(), auth.proof.principal_id())?;
    if let Change::Approve {
        publisher_subject, ..
    } = &request.input
    {
        app.policy.publisher(publisher_subject)?;
    }
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(request.operation_id, "management_write");
    let intent_audit = audit.transaction_copy();
    intent_audit.set_action("software_preflight");
    intent_audit.software(crate::audit::SoftwareFact {
        operation: request.operation_id.to_string(),
        publication: None,
        attempt: None,
        ring: None,
        binding: Some(source.clone()),
        stage: "management_admission",
        outcome: "accepted",
    });
    let intent = app
        .management
        .execute(
            &Command::PublicationIntent {
                source: source.clone(),
                id: id.clone(),
                request: request.clone(),
            },
            &intent_audit,
        )
        .await;
    intent_audit.finalize(intent.as_ref().err().and_then(|e| {
        matches!(e, Error::Unavailable(Failure::Audit))
            .then_some(crate::audit::FailureReason::Transaction)
    }));
    let intent = intent?;
    let at = Timepoint::try_from(intent["as_of"].as_i64().ok_or(Error::Conflict)?)
        .map_err(|_| Error::Conflict)?;
    let operation = rel::RequestId::new(tenant, request.operation_id.to_string())
        .map_err(|_| Error::Malformed)?;
    let call = service::ServiceRequest {
        actor: operator.clone(),
        id: operation.clone(),
        expected_revision: request.expected_revision,
        as_of: at,
    };
    audit.mark_commit_started();
    let outcome = perform(
        service,
        &candidate_id,
        &request.input,
        &call,
        auth.proof.instance_id(),
    )
    .await;
    // The service persists actual domain outcomes. The envelope separately audits
    // this HTTP result, including its request ID, after external effect uncertainty.
    match outcome {
        Ok(effect) => {
            audit.management_result(effect);
            if matches!(effect, Effect::Unknown) {
                return Err(Error::CommitUnknown);
            }
            let candidate = service
                .candidate(&candidate_id, cutoff())
                .await
                .map_err(failure)?
                .ok_or(Error::ManagementNotFound(Missing::Candidate))?;
            Ok(Json(summary(&candidate)))
        }
        Err(e) => Err(e),
    }
}
async fn perform(
    service: &service::PublicationService,
    id: &rel::CandidateId,
    change: &Change,
    request: &service::ServiceRequest,
    instance: &str,
) -> std::result::Result<Effect, Error> {
    let cutoff = cutoff();
    match change {
        Change::Candidate {
            resource,
            version,
            expected_resource_revision,
            submission,
        } => {
            if request.expected_revision != 0 {
                return Err(Error::Conflict);
            }
            let (_, replayed) = service
                .create_candidate(
                    &service::CandidateInput {
                        actor: request.actor.clone(),
                        candidate: id.clone(),
                        request: request.id.clone(),
                        resource: rss_mdm_resource::Id::new(resource)
                            .map_err(|_| Error::Malformed)?,
                        version: rss_mdm_resource::Id::new(version)
                            .map_err(|_| Error::Malformed)?,
                        expected_resource_revision: *expected_resource_revision,
                        submission: submission.clone().into(),
                        as_of: request.as_of,
                    },
                    cutoff,
                )
                .await
                .map_err(failure)?;
            Ok(effect(replayed))
        }
        Change::Validate { ring } => {
            let result = service
                .validate(id, ring.core(), request, cutoff)
                .await
                .map_err(failure)?;
            Ok(transition_effect(result))
        }
        Change::Approve {
            ring,
            publisher_subject,
        } => {
            let result = service
                .approve(
                    id,
                    ring.core(),
                    &actor(id.tenant(), instance, publisher_subject)?,
                    request,
                    cutoff,
                )
                .await
                .map_err(failure)?;
            Ok(transition_effect(result))
        }
        Change::Authorize { ring } => {
            let result = service
                .authorize(id, ring.core(), request, cutoff)
                .await
                .map_err(failure)?;
            Ok(transition_effect(result))
        }
        Change::Retry { ring, attempt } => {
            let result = service
                .retry(id, ring.core(), *attempt, request, cutoff)
                .await
                .map_err(failure)?;
            Ok(transition_effect(result))
        }
        Change::Withdraw { ring } => withdraw(service, id, *ring, request, cutoff).await,
        Change::Publish {
            ring,
            publication,
            attempt,
        }
        | Change::Recover {
            ring,
            publication,
            attempt,
        } => {
            let c = service
                .candidate(id, cutoff)
                .await
                .map_err(failure)?
                .ok_or(Error::ManagementNotFound(Missing::Candidate))?;
            let snap = c.snapshot();
            let rel::RingState::Publication(p) = snap.ring_state(ring.core()) else {
                return Err(Error::Conflict);
            };
            if p.id().digest().bytes() != *publication || p.attempt != *attempt {
                return Err(Error::Conflict);
            }
            let completed = matches!(
                p.outcome,
                rel::PublicationOutcome::Reported(
                    rel::PublicationResult::Applied(_) | rel::PublicationResult::NotApplied(_)
                )
            );
            let result = if matches!(change, Change::Publish { .. }) {
                service
                    .publish(p.id(), p.attempt, request.as_of, cutoff)
                    .await
                    .map_err(failure)?
            } else {
                service
                    .reconcile(p.id(), p.attempt, request.as_of, cutoff)
                    .await
                    .map_err(failure)?
            };
            Ok(match result {
                rel::PublicationOutcome::Reported(
                    rel::PublicationResult::Applied(_) | rel::PublicationResult::NotApplied(_),
                ) if completed => Effect::Replayed,
                rel::PublicationOutcome::Reported(
                    rel::PublicationResult::Applied(_) | rel::PublicationResult::NotApplied(_),
                ) => Effect::Performed,
                _ => Effect::Unknown,
            })
        }
    }
}
fn cutoff() -> Deadline {
    Deadline::from_timeout(&crate::lifecycle::RuntimeTimer, Duration::from_secs(6))
        .expect("constant budget")
}
fn summary(c: &rel::Candidate) -> wire::Candidate {
    let snapshot = c.snapshot();
    let rings = rel::Ring::ALL
        .iter()
        .map(|ring| {
            let (state, publication) = match snapshot.ring_state(*ring) {
                rel::RingState::Publication(p) => (
                    "publication",
                    Some(wire::Publication {
                        id: p.id().digest().bytes(),
                        attempt: p.attempt,
                        outcome: match p.outcome {
                            rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(
                                _,
                            )) => "published",
                            rel::PublicationOutcome::Reported(
                                rel::PublicationResult::NotApplied(_),
                            ) => "not_applied",
                            _ => "unknown",
                        }
                        .into(),
                    }),
                ),
                rel::RingState::Approved(_) => ("approved", None),
                rel::RingState::Validated(_) => ("validated", None),
                _ => ("candidate", None),
            };
            let approval = match snapshot.ring_state(*ring) {
                rel::RingState::Approved(a) => Some(a),
                rel::RingState::Publication(p) => Some(&p.approval),
                _ => None,
            };
            wire::CandidateRing {
                ring: ring_name(*ring).into(),
                state: state.into(),
                publication,
                approval: approval.map(|a| wire::Approval {
                    approver: a.approver.value().into(),
                    publisher: a.publisher.value().into(),
                    at: a.at.unix_seconds(),
                    digest: a.digest().bytes(),
                }),
            }
        })
        .collect();
    wire::Candidate {
        id: snapshot.id.value().into(),
        revision: snapshot.revision,
        content_digest: snapshot.content.digest().bytes(),
        disposition: disposition(snapshot.disposition).into(),
        manifest_digest: snapshot.content.manifest().bytes(),
        source_snapshot: snapshot.content.source_snapshot().bytes(),
        rings,
        submission: None,
    }
}

fn disposition(d: rel::Disposition) -> &'static str {
    match d {
        rel::Disposition::Active => "active",
        rel::Disposition::Quarantined => "quarantined",
        rel::Disposition::Deprecated => "deprecated",
    }
}
fn ring_name(r: rel::Ring) -> &'static str {
    match r {
        rel::Ring::Test => "test",
        rel::Ring::Pilot => "pilot",
        rel::Ring::Production => "production",
    }
}

fn effect(replayed: bool) -> Effect {
    if replayed {
        Effect::Replayed
    } else {
        Effect::Performed
    }
}
fn transition_effect(result: rel::Transition) -> Effect {
    effect(matches!(result, rel::Transition::Replayed(_)))
}

async fn withdraw(
    service: &service::PublicationService,
    id: &rel::CandidateId,
    ring: Ring,
    request: &service::ServiceRequest,
    cutoff: Deadline,
) -> std::result::Result<Effect, Error> {
    service
        .candidate(id, cutoff)
        .await
        .map_err(failure)?
        .ok_or(Error::ManagementNotFound(Missing::Candidate))?;
    let result = service
        .withdraw(id, ring.core(), request, cutoff)
        .await
        .map_err(failure)?;
    Ok(match result.outcome {
        service::Withdrawal::Complete | service::Withdrawal::NotPublished => {
            effect(result.replayed)
        }
        _ => Effect::Unknown,
    })
}
