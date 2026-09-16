//! The browser actor authorizes work; the controlled driver owns external effects.
use super::*;
use crate::api::{App, RequestAuth};
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
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    Candidate {
        resource: String,
        version: String,
        expected_resource_revision: u64,
        submission: service::Submission,
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
    client: &str,
    subject: &str,
) -> std::result::Result<rel::ActorId, Error> {
    rel::ActorId::new(tenant, json!([client, subject]).to_string()).map_err(|_| Error::Malformed)
}
fn failure(e: service::Error) -> Error {
    match e {
        service::Error::Diagnostic { category, .. } => failure(*category),
        service::Error::Input
        | service::Error::Content
        | service::Error::ArtifactAddress
        | service::Error::ArtifactBudget
        | service::Error::ArtifactDigest => Error::Malformed,
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
) -> std::result::Result<Json<Value>, Error> {
    app.policy.manage(&auth.proof, Permission::ReleaseRead)?;
    audit.set_action("management_read");
    audit.target(&id);
    let service = app
        .management
        .publications
        .get(&source)
        .ok_or(Error::NotFound)?;
    let id = rel::CandidateId::new(app.management.tenant, id).map_err(|_| Error::Malformed)?;
    let candidate = service
        .candidate(&id, cutoff())
        .await
        .map_err(failure)?
        .ok_or(Error::NotFound)?;
    let mut view = summary(&candidate);
    view["submission"] =
        serde_json::to_value(service.submission(&id, cutoff()).await.map_err(failure)?)
            .map_err(|_| Error::Unavailable(Failure::Runtime))?;
    Ok(Json(view))
}
async fn write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((source, id)): Path<(String, String)>,
    Json(request): Json<Operation<Change>>,
) -> std::result::Result<Json<Value>, Error> {
    let permission = match request.input {
        Change::Candidate { .. } => Permission::ReleaseWrite,
        Change::Validate { .. } => Permission::ReleaseValidate,
        Change::Approve { .. } => Permission::ReleaseApprove,
        Change::Authorize { .. } | Change::Publish { .. } => Permission::ReleasePublish,
        Change::Recover { .. } | Change::Retry { .. } => Permission::ReleaseRecover,
        Change::Withdraw { .. } => Permission::ReleaseWithdraw,
    };
    app.policy.manage(&auth.proof, permission)?;
    let service = app
        .management
        .publications
        .get(&source)
        .ok_or(Error::NotFound)?;
    let tenant = app.management.tenant;
    let candidate_id = rel::CandidateId::new(tenant, &id).map_err(|_| Error::Malformed)?;
    let operator = actor(tenant, auth.proof.client_id(), auth.proof.subject())?;
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
        .await?;
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
        auth.proof.client_id(),
    )
    .await;
    // The service persists actual domain outcomes. The envelope separately audits
    // this HTTP result, including its request ID, after external effect uncertainty.
    match outcome {
        Ok(()) => {
            let candidate = service
                .candidate(&candidate_id, cutoff())
                .await
                .map_err(failure)?
                .ok_or(Error::NotFound)?;
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
    client: &str,
) -> std::result::Result<(), Error> {
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
            service
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
                        submission: submission.clone(),
                        as_of: request.as_of,
                    },
                    cutoff,
                )
                .await
                .map_err(failure)?;
        }
        Change::Validate { ring } => {
            service
                .validate(id, ring.core(), request, cutoff)
                .await
                .map_err(failure)?;
        }
        Change::Approve {
            ring,
            publisher_subject,
        } => {
            service
                .approve(
                    id,
                    ring.core(),
                    &actor(id.tenant(), client, publisher_subject)?,
                    request,
                    cutoff,
                )
                .await
                .map_err(failure)?;
        }
        Change::Authorize { ring } => {
            service
                .authorize(id, ring.core(), request, cutoff)
                .await
                .map_err(failure)?;
        }
        Change::Retry { ring, attempt } => {
            service
                .retry(id, ring.core(), *attempt, request, cutoff)
                .await
                .map_err(failure)?;
        }
        Change::Withdraw { ring } => {
            service
                .withdraw(id, ring.core(), request, cutoff)
                .await
                .map_err(failure)?;
        }
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
                .ok_or(Error::NotFound)?;
            let snap = c.snapshot();
            let rel::RingState::Publication(p) = snap.ring_state(ring.core()) else {
                return Err(Error::Conflict);
            };
            if p.id().digest().bytes() != *publication || p.attempt != *attempt {
                return Err(Error::Conflict);
            }
            if matches!(change, Change::Publish { .. }) {
                service
                    .publish(p.id(), p.attempt, request.as_of, cutoff)
                    .await
                    .map_err(failure)?;
            } else {
                service
                    .reconcile(p.id(), p.attempt, request.as_of, cutoff)
                    .await
                    .map_err(failure)?;
            }
        }
    }
    Ok(())
}
fn cutoff() -> Deadline {
    Deadline::from_timeout(&crate::lifecycle::RuntimeTimer, Duration::from_secs(6))
        .expect("constant budget")
}
fn summary(c: &rel::Candidate) -> Value {
    let snapshot = c.snapshot();
    json!({"id":snapshot.id.value(),"revision":snapshot.revision,"content_digest":snapshot.content.digest().bytes(),"disposition":format!("{:?}",snapshot.disposition),"manifest_digest":snapshot.content.manifest().bytes(),"source_snapshot":snapshot.content.source_snapshot().bytes(),"rings":rel::Ring::ALL.iter().map(|ring| {
  let (state,publication)=match snapshot.ring_state(*ring) {
   rel::RingState::Publication(p)=>("publication",Some(json!({"id":p.id().digest().bytes(),"attempt":p.attempt,"outcome":match &p.outcome {rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))=>"published",rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_))=>"not_applied",_=>"unknown"}}))),
   rel::RingState::Approved(_)=>("approved",None),rel::RingState::Validated(_)=>("validated",None),_ =>("candidate",None),
  };let approval=match snapshot.ring_state(*ring) {rel::RingState::Approved(a)=>Some(a),rel::RingState::Publication(p)=>Some(&p.approval),_=>None};
            json!({"ring":format!("{ring:?}"),"state":state,"publication":publication,"approval":approval.map(|a|json!({"approver":a.approver.value(),"publisher":a.publisher.value(),"at":a.at.unix_seconds(),"digest":a.digest().bytes()}))})
 }).collect::<Vec<_>>()})
}
