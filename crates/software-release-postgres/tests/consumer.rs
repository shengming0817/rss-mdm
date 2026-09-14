use rss_mdm_software_release_postgres::{core as r, *};
mod support;
use support::*;
fn actor(s: &str) -> r::ActorId {
    r::ActorId::new(tenant(), s).unwrap()
}
fn request_id() -> r::RequestId {
    r::RequestId::new(tenant(), format!("requests/{}+@", unique())).unwrap()
}
fn content(package: &str, byte: u8) -> r::Content {
    r::Content::new(
        r::SoftwareIdentity::new(r::SoftwareIdentityFields {
            source: "private".into(),
            package: package.into(),
            version: "1".into(),
            platform: "windows".into(),
        })
        .unwrap(),
        r::Digest::from_bytes([1; 32]),
        r::Digest::from_bytes([2; 32]),
        r::Digest::from_bytes([3; 32]),
        vec![
            r::VariantContent::new(
                "x64",
                "msi",
                vec![r::Artifact::new("installer", r::Digest::from_bytes([byte; 32])).unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn candidate() -> r::Candidate {
    let p = unique();
    r::Candidate::new(
        r::CandidateId::new(tenant(), &p).unwrap(),
        content(&p, 4),
        at(1),
    )
}
fn request(c: &r::Candidate, who: &str, operation: r::Operation) -> r::Request {
    r::Request {
        id: request_id(),
        actor: actor(who),
        expected_revision: c.snapshot().revision,
        as_of: at(10),
        operation,
    }
}
async fn apply(s: &ReleaseStore, c: &mut r::Candidate, who: &str, op: r::Operation) -> r::Decision {
    let r = request(c, who, op);
    let result = s
        .transition(&c.snapshot().id, &r, deadline())
        .await
        .unwrap();
    assert!(matches!(
        s.transition(&c.snapshot().id, &r, deadline())
            .await
            .unwrap(),
        r::Transition::Replayed(_)
    ));
    match result {
        r::Transition::Applied { next, decision, .. } => {
            *c = *next;
            decision
        }
        _ => panic!(),
    }
}
async fn authorize(s: &ReleaseStore, c: &mut r::Candidate) -> r::Publication {
    let validation = r::Validation {
        candidate: c.snapshot().id.clone(),
        content: c.snapshot().content.digest(),
        ring: r::Ring::Test,
        evidence: r::Evidence {
            actor: actor("validator"),
            digest: r::Digest::from_bytes([8; 32]),
            at: at(10),
        },
        verdict: r::Verdict::Passed,
    };
    apply(s, c, "publisher", r::Operation::Validate(validation)).await;
    apply(
        s,
        c,
        "approver",
        r::Operation::Approve {
            ring: r::Ring::Test,
            publisher: actor("publisher"),
            policy: r::ActorPolicy::Separate,
        },
    )
    .await;
    let r::RingState::Approved(a) = &c.snapshot().rings[0] else {
        panic!()
    };
    let op = r::Operation::Authorize {
        ring: r::Ring::Test,
        approval: a.digest(),
    };
    let r::Decision::Publish(p) = apply(s, c, "publisher", op).await else {
        panic!()
    };
    *p
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn release_approval_unknown_retry_history_and_late_results() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let mut c = candidate();
    let create = request_id();
    let receipt = s.create(&create, &c, deadline()).await.unwrap();
    assert_eq!(receipt, s.create(&create, &c, deadline()).await.unwrap());
    assert_event(c.snapshot().id.value(), create.value(), 0, 1);
    let p = authorize(&s, &mut c).await;
    let evidence = || r::Evidence {
        actor: actor("backend"),
        digest: r::Digest::from_bytes([9; 32]),
        at: at(10),
    };
    for outcome in [
        r::PublicationResult::Unknown(evidence()),
        r::PublicationResult::NotApplied(evidence()),
    ] {
        apply(
            &s,
            &mut c,
            "backend",
            r::Operation::Record {
                ring: r::Ring::Test,
                publication: p.id(),
                attempt: 1,
                outcome,
            },
        )
        .await;
    }
    let decision = apply(
        &s,
        &mut c,
        "publisher",
        r::Operation::Retry {
            ring: r::Ring::Test,
            publication: p.id(),
            attempt: 1,
        },
    )
    .await;
    let r::Decision::Publish(next) = decision else {
        panic!()
    };
    assert_eq!(p.id(), next.id());
    assert_eq!(next.attempt, 2);
    apply(&s, &mut c, "operator", r::Operation::Quarantine).await;
    apply(
        &s,
        &mut c,
        "backend",
        r::Operation::Record {
            ring: r::Ring::Test,
            publication: p.id(),
            attempt: 2,
            outcome: r::PublicationResult::Applied(evidence()),
        },
    )
    .await;
    assert_eq!(c.snapshot().disposition, r::Disposition::Quarantined);
    assert!(c.snapshot().rings[0].is_published());
    let restarted = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    assert_eq!(
        restarted.get(&c.snapshot().id, deadline()).await.unwrap(),
        Some(c.clone())
    );
    let history = restarted
        .attempt_history(&c.snapshot().id, None, 100, deadline())
        .await
        .unwrap();
    assert!(history.iter().any(|h| h.publication.attempt == 1
        && matches!(
            h.publication.outcome,
            r::PublicationOutcome::Reported(r::PublicationResult::NotApplied(_))
        )));
    let foreign_store = ReleaseStore::new(runtime, foreign(), deadline())
        .await
        .unwrap();
    assert!(
        foreign_store
            .get(
                &r::CandidateId::new(foreign(), c.snapshot().id.value()).unwrap(),
                deadline()
            )
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn release_immutable_version_request_uniqueness_and_rollback() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let c = candidate();
    let id = request_id();
    s.create(&id, &c, deadline()).await.unwrap();
    let other = r::Candidate::new(
        r::CandidateId::new(tenant(), unique()).unwrap(),
        content(&c.snapshot().content.software().fields().package, 5),
        at(1),
    );
    assert!(matches!(
        s.create(&request_id(), &other, deadline()).await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    assert!(
        s.get(&other.snapshot().id, deadline())
            .await
            .unwrap()
            .is_none()
    );
    assert!(s.create(&id, &candidate(), deadline()).await.is_err());
    let a = request(&c, "operator", r::Operation::Quarantine);
    let b = request(&c, "operator", r::Operation::Deprecate);
    let (a, b) = tokio::join!(
        s.transition(&c.snapshot().id, &a, deadline()),
        s.transition(&c.snapshot().id, &b, deadline())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let fresh = candidate();
    s.create(&request_id(), &fresh, deadline()).await.unwrap();
    let change = request(&fresh, "operator", r::Operation::Quarantine);
    let result = runtime
        .local_tx_with_context(
            tenant(),
            deadline(),
            (&s, &fresh, &change),
            |(s, c, r), tx| {
                Box::pin(async move {
                    s.transition_in(tx, &c.snapshot().id, r).await?.unwrap();
                    Err::<(), _>(rss_transactional_messaging_postgres::PgError::from(
                        sqlx::Error::RowNotFound,
                    ))
                })
            },
        )
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    assert!(s.operation(&change.id, deadline()).await.unwrap().is_none());
    assert_eq!(
        s.get(&fresh.snapshot().id, deadline()).await.unwrap(),
        Some(fresh)
    );
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn release_event_failure_and_runtime_admission() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let c = candidate();
    let id = request_id();
    sql("REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_software_release_runtime");
    let result = s.create(&id, &c, deadline()).await;
    sql("GRANT INSERT ON rss_transactional_messaging.outbox TO mdm_software_release_runtime");
    assert!(result.is_err());
    assert!(s.operation(&id, deadline()).await.unwrap().is_none());
    assert!(s.get(&c.snapshot().id, deadline()).await.unwrap().is_none());
    let other = support::runtime().await;
    let result = other
        .local_tx_with_context(tenant(), deadline(), (&s, &c, &id), |(s, c, id), tx| {
            Box::pin(async move { s.create_in(tx, id, c).await })
        })
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    sql("ALTER TABLE mdm_software_release.aggregates NO FORCE ROW LEVEL SECURITY");
    let result = ReleaseStore::new(runtime, tenant(), deadline()).await;
    sql("ALTER TABLE mdm_software_release.aggregates FORCE ROW LEVEL SECURITY");
    assert!(result.is_err());
}

fn assert_event(id: &str, request: &str, revision: u64, occurred_at: i64) {
    use sha2::{Digest, Sha256};
    let message_id = format!(
        "software-release.v1:{:x}",
        Sha256::digest(request.as_bytes())
    );
    let envelope: serde_json::Value = serde_json::from_str(&sql(&format!(
        "SELECT envelope FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='{}'",
        tenant(), message_id
    ))).unwrap();
    assert_eq!(envelope["tenant"], tenant().to_string());
    assert_eq!(envelope["occurred_at"], occurred_at);
    assert_eq!(envelope["domain"], "mdm-software-release");
    assert_eq!(envelope["route"], "software-release.changed");
    assert_eq!(envelope["contract"], "mdm.software-release.changed");
    assert_eq!(envelope["version"], "v1");
    assert_eq!(envelope["partition"], id);
    assert_eq!(
        envelope["schema"],
        format!("sha256:{:x}", Sha256::digest(EVENT_SCHEMA))
    );
    let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"v":1,"id":id,"request":request,"revision":revision})
    );
    let schema: serde_json::Value = serde_json::from_str(EVENT_SCHEMA).unwrap();
    let required: std::collections::BTreeSet<_> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        required,
        payload
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    );
}
