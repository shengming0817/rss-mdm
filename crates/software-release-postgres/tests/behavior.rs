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
fn fresh_publication() -> r::Publication {
    let p = unique();
    support::publication(
        r::PublicationKey::new(tenant(), &p).unwrap(),
        content(&p, 4),
        at(1),
    )
}
fn request(c: &r::Publication, who: &str, operation: r::Operation) -> r::Request {
    r::Request {
        id: request_id(),
        actor: actor(who),
        expected_revision: c.snapshot().revision,
        as_of: at(10),
        operation,
    }
}
async fn apply(
    s: &ReleaseStore,
    c: &mut r::Publication,
    who: &str,
    op: r::Operation,
) -> r::Decision {
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
#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=software_release.persistence"]
async fn release_publication_unknown_retry_history_and_late_results() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let mut c = fresh_publication();
    let create = request_id();
    let receipt = s.create(&create, &c, deadline()).await.unwrap();
    assert_eq!(receipt, s.create(&create, &c, deadline()).await.unwrap());
    assert_event(c.snapshot().id.value(), create.value(), 0, 1);
    let p = c.snapshot().attempt.clone();
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
    apply(&s, &mut c, "operator", r::Operation::Withdraw).await;
    apply(
        &s,
        &mut c,
        "backend",
        r::Operation::Record {
            publication: p.id(),
            attempt: 2,
            outcome: r::PublicationResult::Applied(evidence()),
        },
    )
    .await;
    assert!(c.snapshot().withdrawn);
    assert!(matches!(
        c.snapshot().attempt.outcome,
        r::PublicationOutcome::Reported(r::PublicationResult::Applied(_))
    ));
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
    let observed = history
        .iter()
        .map(|h| {
            assert_eq!(h.attempt.id(), p.id());
            (
                h.attempt.attempt,
                match h.attempt.outcome {
                    r::PublicationOutcome::Pending => "pending",
                    r::PublicationOutcome::Reported(r::PublicationResult::Unknown(_)) => "unknown",
                    r::PublicationOutcome::Reported(r::PublicationResult::NotApplied(_)) => {
                        "not_applied"
                    }
                    r::PublicationOutcome::Reported(r::PublicationResult::Applied(_)) => "applied",
                },
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        [
            (1, "pending"),
            (1, "unknown"),
            (1, "not_applied"),
            (2, "pending"),
            (2, "pending"),
            (2, "applied")
        ]
    );
    let foreign_store = ReleaseStore::new(runtime, foreign(), deadline())
        .await
        .unwrap();
    assert!(
        foreign_store
            .get(
                &r::PublicationKey::new(foreign(), c.snapshot().id.value()).unwrap(),
                deadline()
            )
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=software_release.persistence"]
#[cfg(feature = "integration")]
async fn release_immutable_version_request_uniqueness_and_rollback() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let c = fresh_publication();
    let id = request_id();
    s.create(&id, &c, deadline()).await.unwrap();
    let other = support::publication(
        r::PublicationKey::new(tenant(), unique()).unwrap(),
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
    assert!(matches!(
        s.create(&id, &fresh_publication(), deadline()).await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    let a = request(&c, "operator", r::Operation::Withdraw);
    let b = request(&c, "operator", r::Operation::Withdraw);
    let (a, b) = tokio::join!(
        s.transition(&c.snapshot().id, &a, deadline()),
        s.transition(&c.snapshot().id, &b, deadline())
    );
    let next = match (a, b) {
        (Ok(r::Transition::Applied { next, .. }), Err(Error::Rejected(Rejection::Conflict)))
        | (Err(Error::Rejected(Rejection::Conflict)), Ok(r::Transition::Applied { next, .. })) => {
            next
        }
        other => panic!("CAS must have one winner and one conflict: {other:?}"),
    };
    assert_eq!(next.snapshot().revision, 1);
    assert_eq!(
        s.get(&c.snapshot().id, deadline()).await.unwrap(),
        Some(*next)
    );
    let fresh = fresh_publication();
    runtime
        .local_tx_with_context(tenant(), deadline(), &fresh, |publication, tx| {
            Box::pin(async move { fixture_pending_in(tx, publication).await })
        })
        .await
        .fold(
            |_| (),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    let change = request(&fresh, "operator", r::Operation::Withdraw);
    let result = runtime
        .local_tx_with_context(
            tenant(),
            deadline(),
            (&s, &fresh, &change),
            |(s, c, r), tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(&[s.partition(c.snapshot().id.value())?])
                        .await?;
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
#[ignore = "real PostgreSQL: make t2 MODULE=software_release.persistence"]
async fn release_events_and_runtime_binding() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let c = fresh_publication();
    let id = request_id();
    let other = support::runtime().await;
    let result = other
        .local_tx_with_context(tenant(), deadline(), (&s, &c, &id), |(s, c, id), tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[s.partition(c.snapshot().id.value())?])
                    .await?;
                s.create_in(tx, id, c).await
            })
        })
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |error| error.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant,
        |_| false,
        |_| false,
        |_| false
    ));
    let committed = s.create(&id, &c, deadline()).await.unwrap();
    assert_eq!(s.operation(&id, deadline()).await.unwrap(), Some(committed));
    assert_event(c.snapshot().id.value(), id.value(), 0, 1);
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

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=software_release.persistence"]
async fn admission_rejects_noninherited_switchable_privileges() {
    let runtime = runtime().await;
    let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let c = fresh_publication();
    let id = request_id();
    sql(
        "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) FROM mdm_software_release_runtime",
    );
    let result = s.create(&id, &c, deadline()).await;
    sql(
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_software_release_runtime",
    );
    assert!(matches!(
        result,
        Err(Error::RolledBack(ref error)) if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::Permanent
    ));
    assert!(s.operation(&id, deadline()).await.unwrap().is_none());
    assert!(s.get(&c.snapshot().id, deadline()).await.unwrap().is_none());
    sql("ALTER TABLE mdm_software_release.aggregates NO FORCE ROW LEVEL SECURITY");
    let result = ReleaseStore::new(runtime.clone(), tenant(), deadline()).await;
    sql("ALTER TABLE mdm_software_release.aggregates FORCE ROW LEVEL SECURITY");
    assert!(result.is_err());
    ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let role = format!("acl_{}", unique().replace('-', "_"));
    let bridge = format!("{role}_bridge");
    sql(&format!(
        "CREATE ROLE {role} NOLOGIN; CREATE ROLE {bridge} NOLOGIN; GRANT {role} TO {bridge} WITH INHERIT FALSE, SET TRUE; GRANT {bridge} TO mdm_software_release_runtime WITH INHERIT FALSE, SET TRUE; GRANT USAGE ON SCHEMA mdm_software_release TO {role};"
    ));
    let granted_role = role.clone();
    let outcome = tokio::spawn(async move {
    let role = granted_role;
    let privilege = "UPDATE(document) ON mdm_software_release.immutable";
    sql(&format!("GRANT {privilege} TO {role}"));
    let result = ReleaseStore::new(runtime.clone(), tenant(), deadline()).await;
    sql(&format!("REVOKE {privilege} FROM {role}"));
    assert!(matches!(result, Err(Error::RolledBack(ref e)) if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant));
    ReleaseStore::new(runtime.clone(), tenant(), deadline()).await.unwrap();
    // Permitted column privileges in a switchable role remain admissible.
    sql(&format!(
        "GRANT UPDATE(document) ON mdm_software_release.aggregates TO {role}"
    ));
    ReleaseStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    sql(&format!(
        "REVOKE UPDATE(document) ON mdm_software_release.aggregates FROM {role}"
    ));
    }).await;
    sql(&format!(
        "REVOKE {bridge} FROM mdm_software_release_runtime; REVOKE {role} FROM {bridge}; DROP OWNED BY {role}; DROP ROLE {bridge}; DROP ROLE {role};"
    ));
    outcome.unwrap();
}
