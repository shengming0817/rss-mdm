use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS: make t2 MODULE=publication.withdrawal"]
async fn ring_isolation_unstarted_withdrawal_and_lost_delete_ack() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_submission()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = authorize(&service, &input.candidate, rel::Ring::Test).await;
    service.publish(p.id(), 1, at(10), cutoff()).await.unwrap();
    assert_eq!(server.state.lock().unwrap().manifests.len(), 1);
    let pilot = authorize(&service, &input.candidate, rel::Ring::Pilot).await;
    service
        .publish(pilot.id(), 1, at(10), cutoff())
        .await
        .unwrap();
    assert_eq!(server.state.lock().unwrap().manifests.len(), 2);
    let production = authorize(&service, &input.candidate, rel::Ring::Production).await;
    assert_eq!(
        service
            .withdraw(
                &input.candidate,
                rel::Ring::Production,
                &request_for(&service, &input.candidate).await,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert_eq!(server.state.lock().unwrap().posts, 2);
    assert!(
        service
            .publish(production.id(), 1, at(10), cutoff())
            .await
            .is_ok()
    );
    assert_eq!(server.state.lock().unwrap().posts, 2);
    server.state.lock().unwrap().reject_information_once = true;
    assert_eq!(
        service
            .withdraw(
                &input.candidate,
                rel::Ring::Test,
                &request_for(&service, &input.candidate).await,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::PreflightRetryable
    );
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Withdrawal::PreflightRetryable
    );
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    drop(service);
    let service = server.service(runtime.clone(), server.winget()).await;
    assert_eq!(
        service
            .withdrawal_status(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Some(Withdrawal::PreflightRetryable)
    );
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    let bindings = audit_records()
        .iter()
        .filter(|r| r.event().facts().resource().id().as_str() == input.candidate.value())
        .map(audit_payload)
        .filter(|p| p["software"]["stage"] == "record_result")
        .map(|p| p["software"]["binding"].as_str().unwrap().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(bindings.len(), 2);
    server.state.lock().unwrap().drop_delete_response = true;
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || AuditLog(writer.clone()))
        .finish();
    assert_eq!(
        service
            .withdraw(
                &input.candidate,
                rel::Ring::Test,
                &request_for(&service, &input.candidate).await,
                cutoff()
            )
            .with_subscriber(subscriber)
            .await
            .unwrap()
            .outcome,
        Withdrawal::SourceOutcomeUnknown
    );
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("software source write needs reconciliation"));
    for field in [
        "tenant=",
        "publication=",
        "attempt=1",
        "ring=0",
        "source_binding=",
    ] {
        assert!(logs.contains(field), "missing {field}: {logs}");
    }
    assert!(!logs.contains(&server.base));
    assert!(!logs.contains("x-functions-key"));
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Withdrawal::SourceOutcomeUnknown
    );
    assert_eq!(server.state.lock().unwrap().deletes, 1);
    drop(service);
    let restarted = server.service(runtime.clone(), server.winget()).await;
    assert_eq!(
        restarted
            .withdrawal_status(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Some(Withdrawal::SourceOutcomeUnknown)
    );
    assert_eq!(server.state.lock().unwrap().deletes, 1);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + HTTPS: make t2 MODULE=publication.withdrawal"]
async fn preflight_failure_allows_explicit_retry_without_resubmitting_unknown() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_submission()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = authorize(&service, &input.candidate, rel::Ring::Test).await;
    server.state.lock().unwrap().reject_information_once = true;
    assert!(matches!(
        service.publish(p.id(), 1, at(10), cutoff()).await.unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_))
    ));
    assert_eq!(server.state.lock().unwrap().posts, 0);
    let c = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    let r = request(&c);
    let rel::Transition::Applied {
        decision: rel::Decision::Publish(next),
        ..
    } = service
        .retry(&input.candidate, rel::Ring::Test, 1, &r, cutoff())
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(next.id(), p.id());
    assert_eq!(next.attempt, 2);
    assert!(matches!(
        service
            .publish(next.id(), 2, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert_eq!(server.state.lock().unwrap().posts, 1);
    assert!(matches!(
        service
            .retry(&input.candidate, rel::Ring::Test, 1, &r, cutoff())
            .await
            .unwrap(),
        rel::Transition::Replayed(_)
    ));
    runtime.close().await;
}
