use super::*;

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.withdrawal"]
async fn quarantine_denies_published_reads_and_ring_cleanup_preserves_other_projections() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let test = submit_publication(&service, &input.candidate, rel::Ring::Test).await;
    service
        .publish(test.id(), 1, at(10), cutoff())
        .await
        .unwrap();
    let pilot = submit_publication(&service, &input.candidate, rel::Ring::Pilot).await;
    service
        .publish(pilot.id(), 1, at(10), cutoff())
        .await
        .unwrap();
    assert!(
        service
            .published(rel::Ring::Test, test.id().digest().bytes(), cutoff())
            .await
            .is_ok()
    );
    assert!(
        service
            .published(rel::Ring::Pilot, pilot.id().digest().bytes(), cutoff())
            .await
            .is_ok()
    );
    assert!(matches!(
        service
            .published(rel::Ring::Pilot, test.id().digest().bytes(), cutoff())
            .await,
        Err(Error::CandidateNotFound)
    ));
    let request = request_for(&service, &input.candidate).await;
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, &request, cutoff())
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    // Candidate quarantine fences reads in every ring, while each projection is removed by its own intent.
    assert!(matches!(
        service
            .published(rel::Ring::Test, test.id().digest().bytes(), cutoff())
            .await,
        Err(Error::CandidateNotFound)
    ));
    assert!(matches!(
        service
            .published(rel::Ring::Pilot, pilot.id().digest().bytes(), cutoff())
            .await,
        Err(Error::CandidateNotFound)
    ));
    assert!(
        service
            .published_page(rel::Ring::Test, "", 100, cutoff())
            .await
            .unwrap()
            .is_empty()
    );
    let retained = service
        .published_page(rel::Ring::Pilot, "", 100, cutoff())
        .await
        .unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].1, pilot.id().digest().bytes());
    assert!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, &request, cutoff())
            .await
            .unwrap()
            .replayed
    );
    let request = request_for(&service, &input.candidate).await;
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Pilot, &request, cutoff())
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert!(
        service
            .published_page(rel::Ring::Pilot, "", 100, cutoff())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(server.state.lock().unwrap().posts, 0);
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.withdrawal"]
async fn unstarted_withdrawal_cancels_original_attempt_without_publishing() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = submit_publication(&service, &input.candidate, rel::Ring::Test).await;
    let request = request_for(&service, &input.candidate).await;
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, &request, cutoff())
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert!(matches!(
        service
            .publish(p.id(), p.attempt, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_))
    ));
    assert!(matches!(
        service
            .published(rel::Ring::Test, p.id().digest().bytes(), cutoff())
            .await,
        Err(Error::CandidateNotFound)
    ));
    assert!(
        service
            .reconciliation_page("", 32, cutoff())
            .await
            .unwrap()
            .work
            .is_empty()
    );
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), p.attempt, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    assert_eq!(server.state.lock().unwrap().posts, 0);
    runtime.close().await;
}
