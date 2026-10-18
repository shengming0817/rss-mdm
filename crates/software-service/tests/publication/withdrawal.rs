use super::*;

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.withdrawal"]
async fn one_target_withdrawal_preserves_an_independent_target() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let first = server.service(runtime.clone(), server.winget()).await;
    let a = seed(runtime.clone(), &server, server.winget_document()).await;
    let digest = first.target()["digest"].clone();
    let mut config = server.winget();
    let SourceConfig::Winget(c) = &mut config else {
        panic!()
    };
    c.base.push_str("secondary/");
    let second = PublicationService::connect(
        host(runtime.clone(), audit_store().await).await,
        tenant(),
        format!("{}-secondary", server.logical),
        config,
        actors(),
        cutoff(),
    )
    .await
    .unwrap();
    let mut b = a.clone();
    b.record = rel::PublicationKey::new(tenant(), unique()).unwrap();
    b.request = rel::RequestId::new(tenant(), uuid::Uuid::new_v4().to_string()).unwrap();
    let pb = submit_publication(&second, &b).await;
    second
        .publish(pb.id(), pb.attempt, at(10), cutoff())
        .await
        .unwrap();
    let pa = submit_publication(&first, &a).await;
    first
        .publish(pa.id(), pa.attempt, at(10), cutoff())
        .await
        .unwrap();
    assert_eq!(first.target()["digest"], digest);
    assert_ne!(pa.id(), pb.id());
    let r = request_for(&first, &a.record).await;
    assert_eq!(
        first
            .withdraw(&a.record, &r, &TestPublishAccess, cutoff())
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert!(
        first
            .published(pa.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    assert!(
        second
            .published(pb.id().digest().bytes(), cutoff())
            .await
            .is_ok()
    );
    assert!(
        first
            .published_page("", 100, cutoff())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        second
            .published_page("", 100, cutoff())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        first
            .withdraw(&a.record, &r, &TestPublishAccess, cutoff())
            .await
            .unwrap()
            .replayed
    );
    withdraw_version(&a).await;
    assert!(
        second
            .published(pb.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    let work = second
        .reconciliation_page("", 32, cutoff())
        .await
        .unwrap()
        .work;
    assert!(
        work.iter()
            .any(|w| w.withdrawal && w.publication == pb.id())
    );
    assert_eq!(
        second
            .reconcile_withdrawal(pb.id(), pb.attempt, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    assert!(
        second
            .published_page("", 100, cutoff())
            .await
            .unwrap()
            .is_empty()
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.withdrawal"]
async fn unstarted_withdrawal_cancels_original_attempt_without_publishing() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    let p = submit_publication(&service, &input).await;
    let request = request_for(&service, &input.record).await;
    assert_eq!(
        service
            .withdraw(&input.record, &request, &TestPublishAccess, cutoff())
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
        service.published(p.id().digest().bytes(), cutoff()).await,
        Err(Error::PublicationNotFound)
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
