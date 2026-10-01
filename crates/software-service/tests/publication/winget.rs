use super::*;

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.winget"]
async fn full_version_publication_recovery_and_public_artifact_boundary() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = authorize(&service, &input.candidate, rel::Ring::Test).await;
    assert!(
        service
            .published(rel::Ring::Test, p.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    sql(
        "CREATE FUNCTION public.reject_release_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_release_result();",
    );
    let failed = service.publish(p.id(), p.attempt, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_release_result();",
    );
    assert!(failed.is_err());
    assert_eq!(server.state.lock().unwrap().posts, 0);
    let page = service.reconciliation_page("", 32, cutoff()).await.unwrap();
    assert!(
        page.work.iter().any(|work| work.publication == p.id()
            && work.attempt == p.attempt
            && !work.withdrawal)
    );
    drop(service);
    let service = server.service(runtime.clone(), server.winget()).await;
    assert!(matches!(
        service
            .reconcile(p.id(), p.attempt, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    let served = service
        .published(rel::Ring::Test, p.id().digest().bytes(), cutoff())
        .await
        .unwrap();
    assert_eq!(served.resource_digest, input.resource_digest);
    let ExportDocument::Winget { manifest } = served.document else {
        panic!("native WinGet export");
    };
    assert_eq!(
        manifest["Versions"][0]["Installers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(served.artifacts.len(), 1);
    assert_publication_audit(&p, &input.candidate, "applied");
    assert!(
        service
            .reconciliation_page("", 32, cutoff())
            .await
            .unwrap()
            .work
            .is_empty()
    );
    let request = request_for(&service, &input.candidate).await;
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, &request, cutoff())
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert!(
        service
            .published(rel::Ring::Test, p.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), p.attempt, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    assert_eq!(server.state.lock().unwrap().posts, 0);
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.winget"]
async fn unstarted_publication_recovery_preserves_its_original_identity() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = authorize(&service, &input.candidate, rel::Ring::Test).await;
    let page = service.reconciliation_page("", 32, cutoff()).await.unwrap();
    let work = page
        .work
        .into_iter()
        .find(|work| work.publication == p.id())
        .unwrap();
    assert_eq!(work.attempt, p.attempt);
    assert!(matches!(
        service
            .reconcile(work.publication, work.attempt, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    let candidate = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    let rel::RingState::Publication(current) = candidate.snapshot().ring_state(rel::Ring::Test)
    else {
        panic!("publication")
    };
    assert_eq!(current.id(), p.id());
    assert_eq!(current.attempt, p.attempt);
    assert!(
        service
            .reconciliation_page("", 32, cutoff())
            .await
            .unwrap()
            .work
            .is_empty()
    );
    assert_eq!(server.state.lock().unwrap().posts, 0);
    runtime.close().await;
}
