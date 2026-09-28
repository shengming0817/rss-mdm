use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS + Git: make t2 MODULE=publication.winget"]
async fn full_version_publication_recovery_and_public_artifact_boundary() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_submission()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = authorize(&service, &input.candidate, rel::Ring::Test).await;
    sql(
        "CREATE FUNCTION public.reject_release_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_release_result();",
    );
    let failed = service.publish(p.id(), p.attempt, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_release_result();",
    );
    assert!(failed.is_err());
    assert_eq!(server.state.lock().unwrap().posts, 1);
    drop(service);
    let service = server.service(runtime.clone(), server.winget()).await;
    assert!(matches!(
        service
            .reconcile(p.id(), p.attempt, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert_eq!(server.state.lock().unwrap().posts, 1);
    assert_publication_audit(&p, &input.candidate, "applied");
    assert!(!server.state.lock().unwrap().artifact_auth_leaked);
    assert_eq!(
        server
            .state
            .lock()
            .unwrap()
            .manifests
            .values()
            .next()
            .unwrap()["Versions"][0]["Installers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let withdrawal_request = request_for(&service, &input.candidate).await;
    assert_eq!(
        service
            .withdraw(
                &input.candidate,
                rel::Ring::Test,
                &withdrawal_request,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert_eq!(server.state.lock().unwrap().deletes, 1);
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), p.attempt, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    assert_eq!(server.state.lock().unwrap().deletes, 1);
    assert_eq!(
        service
            .withdraw(
                &input.candidate,
                rel::Ring::Test,
                &withdrawal_request,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert_eq!(server.state.lock().unwrap().deletes, 1);
    let c = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.snapshot().disposition, rel::Disposition::Quarantined);
    assert!(c.snapshot().rings[0].is_published());
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + HTTPS: make t2 MODULE=publication.winget"]
async fn unknown_publication_blocks_withdrawal_and_audit_failure_rolls_back() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_submission()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let c = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    service
        .validate(&input.candidate, rel::Ring::Test, &request(&c), cutoff())
        .await
        .unwrap();
    let c = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    service
        .approve(
            &input.candidate,
            rel::Ring::Test,
            &rel::ActorId::new(tenant(), "publisher").unwrap(),
            &request(&c),
            cutoff(),
        )
        .await
        .unwrap();
    let c = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    let r = request(&c);
    sql("REVOKE INSERT ON mdm_audit.receipts FROM mdm_software_driver");
    let failed = service
        .authorize(&input.candidate, rel::Ring::Test, &r, cutoff())
        .await;
    sql("GRANT INSERT ON mdm_audit.receipts TO mdm_software_driver");
    assert!(failed.is_err());
    assert_eq!(
        service
            .candidate(&input.candidate, cutoff())
            .await
            .unwrap()
            .unwrap(),
        c
    );
    let rel::Transition::Applied {
        decision: rel::Decision::Publish(p),
        ..
    } = service
        .authorize(&input.candidate, rel::Ring::Test, &r, cutoff())
        .await
        .unwrap()
    else {
        panic!()
    };
    {
        let mut state = server.state.lock().unwrap();
        state.drop_post_response = true;
        state.hidden_reads = 1;
    }
    assert!(matches!(
        service.publish(p.id(), 1, at(10), cutoff()).await.unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Unknown(_))
    ));
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
        Withdrawal::WaitingPublication
    );
    assert_publication_audit(&p, &input.candidate, "unknown");
    assert_eq!(
        service
            .withdrawal_status(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Some(Withdrawal::WaitingPublication)
    );
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    assert!(matches!(
        service
            .reconcile(p.id(), 1, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert_eq!(server.state.lock().unwrap().posts, 1);
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Withdrawal::PreflightRetryable
    );
    assert_eq!(server.state.lock().unwrap().deletes, 0);
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
        Withdrawal::Complete
    );
    runtime.close().await;
}
