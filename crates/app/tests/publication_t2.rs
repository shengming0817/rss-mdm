use rss_mdm_app::software_publication::*;
use rss_mdm_software_release as rel;
mod publication_support;
use publication_support::pg::*;
use publication_support::*;
#[tokio::test]
#[ignore = "real PG + HTTPS + Git: publication-t2"]
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
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, at(10), cutoff())
            .await
            .unwrap(),
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
#[ignore = "real PG + HTTPS: publication-t2"]
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
        .approve(&input.candidate, rel::Ring::Test, &request(&c), cutoff())
        .await
        .unwrap();
    let c = service
        .candidate(&input.candidate, cutoff())
        .await
        .unwrap()
        .unwrap();
    let r = request(&c);
    sql("REVOKE INSERT ON mdm_access.audit FROM mdm_software_driver");
    let failed = service
        .authorize(&input.candidate, rel::Ring::Test, &r, cutoff())
        .await;
    sql("GRANT INSERT ON mdm_access.audit TO mdm_software_driver");
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
            .withdraw(&input.candidate, rel::Ring::Test, at(10), cutoff())
            .await
            .unwrap(),
        Withdrawal::Pending
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
        Withdrawal::Pending
    );
    assert_eq!(server.state.lock().unwrap().deletes, 0);
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, at(10), cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PG + HTTPS + bare Git: publication-t2"]
async fn brew_full_version_recovery_shared_tap_and_old_version_withdrawal() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let (_root, config) = brew_config();
    let service = server.service(runtime.clone(), config.clone()).await;
    let first = seed(runtime.clone(), &server, cask(&server, "app", "1")).await;
    service.create_candidate(&first, cutoff()).await.unwrap();
    let p1 = authorize(&service, &first.candidate, rel::Ring::Test).await;
    assert!(matches!(
        service.publish(p1.id(), 1, at(10), cutoff()).await.unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    let old = git(&config, &["rev-parse", "refs/heads/main"]);
    let other = seed(runtime.clone(), &server, formula(&server)).await;
    service.create_candidate(&other, cutoff()).await.unwrap();
    let p2 = authorize(&service, &other.candidate, rel::Ring::Test).await;
    service.publish(p2.id(), 1, at(10), cutoff()).await.unwrap();
    let second = seed(runtime.clone(), &server, cask(&server, "app", "2")).await;
    service.create_candidate(&second, cutoff()).await.unwrap();
    let p3 = authorize(&service, &second.candidate, rel::Ring::Test).await;
    service.publish(p3.id(), 1, at(10), cutoff()).await.unwrap();
    let current = git(&config, &["rev-parse", "refs/heads/main"]);
    assert_eq!(
        service
            .withdraw(&first.candidate, rel::Ring::Test, at(10), cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    assert_eq!(git(&config, &["rev-parse", "refs/heads/main"]), current);
    assert!(git(&config, &["show", "refs/heads/main:Casks/app.rb"]).contains("version \"2\""));
    assert_eq!(
        service
            .withdraw(&second.candidate, rel::Ring::Test, at(10), cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    assert!(git(&config, &["show", "refs/heads/main:Formula/tool.rb"]).contains("class Tool"));
    assert!(
        git(&config, &["show", &format!("{}:Casks/app.rb", old.trim())]).contains("version \"1\"")
    );
    assert!(!server.state.lock().unwrap().artifact_auth_leaked);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PG + HTTPS: publication-t2"]
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
            .withdraw(&input.candidate, rel::Ring::Production, at(10), cutoff())
            .await
            .unwrap(),
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
    server.state.lock().unwrap().drop_delete_response = true;
    assert_eq!(
        service
            .withdraw(&input.candidate, rel::Ring::Test, at(10), cutoff())
            .await
            .unwrap(),
        Withdrawal::Pending
    );
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Withdrawal::Pending
    );
    assert_eq!(server.state.lock().unwrap().deletes, 1);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PG + HTTPS: publication-t2"]
async fn complete_variant_mapping_and_resource_reference_protection() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let mut input = seed(runtime.clone(), &server, server.winget_submission()).await;
    let original = input.submission.clone();
    let Submission::Winget { manifest } = &mut input.submission else {
        panic!()
    };
    manifest["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(matches!(
        service.create_candidate(&input, cutoff()).await,
        Err(Error::Content)
    ));
    input.submission = original;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let r = rss_mdm_resource_postgres::Request {
        id: id(&unique()),
        resource: input.resource.clone(),
        expected_storage_revision: 2,
        as_of: at(10),
        command: rss_mdm_resource_postgres::Command::Archive {
            version: input.version.clone(),
            references: 0,
        },
    };
    assert!(matches!(
        service.archive_resource(&r, cutoff()).await,
        Err(Error::Blocked)
    ));
    let mut same = server.winget();
    same[1] = same[0].clone();
    assert!(
        PublicationService::connect(
            runtime.clone(),
            tenant(),
            server.logical.clone(),
            same,
            server.artifacts(),
            actors(),
            cutoff()
        )
        .await
        .is_err()
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + HTTPS: publication-t2"]
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
#[tokio::test]
#[ignore = "real HTTPS: publication-t2"]
async fn public_artifact_digest_length_tls_redirect_and_timeout_fail_closed() {
    let server = Server::new().await;
    let url = format!("{}artifacts/x64.msi", server.base);
    let digest = rel::Digest::of(b"abc").bytes();
    let reader = server.artifacts();
    reader.verify(&url, 3, digest).await.unwrap();
    assert!(matches!(
        reader.verify(&url, 2, digest).await,
        Err(Error::ArtifactDigest)
    ));
    assert!(matches!(
        reader.verify(&url, 3, [0; 32]).await,
        Err(Error::ArtifactDigest)
    ));
    assert!(matches!(
        reader.verify(&url, 1024 * 1024 + 1, digest).await,
        Err(Error::ArtifactBudget)
    ));
    assert!(matches!(
        reader
            .verify(&format!("{}artifacts/redirect", server.base), 3, digest)
            .await,
        Err(Error::ArtifactTransport)
    ));
    let untrusted = ArtifactReader::new(
        vec![ArtifactOrigin {
            base: format!("{}artifacts/", server.base),
            addresses: vec![server.address],
            private_ca: None,
        }],
        1024,
        std::time::Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(
        untrusted.verify(&url, 3, digest).await,
        Err(Error::ArtifactTransport)
    ));
    let bounded = ArtifactReader::new(
        vec![ArtifactOrigin {
            base: format!("{}artifacts/", server.base),
            addresses: vec![server.address],
            private_ca: Some(server.ca.clone()),
        }],
        1024,
        std::time::Duration::from_millis(100),
    )
    .unwrap();
    assert!(matches!(
        bounded
            .verify(&format!("{}artifacts/timeout", server.base), 3, digest)
            .await,
        Err(Error::ArtifactTimeout)
    ));
    assert!(!server.state.lock().unwrap().artifact_auth_leaked);
}
