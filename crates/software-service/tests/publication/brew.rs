use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS + bare Git: make t2 MODULE=publication.brew"]
async fn brew_full_version_recovery_shared_tap_and_old_version_withdrawal() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let (_root, config) = brew_config();
    let service = server.service(runtime.clone(), config.clone()).await;
    let first = seed(runtime.clone(), &server, cask(&server, "app", "1")).await;
    service.create_candidate(&first, cutoff()).await.unwrap();
    let p1 = authorize(&service, &first.candidate, rel::Ring::Test).await;
    sql(
        "CREATE FUNCTION public.reject_brew_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_brew_result();",
    );
    let failed = service.publish(p1.id(), 1, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_brew_result();",
    );
    assert!(failed.is_err());
    drop(service);
    let service = server.service(runtime.clone(), config.clone()).await;
    assert!(matches!(
        service
            .reconcile(p1.id(), 1, at(10), cutoff())
            .await
            .unwrap(),
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
            .withdraw(
                &first.candidate,
                rel::Ring::Test,
                &request_for(&service, &first.candidate).await,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert_eq!(git(&config, &["rev-parse", "refs/heads/main"]), current);
    assert!(git(&config, &["show", "refs/heads/main:Casks/app.rb"]).contains("version \"2\""));
    assert_eq!(
        service
            .withdraw(
                &second.candidate,
                rel::Ring::Test,
                &request_for(&service, &second.candidate).await,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    assert!(git(&config, &["show", "refs/heads/main:Formula/tool.rb"]).contains("class Tool"));
    assert!(
        git(&config, &["show", &format!("{}:Casks/app.rb", old.trim())]).contains("version \"1\"")
    );
    assert!(!server.state.lock().unwrap().artifact_auth_leaked);
    runtime.close().await;
}
