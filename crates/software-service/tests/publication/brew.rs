use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS + bare Git: make t2 MODULE=publication.brew"]
async fn brew_immutable_tap_recovery_and_version_specific_withdrawal() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let (_root, config) = brew_config();
    let service = server.service(runtime.clone(), config.clone()).await;
    let first = seed(runtime.clone(), &server, cask(&server, "app", "1")).await;
    service.create_candidate(&first, cutoff()).await.unwrap();
    let p1 = submit_publication(&service, &first.candidate, rel::Ring::Test).await;
    sql(
        "CREATE FUNCTION public.reject_brew_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_brew_result();",
    );
    let failed = service.publish(p1.id(), 1, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_brew_result();",
    );
    assert!(failed.is_err());
    // Re-enabling the source changes its generation while the external result is unknown.
    sql(&format!(
        "UPDATE mdm_software.sources SET lifecycle=jsonb_set(lifecycle,'{{revision}}',to_jsonb((lifecycle->>'revision')::bigint+2)) WHERE tenant_id='{}' AND id='{}'",
        tenant(),
        server.logical
    ));
    drop(service);
    let service = server.service(runtime.clone(), config.clone()).await;
    assert!(matches!(
        service
            .reconcile(p1.id(), 1, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert!(
        service
            .published(rel::Ring::Test, p1.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    let old = git(&config, &["rev-parse", "refs/heads/main"]);
    let other = seed(runtime.clone(), &server, formula(&server)).await;
    service.create_candidate(&other, cutoff()).await.unwrap();
    let p2 = submit_publication(&service, &other.candidate, rel::Ring::Test).await;
    service.publish(p2.id(), 1, at(10), cutoff()).await.unwrap();
    let second = seed(runtime.clone(), &server, cask(&server, "app", "2")).await;
    service.create_candidate(&second, cutoff()).await.unwrap();
    let p3 = submit_publication(&service, &second.candidate, rel::Ring::Test).await;
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
    // Each native Tap contains precisely its frozen definition and dependencies.
    let other_snapshot = service
        .published(rel::Ring::Test, p2.id().digest().bytes(), cutoff())
        .await
        .unwrap()
        .snapshot
        .unwrap();
    assert!(
        git(
            &config,
            &["show", &format!("{other_snapshot}:Formula/tool.rb")]
        )
        .contains("class Tool")
    );
    assert!(
        service
            .published(rel::Ring::Test, p2.id().digest().bytes(), cutoff())
            .await
            .is_ok()
    );
    assert!(
        service
            .published(rel::Ring::Test, p1.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    assert!(
        service
            .published(rel::Ring::Test, p3.id().digest().bytes(), cutoff())
            .await
            .is_err()
    );
    assert_eq!(
        git(
            &config,
            &["rev-list", "--parents", "-n", "1", current.trim()]
        )
        .split_whitespace()
        .count(),
        1
    );
    let refs = git(
        &config,
        &["for-each-ref", "--format=%(refname)", "refs/namespaces"],
    );
    assert!(refs.contains(&other_snapshot));
    assert!(!refs.contains(old.trim()));
    assert!(!refs.contains(current.trim()));
    assert!(
        git(&config, &["show", &format!("{}:Casks/app.rb", old.trim())]).contains("version \"1\"")
    );
    assert!(!server.state.lock().unwrap().artifact_auth_leaked);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + Git: make t2 MODULE=publication.brew"]
async fn attempted_publication_withdrawal_recovers_original_git_snapshot_after_restart() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let (_root, config) = brew_config();
    let service = server.service(runtime.clone(), config.clone()).await;
    let input = seed(runtime.clone(), &server, cask(&server, "app", "1")).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = submit_publication(&service, &input.candidate, rel::Ring::Test).await;
    sql(
        "CREATE FUNCTION public.reject_brew_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_brew_result();",
    );
    assert!(
        service
            .publish(p.id(), p.attempt, at(10), cutoff())
            .await
            .is_err()
    );
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_brew_result();",
    );
    let snapshot = git(&config, &["rev-parse", "refs/heads/main"]);
    let SourceConfig::Brew(source) = &config.test else {
        panic!("Brew")
    };
    let lock = source.repository.join(format!(
        "refs/namespaces/{}/refs/heads/main.lock",
        snapshot.trim()
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .unwrap();
    let lock = tempfile::TempPath::try_from_path(lock).unwrap();
    let request = request_for(&service, &input.candidate).await;
    service
        .withdraw(&input.candidate, rel::Ring::Test, &request, cutoff())
        .await
        .unwrap();
    assert_ne!(
        service
            .withdrawal_status(p.id(), p.attempt, cutoff())
            .await
            .unwrap(),
        Some(Withdrawal::Complete)
    );
    assert!(
        git(
            &config,
            &["for-each-ref", "--format=%(refname)", "refs/namespaces"]
        )
        .contains(snapshot.trim())
    );
    lock.close().unwrap();
    drop(service);
    runtime.close().await;
    let runtime = publication_support::pg::runtime().await;
    let service = server.service(runtime.clone(), config.clone()).await;
    let work = service
        .reconciliation_page("", 32, cutoff())
        .await
        .unwrap()
        .work
        .into_iter()
        .find(|work| work.withdrawal && work.publication == p.id() && work.attempt == p.attempt)
        .expect("original incomplete withdrawal missing after reopen");
    service
        .reconcile_withdrawal(work.publication, work.attempt, cutoff())
        .await
        .unwrap();
    assert_eq!(
        service
            .withdrawal_status(p.id(), p.attempt, cutoff())
            .await
            .unwrap(),
        Some(Withdrawal::Complete)
    );
    assert!(
        !git(
            &config,
            &["for-each-ref", "--format=%(refname)", "refs/namespaces"]
        )
        .contains(snapshot.trim())
    );
    assert_eq!(
        sql("SELECT count(*) FROM mdm_software_composition.slots WHERE operation IS NOT NULL"),
        "0"
    );
    assert_eq!(
        sql("SELECT count(*) FROM mdm_software_composition.targets WHERE left(id,2)='p:'"),
        "1"
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PG + Git: make t2 MODULE=publication.brew"]
async fn unknown_withdrawal_only_settles_absence_after_original_cas_is_fenced() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let (_root, config) = brew_config();
    let service = server.service(runtime.clone(), config.clone()).await;
    let first = seed(runtime.clone(), &server, cask(&server, "app", "1")).await;
    service.create_candidate(&first, cutoff()).await.unwrap();
    let initial = submit_publication(&service, &first.candidate, rel::Ring::Test).await;
    service
        .publish(initial.id(), initial.attempt, at(10), cutoff())
        .await
        .unwrap();
    let second = seed(runtime.clone(), &server, cask(&server, "app", "2")).await;
    service.create_candidate(&second, cutoff()).await.unwrap();
    let p = submit_publication(&service, &second.candidate, rel::Ring::Test).await;
    let SourceConfig::Brew(source) = &config.test else {
        panic!("Brew");
    };
    let lock = source.repository.join("refs/heads/main.lock");
    std::fs::write(&lock, b"fixture").unwrap();
    assert!(matches!(
        service
            .publish(p.id(), p.attempt, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Unknown(_))
    ));
    let original: serde_json::Value = serde_json::from_str(&sql(&format!("SELECT convert_from(document,'UTF8') FROM mdm_software_composition.targets WHERE tenant_id='{}' AND candidate='{}' AND left(id,2)='p:'", tenant(), second.candidate.value()))).unwrap();
    let request = request_for(&service, &second.candidate).await;
    assert_eq!(
        service
            .withdraw(&second.candidate, rel::Ring::Test, &request, cutoff())
            .await
            .unwrap()
            .outcome,
        Withdrawal::WaitingPublication
    );
    assert_eq!(
        sql("SELECT count(*) FROM mdm_software_composition.slots WHERE operation IS NOT NULL"),
        "1"
    );
    drop(service);
    std::fs::remove_file(lock).unwrap();
    git(&config, &["update-ref", "-d", "refs/heads/main"]);
    let service = server.service(runtime.clone(), config.clone()).await;
    let work = service
        .reconciliation_page("", 32, cutoff())
        .await
        .unwrap()
        .work
        .into_iter()
        .find(|w| w.withdrawal && w.publication == p.id() && w.attempt == p.attempt)
        .expect("original withdrawal missing");
    assert_eq!(
        service
            .reconcile_withdrawal(work.publication, work.attempt, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    let commit = original["commit"].as_str().unwrap();
    let base = original["base"].as_str().unwrap();
    let SourceConfig::Brew(source) = &config.test else {
        panic!("Brew")
    };
    let replay = std::process::Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(&source.repository)
        .args(["update-ref", "refs/heads/main", commit, base])
        .output()
        .unwrap();
    assert!(!replay.status.success(), "fenced original CAS succeeded");
    assert!(
        !git(
            &config,
            &["for-each-ref", "--format=%(refname)", "refs/namespaces"]
        )
        .contains(commit)
    );
    assert_eq!(
        sql("SELECT count(*) FROM mdm_software_composition.slots WHERE operation IS NOT NULL"),
        "0"
    );
    assert_eq!(
        service
            .withdrawal_status(p.id(), p.attempt, cutoff())
            .await
            .unwrap(),
        Some(Withdrawal::Complete)
    );
    assert_eq!(
        sql("SELECT count(*) FROM mdm_software_composition.targets WHERE left(id,2)='p:'"),
        "2"
    );
    runtime.close().await;
}
