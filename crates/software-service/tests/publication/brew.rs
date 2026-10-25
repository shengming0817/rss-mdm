use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS + bare Git: make t2 MODULE=publication.brew"]
async fn brew_immutable_tap_recovery_and_version_specific_withdrawal() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let content = stored_content().await;
    let (audit_store, audit_pool) = publication_support::pg::audit_store(runtime.clone()).await;
    let (_root, config) = brew_config();
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config.clone(),
        )
        .await;
    let first = seed(
        runtime.clone(),
        &content,
        &server,
        cask(&server, "app", "1"),
    )
    .await;
    let p1 = submit_publication(&service, &first).await;
    sql(
        "CREATE FUNCTION public.reject_brew_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_brew_result();",
    );
    let failed = service.publish(p1.id(), 1, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_brew_result();",
    );
    assert!(matches!(failed, Err(Error::RolledBack(_))), "{failed:?}");
    let snapshot = git(&config, &["rev-parse", "refs/heads/main"]);
    assert!(
        git(
            &config,
            &["for-each-ref", "--format=%(refname)", "refs/namespaces"]
        )
        .contains(snapshot.trim())
    );
    let pending = service
        .record(&first.record, cutoff())
        .await
        .unwrap()
        .unwrap();
    assert!(
        pending.snapshot().attempt.id() == p1.id()
            && matches!(
                pending.snapshot().attempt.outcome,
                rel::PublicationOutcome::Pending
            )
    );
    // Re-enabling the source changes its generation while the external result is unknown.
    sql(&format!(
        "UPDATE mdm_software.sources SET lifecycle=jsonb_set(lifecycle,'{{revision}}',to_jsonb((lifecycle->>'revision')::bigint+2)) WHERE tenant_id='{}' AND id='{}'",
        tenant(),
        server.logical
    ));
    drop(service);
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config.clone(),
        )
        .await;
    assert!(matches!(
        service
            .reconcile(p1.id(), 1, at(10), cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert!(matches!(
        service.published(p1.id().digest().bytes(), cutoff()).await,
        Err(Error::Content)
    ));
    let old = git(&config, &["rev-parse", "refs/heads/main"]);
    let other = seed(runtime.clone(), &content, &server, formula(&server)).await;
    let p2 = submit_publication(&service, &other).await;
    service.publish(p2.id(), 1, at(10), cutoff()).await.unwrap();
    let second = seed(
        runtime.clone(),
        &content,
        &server,
        cask(&server, "app", "2"),
    )
    .await;
    let p3 = submit_publication(&service, &second).await;
    service.publish(p3.id(), 1, at(10), cutoff()).await.unwrap();
    let current = git(&config, &["rev-parse", "refs/heads/main"]);
    assert_eq!(
        service
            .withdraw(
                &first.record,
                &request_for(&service, &first.record).await,
                &TestPublishAccess,
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
                &second.record,
                &request_for(&service, &second.record).await,
                &TestPublishAccess,
                cutoff()
            )
            .await
            .unwrap()
            .outcome,
        Withdrawal::Complete
    );
    // Each native Tap contains precisely its frozen definition and dependencies.
    let other_snapshot = service
        .published(p2.id().digest().bytes(), cutoff())
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
            .published(p2.id().digest().bytes(), cutoff())
            .await
            .is_ok()
    );
    assert!(matches!(
        service.published(p1.id().digest().bytes(), cutoff()).await,
        Err(Error::PublicationNotFound)
    ));
    assert!(matches!(
        service.published(p3.id().digest().bytes(), cutoff()).await,
        Err(Error::PublicationNotFound)
    ));
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
    content.close().await;
    audit_pool.close().await;
}

#[tokio::test]
#[ignore = "real PG + Git: make t2 MODULE=publication.brew"]
async fn attempted_publication_withdrawal_recovers_original_git_snapshot_after_restart() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let content = stored_content().await;
    let (audit_store, audit_pool) = publication_support::pg::audit_store(runtime.clone()).await;
    let (_root, config) = brew_config();
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config.clone(),
        )
        .await;
    let input = seed(
        runtime.clone(),
        &content,
        &server,
        cask(&server, "app", "1"),
    )
    .await;
    let p = submit_publication(&service, &input).await;
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
    let SourceConfig::Brew(source) = &config else {
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
    let request = request_for(&service, &input.record).await;
    service
        .withdraw(&input.record, &request, &TestPublishAccess, cutoff())
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
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config.clone(),
        )
        .await;
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
    content.close().await;
    audit_pool.close().await;
}

#[tokio::test]
#[ignore = "real PG + Git: make t2 MODULE=publication.brew"]
async fn unknown_withdrawal_only_settles_absence_after_original_cas_is_fenced() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let content = stored_content().await;
    let (audit_store, audit_pool) = publication_support::pg::audit_store(runtime.clone()).await;
    let (_root, config) = brew_config();
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config.clone(),
        )
        .await;
    let first = seed(
        runtime.clone(),
        &content,
        &server,
        cask(&server, "app", "1"),
    )
    .await;
    let initial = submit_publication(&service, &first).await;
    service
        .publish(initial.id(), initial.attempt, at(10), cutoff())
        .await
        .unwrap();
    let second = seed(
        runtime.clone(),
        &content,
        &server,
        cask(&server, "app", "2"),
    )
    .await;
    let p = submit_publication(&service, &second).await;
    let SourceConfig::Brew(source) = &config else {
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
    let original: serde_json::Value = serde_json::from_str(&sql(&format!("SELECT convert_from(document,'UTF8') FROM mdm_software_composition.targets WHERE tenant_id='{}' AND record='{}' AND left(id,2)='p:'", tenant(), second.record.value()))).unwrap();
    let request = request_for(&service, &second.record).await;
    assert_eq!(
        service
            .withdraw(&second.record, &request, &TestPublishAccess, cutoff())
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
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config.clone(),
        )
        .await;
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
    let SourceConfig::Brew(source) = &config else {
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
    content.close().await;
    audit_pool.close().await;
}

#[tokio::test]
#[ignore = "real PG + HTTPS + bare Git: make t2 MODULE=publication.brew"]
async fn withdrawal_settles_a_result_observed_after_its_intent() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let content = stored_content().await;
    let (audit_store, audit_pool) = publication_support::pg::audit_store(runtime.clone()).await;
    let (_root, config) = brew_config();
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            config,
        )
        .await;
    let input = seed(
        runtime.clone(),
        &content,
        &server,
        cask(&server, "late", "1"),
    )
    .await;
    let p = submit_publication(&service, &input).await;
    sql(
        "CREATE FUNCTION public.reject_late_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_late_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_late_result();",
    );
    let result = service.publish(p.id(), 1, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_late_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_late_result();",
    );
    assert!(matches!(result, Err(Error::RolledBack(_))));
    withdraw_version(&input).await;
    let observed_at = at(sql(&format!("SELECT (convert_from(document,'UTF8')::jsonb->>'commit_at')::bigint+20 FROM mdm_software_composition.withdrawals WHERE record='{}'", input.record.value())).parse().unwrap());
    // Reproduce an in-flight observation committing after the withdrawal intent.
    let store =
        rss_mdm_software_release_postgres::ReleaseStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
    store
        .transition(
            &input.record,
            &rel::Request {
                id: rel::RequestId::new(tenant(), unique()).unwrap(),
                actor: input.actor.clone(),
                expected_revision: 0,
                as_of: observed_at,
                operation: rel::Operation::Record {
                    publication: p.id(),
                    attempt: 1,
                    outcome: rel::PublicationResult::Unknown(rel::Evidence {
                        actor: input.actor.clone(),
                        digest: rel::Digest::from_bytes([17; 32]),
                        at: observed_at,
                    }),
                },
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    let record = service
        .record(&input.record, cutoff())
        .await
        .unwrap()
        .unwrap();
    assert!(record.snapshot().withdrawn);
    assert!(record.snapshot().at >= observed_at);
    assert!(matches!(
        record.snapshot().attempt.outcome,
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert_eq!(
        service
            .reconcile_withdrawal(p.id(), 1, cutoff())
            .await
            .unwrap(),
        Withdrawal::Complete
    );
    runtime.close().await;
    content.close().await;
    audit_pool.close().await;
}
