use super::*;

#[tokio::test]
#[ignore = "real PG + content: make t2 MODULE=publication.winget"]
async fn full_version_publication_recovery_and_public_artifact_boundary() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    let p = submit_publication(&service, &input).await;
    assert!(matches!(
        service.published(p.id().digest().bytes(), cutoff()).await,
        Err(Error::PublicationNotFound)
    ));
    sql(
        "CREATE FUNCTION public.reject_release_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture result failure'; END $$; CREATE TRIGGER reject_result BEFORE UPDATE ON mdm_software_release.aggregates FOR EACH ROW EXECUTE FUNCTION public.reject_release_result();",
    );
    let failed = service.publish(p.id(), p.attempt, at(10), cutoff()).await;
    sql(
        "DROP TRIGGER reject_result ON mdm_software_release.aggregates; DROP FUNCTION public.reject_release_result();",
    );
    assert!(matches!(failed, Err(Error::RolledBack(_))), "{failed:?}");
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
        .published(p.id().digest().bytes(), cutoff())
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
    let installers = manifest["Versions"][0]["Installers"].as_array().unwrap();
    let architectures = installers
        .iter()
        .map(|i| i["Architecture"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(architectures, ["arm64", "x64"].into());
    for installer in installers {
        let artifact = served
            .artifacts
            .iter()
            .find(|a| installer["InstallerUrl"] == a.url)
            .expect("installer URL missing from hosted artifacts");
        assert_eq!(
            installer["InstallerSha256"],
            artifact
                .sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
    assert_eq!(served.artifacts.len(), 1);
    assert_publication_audit(&p, &input.record, "applied");
    assert!(
        service
            .reconciliation_page("", 32, cutoff())
            .await
            .unwrap()
            .work
            .is_empty()
    );
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
        service.published(p.id().digest().bytes(), cutoff()).await,
        Err(Error::PublicationNotFound)
    ));
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
    let p = submit_publication(&service, &input).await;
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
    let record = service
        .record(&input.record, cutoff())
        .await
        .unwrap()
        .unwrap();
    let current = &record.snapshot().attempt;
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

#[tokio::test]
#[ignore = "real PG: make t2 MODULE=publication.winget"]
async fn draft_publication_rolls_back_every_write_and_replay_rechecks_access() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed_draft(runtime.clone(), &server, server.winget_document()).await;
    let input = bound_input(&service, &input);
    let counts = || {
        sql(
            "SELECT (SELECT count(*) FROM mdm_software.versions),(SELECT count(*) FROM mdm_software.materials),(SELECT count(*) FROM rss_transactional_messaging.outbox),(SELECT count(*) FROM mdm_software_composition.targets),(SELECT count(*) FROM mdm_software_composition.slots WHERE operation IS NOT NULL)",
        )
    };
    let before = counts();
    sql(
        "CREATE SEQUENCE public.draft_fault_reached; GRANT USAGE ON SEQUENCE public.draft_fault_reached TO mdm_software_driver",
    );
    // Reject after catalog writes, once via a SQL error and once via a domain rejection.
    for (index, body) in [
        "RAISE EXCEPTION 'publication fixture rollback';",
        "UPDATE mdm_software.versions SET lifecycle=jsonb_set(lifecycle,'{state}','\"withdrawn\"') WHERE tenant_id=NEW.tenant_id AND resource=NEW.resource AND version=NEW.version;",
    ].into_iter().enumerate() {
        sql(&format!(
            "CREATE FUNCTION public.reject_draft_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.draft_fault_reached'); {body} RETURN NEW; END $$; CREATE TRIGGER reject_draft AFTER INSERT ON mdm_software.versions FOR EACH ROW EXECUTE FUNCTION public.reject_draft_publication();"
        ));
        let result = service
            .submit(
                &input,
                &TestPublishAccess,
                cutoff(),
            )
            .await;
        sql(
            "DROP TRIGGER reject_draft ON mdm_software.versions; DROP FUNCTION public.reject_draft_publication();",
        );
        assert!(matches!(result, Err(Error::Content)), "{result:?}");
        // The publication boundary deliberately maps catalog failures to Content.
        // Sequence advancement survives rollback and proves this trigger was reached.
        assert_eq!(sql("SELECT last_value FROM public.draft_fault_reached"), (index + 1).to_string());
        assert_eq!(sql("SELECT is_called FROM public.draft_fault_reached"), "t");
        assert_eq!(
            counts(),
            before,
            "failed publication committed partial effects"
        );
        assert!(service.record(&input.record,cutoff()).await.unwrap().is_none());
    }
    sql("DROP SEQUENCE public.draft_fault_reached");
    let applied = service
        .submit(&input, &TestPublishAccess, cutoff())
        .await
        .unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_software.versions WHERE resource='{}'",
            input.resource.as_str()
        )),
        "1"
    );
    let (receipt, replayed) = applied;
    assert!(!replayed);
    let next = service
        .record(&input.record, cutoff())
        .await
        .unwrap()
        .unwrap();
    let persisted_receipt = || {
        sql(&format!(
            "SELECT to_jsonb(r) FROM mdm_software_release.requests r WHERE tenant_id='{}' AND id='{}'",
            tenant(),
            input.request.value()
        ))
    };
    let original_receipt = persisted_receipt();
    assert!(!original_receipt.is_empty());
    let publish_audits = || {
        audit_records()
            .iter()
            .filter(|r| {
                r.event().facts().action().as_str() == "software_publish"
                    && r.event().facts().resource().id().as_str() == input.record.value()
            })
            .count()
    };
    assert_eq!(publish_audits(), 1);
    let after = counts();
    assert_eq!(
        service
            .submit(&input, &TestPublishAccess, cutoff())
            .await
            .unwrap(),
        (receipt, true)
    );
    assert_eq!(
        service
            .record(&input.record, cutoff())
            .await
            .unwrap()
            .unwrap(),
        next
    );
    assert_eq!(persisted_receipt(), original_receipt);
    assert_eq!(publish_audits(), 1);
    assert_eq!(counts(), after);
    struct Revoked;
    impl PublishAccess for Revoked {
        fn check<'a, 'c>(
            &'a self,
            _tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'c>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>>
        {
            Box::pin(async { Err(Error::Identity) })
        }
    }
    assert!(matches!(
        service.submit(&input, &Revoked, cutoff()).await,
        Err(Error::Identity)
    ));
    assert_eq!(counts(), after);
    runtime.close().await;
}
