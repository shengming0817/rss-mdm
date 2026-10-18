use super::*;

#[tokio::test]
#[ignore = "real PG COMMIT ACK loss + HTTPS: make t2 MODULE=publication.recovery"]
async fn publication_result_commit_unknown_recovers_one_projection_and_audit() {
    let server = Server::new().await;
    let proxy = ack::AckProxy::start().await;
    let runtime = runtime_at(Some(proxy.port), "mdm_software_driver").await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_document()).await;
    let p = submit_publication(&service, &input).await;
    let gate = ack::CommitGate::start(input.record.value()).await;
    let cutoff =
        rss_request_context::Deadline::from_timeout(&Timer, std::time::Duration::from_secs(7))
            .unwrap();
    let mut operation = Box::pin(service.publish(p.id(), 1, at(10), cutoff));
    tokio::select! {_=gate.entered()=>{}, result=&mut operation=>panic!("publication returned before result COMMIT: {result:?}")}
    proxy
        .discard
        .store(true, std::sync::atomic::Ordering::SeqCst);
    gate.release();
    let result = operation.await;
    assert!(matches!(result, Err(Error::CommitUnknown(_))), "{result:?}");
    drop(gate);
    drop(service);
    runtime.close().await;
    drop(proxy);
    let runtime = publication_support::pg::runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let publication = p
        .id()
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let committed = || {
        sql(&format!(
            "SELECT jsonb_build_object('receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM mdm_software_release.requests r WHERE tenant_id='{}' AND owner='{}'),'slots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.binding,s.coordinate) FROM mdm_software_composition.slots s JOIN mdm_software_composition.projections p USING(tenant_id,binding,coordinate) WHERE publication=decode('{publication}','hex')),'projections',(SELECT jsonb_agg(to_jsonb(p) ORDER BY binding) FROM mdm_software_composition.projections p WHERE tenant_id='{}' AND publication=decode('{publication}','hex')))",
            tenant(),
            input.record.value(),
            tenant()
        ))
    };
    let before = committed();
    let facts: serde_json::Value = serde_json::from_str(&before).unwrap();
    assert!(
        facts["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"].as_str().unwrap().starts_with("record/"))
    );
    assert_eq!(facts["projections"].as_array().unwrap().len(), 1);
    assert_eq!(facts["slots"].as_array().unwrap().len(), 1);
    assert!(facts["slots"][0]["operation"].is_null());
    assert_publication_audit(&p, &input.record, "applied");
    assert_eq!(
        audit_records()
            .iter()
            .filter(|r| r.event().facts().action().as_str() == "software_result"
                && r.event().facts().resource().id().as_str() == input.record.value())
            .count(),
        1
    );
    assert!(
        service
            .published(p.id().digest().bytes(), publication_support::pg::cutoff())
            .await
            .is_ok()
    );
    assert!(matches!(
        service
            .reconcile(p.id(), 1, at(10), publication_support::pg::cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert_eq!(server.state.lock().unwrap().posts, 0);
    assert_eq!(
        audit_records()
            .iter()
            .filter(|r| r.event().facts().action().as_str() == "software_result"
                && r.event().facts().resource().id().as_str() == input.record.value())
            .count(),
        1
    );
    let target:serde_json::Value=serde_json::from_str(&sql(&format!("SELECT convert_from(document,'UTF8') FROM mdm_software_composition.targets WHERE record='{}' AND left(id,2)='p:'",input.record.value()))).unwrap();
    let binding = target["binding"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| format!("{:02x}", b.as_u64().unwrap()))
        .collect::<String>();
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_software_composition.slots WHERE binding=decode('{binding}','hex') AND operation IS NOT NULL"
        )),
        "0"
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_software_composition.projections WHERE binding=decode('{binding}','hex')"
        )),
        "1"
    );
    assert_publication_audit(&p, &input.record, "applied");
    assert_eq!(
        committed(),
        before,
        "reconcile changed committed publication facts"
    );
    runtime.close().await;
}
