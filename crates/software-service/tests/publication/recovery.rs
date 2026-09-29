use super::*;

#[tokio::test]
#[ignore = "real PG COMMIT ACK loss + HTTPS: make t2 MODULE=publication.recovery"]
async fn publication_result_commit_unknown_recovers_one_external_call_and_audit() {
    let server = Server::new().await;
    let proxy = ack::AckProxy::start().await;
    let runtime = runtime_at(Some(proxy.port), "mdm_software_driver").await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let input = seed(runtime.clone(), &server, server.winget_submission()).await;
    service.create_candidate(&input, cutoff()).await.unwrap();
    let p = authorize(&service, &input.candidate, rel::Ring::Test).await;
    let gate = ack::CommitGate::start(input.candidate.value()).await;
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
    assert!(matches!(
        service
            .reconcile(p.id(), 1, at(10), publication_support::pg::cutoff())
            .await
            .unwrap(),
        rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
    ));
    assert_eq!(server.state.lock().unwrap().posts, 1);
    assert_eq!(
        audit_records()
            .iter()
            .filter(|r| r.event().facts().action().as_str() == "software_result"
                && r.event().facts().resource().id().as_str() == input.candidate.value())
            .count(),
        1
    );
    let target:serde_json::Value=serde_json::from_str(&sql(&format!("SELECT convert_from(document,'UTF8') FROM mdm_software_composition.targets WHERE candidate='{}' AND left(id,2)='p:'",input.candidate.value()))).unwrap();
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
    runtime.close().await;
}
