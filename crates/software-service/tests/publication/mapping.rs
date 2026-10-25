use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS: make t2 MODULE=publication.mapping"]
async fn record_receipts_and_persisted_source_admission() {
    let server = Server::new().await;
    let runtime = runtime().await;
    let content = stored_content().await;
    let (audit_store, audit_pool) = publication_support::pg::audit_store(runtime.clone()).await;
    let service = server
        .service(
            runtime.clone(),
            audit_store.clone(),
            content.clone(),
            server.winget(),
        )
        .await;
    let mut input = seed(runtime.clone(), &content, &server, server.winget_document()).await;
    let original = input.resource_digest;
    input.resource_digest = [0; 32];
    assert!(matches!(
        service
            .submit(&bound_input(&service, &input), &TestPublishAccess, cutoff())
            .await,
        Err(Error::Content)
    ));
    input.resource_digest = original;
    let (_, replayed) = service
        .submit(&bound_input(&service, &input), &TestPublishAccess, cutoff())
        .await
        .unwrap();
    assert!(!replayed);
    input.expected_resource_revision += 1;
    assert!(matches!(
        service
            .submit(&bound_input(&service, &input), &TestPublishAccess, cutoff())
            .await,
        Err(Error::Conflict)
    ));
    input.record = rel::PublicationKey::new(tenant(), unique()).unwrap();
    input.request = rel::RequestId::new(tenant(), uuid::Uuid::new_v4().to_string()).unwrap();
    assert!(matches!(
        service
            .submit(&bound_input(&service, &input), &TestPublishAccess, cutoff())
            .await,
        Err(Error::Conflict)
    ));
    input.expected_resource_revision -= 1;
    let connect = || async {
        PublicationService::connect(
            try_host(runtime.clone(), audit_store.clone(), content.clone())
                .await
                .map_err(|_| Error::Identity)?,
            tenant(),
            server.logical.clone(),
            server.winget(),
            actors(),
            cutoff(),
        )
        .await
    };
    sql("GRANT SELECT ON mdm_access.credentials TO mdm_software_driver");
    let extra = connect().await;
    sql("REVOKE SELECT ON mdm_access.credentials FROM mdm_software_driver");
    assert!(extra.is_err());
    assert!(connect().await.is_ok());
    sql("GRANT INSERT ON mdm_audit.receipts TO mdm_software_driver WITH GRANT OPTION");
    let delegation = connect().await;
    sql(
        "REVOKE INSERT ON mdm_audit.receipts FROM mdm_software_driver; GRANT INSERT(tenant_id,source_id,event_id,fingerprint,source_bytes,message_id,reserved,enqueued_at) ON mdm_audit.receipts TO mdm_software_driver",
    );
    assert!(delegation.is_err());
    assert!(connect().await.is_ok());
    sql("ALTER POLICY tenant ON mdm_audit.receipts USING(true) WITH CHECK(true)");
    let broad = connect().await;
    sql(
        "ALTER POLICY tenant ON mdm_audit.receipts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
    );
    assert!(broad.is_err());
    assert!(connect().await.is_ok());
    assert!(
        PublicationService::connect(
            host(runtime.clone(), audit_store.clone(), content.clone()).await,
            tenant(),
            format!("{}-alias", server.logical),
            server.winget(),
            actors(),
            cutoff()
        )
        .await
        .is_err()
    );
    let mut swapped = server.winget();
    let SourceConfig::Winget(c) = &mut swapped else {
        panic!()
    };
    c.artifacts_base.push_str("changed/");
    assert!(
        PublicationService::connect(
            host(runtime.clone(), audit_store.clone(), content.clone()).await,
            tenant(),
            server.logical.clone(),
            swapped,
            actors(),
            cutoff()
        )
        .await
        .is_err()
    );
    runtime.close().await;
    content.close().await;
    audit_pool.close().await;
}
