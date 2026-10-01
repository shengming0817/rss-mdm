use super::*;

#[tokio::test]
#[ignore = "real PG + HTTPS: make t2 MODULE=publication.mapping"]
async fn complete_variant_mapping_and_resource_reference_protection() {
    let audit_store = audit_store().await;
    let server = Server::new().await;
    let runtime = runtime().await;
    let service = server.service(runtime.clone(), server.winget()).await;
    let mut input = seed(runtime.clone(), &server, server.winget_document()).await;
    let original = input.resource_digest;
    input.resource_digest = [0; 32];
    assert!(matches!(
        service.create_candidate(&input, cutoff()).await,
        Err(Error::Content)
    ));
    input.resource_digest = original;
    let (receipt, replayed) = service.create_candidate(&input, cutoff()).await.unwrap();
    assert!(!replayed);
    assert_eq!(
        service.create_candidate(&input, cutoff()).await.unwrap(),
        (receipt, true)
    );
    input.expected_resource_revision += 1;
    assert!(matches!(
        service.create_candidate(&input, cutoff()).await,
        Err(Error::Conflict)
    ));
    input.expected_resource_revision -= 1;
    let mut same = server.winget();
    same.pilot = same.test.clone();
    assert!(
        PublicationService::connect(
            host(runtime.clone(), audit_store.clone()),
            tenant(),
            server.logical.clone(),
            same,
            actors(),
            cutoff()
        )
        .await
        .is_err()
    );
    let connect = || {
        PublicationService::connect(
            host(runtime.clone(), audit_store.clone()),
            tenant(),
            server.logical.clone(),
            server.winget(),
            actors(),
            cutoff(),
        )
    };
    sql("GRANT SELECT ON mdm_access.credentials TO mdm_software_driver");
    let extra = connect().await;
    sql("REVOKE SELECT ON mdm_access.credentials FROM mdm_software_driver");
    assert!(extra.is_err());
    sql("GRANT INSERT ON mdm_audit.receipts TO mdm_software_driver WITH GRANT OPTION");
    let delegation = connect().await;
    sql("REVOKE GRANT OPTION FOR INSERT ON mdm_audit.receipts FROM mdm_software_driver");
    assert!(delegation.is_err());
    sql("ALTER POLICY tenant ON mdm_audit.receipts USING(true) WITH CHECK(true)");
    let broad = connect().await;
    sql(
        "ALTER POLICY tenant ON mdm_audit.receipts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
    );
    assert!(broad.is_err());
    assert!(connect().await.is_ok());
    assert!(
        PublicationService::connect(
            host(runtime.clone(), audit_store.clone()),
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
    std::mem::swap(&mut swapped.test, &mut swapped.pilot);
    assert!(
        PublicationService::connect(
            host(runtime.clone(), audit_store.clone()),
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
}
