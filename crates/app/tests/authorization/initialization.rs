use super::*;
use crate::audit_test_support::audit_count;

#[tokio::test]
#[ignore = "MODULE=authorization.initialization: real authorization contract"]
async fn initialization_receipt_atomicity_and_recovery() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let subject = prepared_subject(&authority::Authority::prepared_browser("other")?)?;
    let (pool, source, audit_store) = crate::audit_test_support::request_store().await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool));
    resources.resource(SourceResource(source));
    resources.finish(async {
    crate::authorization::store::initialize_authorization(
        &audit_store,
        crate::test_support::identity::user(case_tenant(), case_admin()),
        Uuid::new_v4(),
    )
    .await?;
    ensure!(matches!(
        crate::authorization::store::initialize_authorization(
            &audit_store,
            crate::test_support::identity::user(case_tenant(), case_admin()),
            Uuid::new_v4()
        )
        .await,
        Err(rss_mdm_authorization_service::Error::Conflict)
    ));
    // The initializer marker, grant, receipt and audit must all roll back together.
    let mut isolated = crate::test_support::identity::user(case_tenant(), case_admin());
    isolated.instance_id = Uuid::new_v4().to_string();
    let init_key = Uuid::new_v4();
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")?;
    let failed = crate::authorization::store::initialize_authorization(
        &audit_store,
        isolated.clone(),
        init_key,
    )
    .await;
    pg("GRANT INSERT(tenant_id,source_id,event_id,fingerprint,source_bytes,message_id,reserved,enqueued_at) ON mdm_audit.receipts TO mdm_access")?;
    ensure!(matches!(failed, Err(rss_mdm_authorization_service::Error::Audit(_))));
    ensure!(audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(init_key.to_string().as_str()) && r.result() == "success").await? == 0);
    for table in [
        "authorization_initializations",
        "authorization_rules",
        "authorization_operations",
    ] {
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{}'", isolated.instance_id, TENANT = case_tenant()))?.trim() == "0");
    }
    audit_store.inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck);
    ensure!(matches!(
        crate::authorization::store::initialize_authorization(
            &audit_store,
            isolated.clone(),
            init_key
        )
        .await,
        Err(rss_mdm_authorization_service::Error::CommitUnknown)
    ));
    let initial = crate::authorization::store::initialize_authorization(
        &audit_store,
        isolated.clone(),
        init_key,
    )
    .await?;
    ensure!(audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(init_key.to_string().as_str()) && r.result() == "success").await? == 1);
    // Simulate the persisted result of deleting the seed, without changing its marker/receipt.
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET revision=2,document=NULL WHERE tenant_id='{TENANT}' AND instance='{}' AND id='{}'",
        isolated.instance_id,
        initial.id,
        TENANT = case_tenant()
    ))?;
    let (reopened_pool, reopened_source, reopened) = crate::audit_test_support::request_store().await?;
    let replayed = crate::authorization::store::initialize_authorization(
        reopened.as_ref(),
        isolated.clone(),
        init_key,
    )
    .await?;
    ensure!(replayed.id == initial.id && replayed.revision == initial.revision);
    ensure!(matches!(
        crate::authorization::store::initialize_authorization(
            reopened.as_ref(),
            isolated.clone(),
            Uuid::new_v4()
        )
        .await,
        Err(rss_mdm_authorization_service::Error::Conflict)
    ));
    ensure!(pg(&format!("SELECT document IS NULL FROM mdm_access.authorization_rules WHERE tenant_id='{TENANT}' AND instance='{}' AND id='{}'", isolated.instance_id, initial.id, TENANT = case_tenant()))?.trim() == "t");
    reopened_source.close().await;
    reopened_pool.close().await;
    // A valid-looking but absent target never acquires the irreversible bootstrap marker.
    let wrong_key = Uuid::new_v4();
    let mut init = json!({"database":base["access_database"],"identityDatabase":base["identity"]["database"],
        "expectedEpoch":base["flow"]["storage"]["epoch"],
        "installation":{"audit_mode":"plain","instance_id":INSTANCE,"target":base["flow"]["storage"]["target"],"lineage":base["flow"]["storage"]["lineage"]},
        "audit":{"mode":"plain"},"login":crate::test_support::case::login("other"),"passwordFile":std::path::Path::new(&std::env::var("MDM_TEST_CONFIG")?).parent().unwrap().join("account-password"),
        "operationId":wrong_key,"user":{"instanceId":INSTANCE,"tenantId":case_tenant(),"principalId":Uuid::new_v4()}});
    // This case owns its tenant. Start the public command from an uninitialized
    // authorization store while retaining the real, authenticated Identity account.
    let mut valid = init.clone();
    valid["operationId"] = json!(Uuid::new_v4());
    valid["user"]["principalId"] = subject.clone().into();
    pg(&format!("DELETE FROM mdm_access.authorization_initializations WHERE tenant_id='{tenant}' AND instance='{INSTANCE}'; DELETE FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND instance='{INSTANCE}'",tenant=case_tenant()))?;
    let public = crate::authorization::initialize(serde_json::from_value(valid.clone())?).await?;
    let replay = crate::authorization::initialize(serde_json::from_value(valid)?).await?;
    ensure!(public.id == replay.id && public.revision == replay.revision);
    ensure!(matches!(
        crate::authorization::initialize(serde_json::from_value(init.clone())?).await,
        Err(crate::Error::Authorization(
            rss_mdm_authorization_service::Error::Forbidden
        ))
    ));
    init["user"]["principalId"] = subject.clone().into();
    init["user"]["instanceId"] = Uuid::new_v4().to_string().into();
    ensure!(matches!(
        crate::authorization::initialize(serde_json::from_value(init)?).await,
        Err(crate::Error::Configuration(_))
    ));
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.authorization_operations WHERE operation_id='{wrong_key}'"
        ))?
        .trim()
            == "0"
    );

    Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.initialization: bounded transaction and ACK recovery"]
async fn bounded_initialization_recovery() -> Result<()> {
    let (pool, source, audit_store) = crate::audit_test_support::request_store().await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool));
    resources.resource(SourceResource(source));
    resources.finish(async {
    let store = audit_store.as_ref();
    // The same command deadline projection is used before COMMIT and after a durable but unacknowledged COMMIT.
    for (fault, committed) in [
        (rss_transactional_messaging_postgres::PgTransactionFault::CommitPending, false),
        (rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck, true),
    ] {
        let mut user = crate::test_support::identity::user(case_tenant(), case_admin());
        user.instance_id = Uuid::new_v4().to_string();
        let key = Uuid::new_v4();
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            case_tenant().into(),
            "authorization_initialize",
        );
        store.inject_next_fault(fault);
        let deadline = rss_request_context::Deadline::from_timeout(
            &crate::lifecycle::RuntimeTimer,
            std::time::Duration::from_secs(1),
        )?;
        let outcome = crate::authorization::bounded_initialization(
            &audit,
            deadline,
            crate::authorization::store::initialize_fixture_audited(
                store,
                user.clone(),
                key,
                &audit,
            ),
        )
        .await;
        audit.finalize(Some(rss_mdm_audit_integration::FailureReason::Transaction));
        ensure!(matches!(
            outcome,
            Err(crate::Error::CommitUnknown
                | crate::Error::Authorization(rss_mdm_authorization_service::Error::CommitUnknown))
        ));
        let durable = pg(&format!(
            "SELECT count(*) FROM mdm_access.authorization_initializations WHERE tenant_id='{TENANT}' AND instance='{}'",
            user.instance_id,
            TENANT = case_tenant()
        ))?;
        ensure!(durable.trim() == if committed { "1" } else { "0" });
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id='{}' AND operation_id='{key}'", case_tenant()))?.trim() == if committed { "1" } else { "0" });
        ensure!(audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(key.to_string().as_str()) && r.result() == "success").await? == usize::from(committed));

        let receipt =
            crate::authorization::store::initialize_authorization(store, user.clone(), key).await?;
        ensure!(
            crate::authorization::store::initialize_authorization(store, user, key)
                .await?
                .id
                == receipt.id
        );
    }
    Ok(())

    }).await
}
