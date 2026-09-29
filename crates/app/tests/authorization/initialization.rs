use super::*;

#[tokio::test]
#[ignore = "MODULE=authorization.initialization: real authorization contract"]
async fn initialization_receipt_atomicity_and_recovery() -> Result<()> {
    let Fixture {
        base,
        subject,
        audit_store,
        ..
    } = fixture().await?;
    ensure!(matches!(
        crate::authorization::store::initialize_authorization(
            &audit_store,
            crate::test_support::identity::user(TENANT, ADMIN),
            Uuid::new_v4()
        )
        .await,
        Err(crate::Error::Conflict)
    ));
    // The initializer marker, grant, receipt and audit must all roll back together.
    let mut isolated = crate::test_support::identity::user(TENANT, ADMIN);
    isolated.instance_id = Uuid::new_v4().to_string();
    let init_key = Uuid::new_v4();
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")?;
    let failed = crate::authorization::store::initialize_authorization(
        &audit_store,
        isolated.clone(),
        init_key,
    )
    .await;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_access")?;
    ensure!(failed.is_err());
    for table in [
        "authorization_initializations",
        "authorization_rules",
        "operations",
    ] {
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{}'", isolated.instance_id))?.trim() == "0");
    }
    audit_store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    ensure!(matches!(
        crate::authorization::store::initialize_authorization(
            &audit_store,
            isolated.clone(),
            init_key
        )
        .await,
        Err(crate::Error::CommitUnknown)
    ));
    let initial = crate::authorization::store::initialize_authorization(
        &audit_store,
        isolated.clone(),
        init_key,
    )
    .await?;
    // Simulate the persisted result of deleting the seed, without changing its marker/receipt.
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET revision=2,document=NULL WHERE tenant_id='{TENANT}' AND instance='{}' AND id='{}'",
        isolated.instance_id, initial.id
    ))?;
    let reopened = database(&base).await?;
    let replayed = crate::authorization::store::initialize_authorization(
        reopened
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?
            .as_ref(),
        isolated.clone(),
        init_key,
    )
    .await?;
    ensure!(replayed.id == initial.id && replayed.revision == initial.revision);
    ensure!(matches!(
        crate::authorization::store::initialize_authorization(
            reopened
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?
                .as_ref(),
            isolated.clone(),
            Uuid::new_v4()
        )
        .await,
        Err(crate::Error::Conflict)
    ));
    ensure!(pg(&format!("SELECT document IS NULL FROM mdm_access.authorization_rules WHERE tenant_id='{TENANT}' AND instance='{}' AND id='{}'", isolated.instance_id, initial.id))?.trim() == "t");
    reopened.close().await;
    // A valid-looking but absent target never acquires the irreversible bootstrap marker.
    let wrong_key = Uuid::new_v4();
    let mut init = json!({"database":base["access_database"],"identityDatabase":base["identity"]["database"],
        "installation":{"audit_mode":"plain","instance_id":INSTANCE,"target":base["flow"]["storage"]["target"],"lineage":base["flow"]["storage"]["lineage"],"epoch":base["flow"]["storage"]["epoch"],"tenants":[TENANT]},
        "audit":{"mode":"plain"},"login":"authorization-member","passwordFile":std::path::Path::new(&std::env::var("MDM_TEST_CONFIG")?).parent().unwrap().join("account-password"),
        "operationId":wrong_key,"user":{"instanceId":INSTANCE,"tenantId":TENANT,"principalId":Uuid::new_v4()}});
    ensure!(matches!(
        crate::authorization::initialize(serde_json::from_value(init.clone())?).await,
        Err(crate::Error::Forbidden)
    ));
    init["user"]["principalId"] = subject.clone().into();
    init["user"]["instanceId"] = Uuid::new_v4().to_string().into();
    ensure!(matches!(
        crate::authorization::initialize(serde_json::from_value(init)?).await,
        Err(crate::Error::Configuration(_))
    ));
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.operations WHERE operation_id='{wrong_key}'"
        ))?
        .trim()
            == "0"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=authorization.initialization: bounded transaction and ACK recovery"]
async fn bounded_initialization_recovery() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let store = fixture.audit.as_ref();
    // The same command deadline projection is used before COMMIT and after a durable but unacknowledged COMMIT.
    for (fault, committed) in [
        (rss_audit_postgres::PgFault::BeforeCommitPending, false),
        (rss_audit_postgres::PgFault::CommitUnknownAfterAck, true),
    ] {
        let mut user = crate::test_support::identity::user(TENANT, ADMIN);
        user.instance_id = Uuid::new_v4().to_string();
        let key = Uuid::new_v4();
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(TENANT.into(), "authorization_initialize");
        store.inject_next_fault(fault);
        let deadline = rss_request_context::Deadline::from_timeout(
            &crate::lifecycle::RuntimeTimer,
            std::time::Duration::from_secs(1),
        )?;
        let outcome = crate::authorization::bounded_initialization(
            &audit,
            deadline,
            crate::authorization::store::initialize_authorization_audited(
                store,
                user.clone(),
                key,
                &audit,
            ),
        )
        .await;
        audit.finalize(Some(rss_mdm_audit_integration::FailureReason::Transaction));
        ensure!(matches!(outcome, Err(crate::Error::CommitUnknown)));
        let durable = pg(&format!(
            "SELECT count(*) FROM mdm_access.authorization_initializations WHERE tenant_id='{TENANT}' AND instance='{}'",
            user.instance_id
        ))?;
        ensure!(durable.trim() == if committed { "1" } else { "0" });
        let receipt =
            crate::authorization::store::initialize_authorization(store, user.clone(), key).await?;
        ensure!(
            crate::authorization::store::initialize_authorization(store, user, key)
                .await?
                .id
                == receipt.id
        );
    }
    let audit =
        rss_mdm_audit_integration::RequestAudit::new(TENANT.into(), "authorization_initialize");
    let deadline = rss_request_context::Deadline::from_timeout(
        &crate::lifecycle::RuntimeTimer,
        std::time::Duration::from_millis(10),
    )?;
    let before: Result<(), crate::Error> =
        crate::authorization::bounded_initialization(&audit, deadline, std::future::pending())
            .await;
    audit.finalize(Some(rss_mdm_audit_integration::FailureReason::Transaction));
    ensure!(matches!(
        before,
        Err(crate::Error::Unavailable(crate::Failure::RequestDeadline))
    ));
    Ok(())
}
