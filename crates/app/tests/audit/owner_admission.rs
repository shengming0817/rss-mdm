use crate::planning::test_support::*;

#[tokio::test]
#[ignore = "MODULE=audit.integrity: real capability storage and transactions"]
async fn audit_startup_rejects_each_borrowed_owner_snapshot_isolation() {
    let store = audit_store().await;
    for role in [
        "mdm_flow_runtime",
        "mdm_command_runtime",
        "mdm_software_driver",
    ] {
        sql(&format!(
            "ALTER ROLE {role} SET default_transaction_isolation='repeatable read'"
        ));
        let runtime = runtime_role(tenant(), role).await;
        let result = crate::database::admit_audit_runtime(&runtime, &store, tenant()).await;
        runtime.close().await;
        sql(&format!(
            "ALTER ROLE {role} RESET default_transaction_isolation"
        ));
        assert!(
            matches!(result, Err(Error::Unavailable(Failure::AuditIsolation))),
            "{role}: {result:?}"
        );
        let runtime = runtime_role(tenant(), role).await;
        crate::database::admit_audit_runtime(&runtime, &store, tenant())
            .await
            .unwrap();
        runtime.close().await;
    }
}
