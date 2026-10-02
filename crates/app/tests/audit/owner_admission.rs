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
        let original = sql(&format!(
            "SELECT coalesce((SELECT split_part(setting,'=',2) FROM pg_roles r CROSS JOIN LATERAL unnest(r.rolconfig) setting WHERE r.rolname='{role}' AND setting LIKE 'default_transaction_isolation=%'),'')"
        ));
        sql(&format!(
            "ALTER ROLE {role} SET default_transaction_isolation='repeatable read'"
        ));
        let runtime = runtime_role(tenant(), role).await;
        let result = crate::database::admit_audit_runtime(&runtime, &store, tenant()).await;
        runtime.close().await;
        sql(&if original.is_empty() {
            format!("ALTER ROLE {role} RESET default_transaction_isolation")
        } else {
            format!(
                "ALTER ROLE {role} SET default_transaction_isolation='{}'",
                original.replace('\'', "''")
            )
        });
        assert!(
            matches!(
                result,
                Err(Error::Unavailable(crate::Failure::AuditIsolation))
            ),
            "{role}: {result:?}"
        );
        let runtime = runtime_role(tenant(), role).await;
        crate::database::admit_audit_runtime(&runtime, &store, tenant())
            .await
            .unwrap();
        runtime.close().await;
    }
}
