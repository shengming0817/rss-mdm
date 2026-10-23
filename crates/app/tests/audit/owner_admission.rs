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
        let result = store
            .on_runtime(
                runtime.clone(),
                tenant(),
                &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                    .control(),
            )
            .await;
        runtime.close().await;
        sql(&if original.is_empty() {
            format!("ALTER ROLE {role} RESET default_transaction_isolation")
        } else {
            format!(
                "ALTER ROLE {role} SET default_transaction_isolation='{}'",
                original.replace('\'', "''")
            )
        });
        assert!(result.is_err(), "{role}: owner isolation admission");
        let runtime = runtime_role(tenant(), role).await;
        store
            .on_runtime(
                runtime.clone(),
                tenant(),
                &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                    .control(),
            )
            .await
            .unwrap();
        runtime.close().await;
    }
}

#[tokio::test]
#[ignore = "MODULE=audit.integrity: actual borrowed worker startup permissions"]
async fn audit_startup_validates_each_borrowed_owner_permissions() {
    let mode = super::super::integrity(true).unwrap();
    let store = audit_store_with_integrity(mode).await;
    for role in [
        "mdm_flow_runtime",
        "mdm_command_runtime",
        "mdm_software_driver",
    ] {
        let runtime = runtime_role(tenant(), role).await;
        for table in [
            "mdm_audit.receipts",
            "rss_audit.records",
            "rss_ledger.entries",
        ] {
            sql(&format!("GRANT UPDATE ON {table} TO {role}"));
            let result = store
                .on_runtime(
                    runtime.clone(),
                    tenant(),
                    &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                        .control(),
                )
                .await;
            sql(&format!("REVOKE UPDATE ON {table} FROM {role}"));
            assert!(result.is_err(), "{role} {table}: owner privilege admission");
            store
                .on_runtime(
                    runtime.clone(),
                    tenant(),
                    &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                        .control(),
                )
                .await
                .unwrap();
        }
        runtime.close().await;
    }
}
