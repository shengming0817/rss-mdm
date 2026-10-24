use super::super::{integrity, pool};
use crate::audit_test_support::source_runtime;
use crate::test_support::{case, process::pg};
use rss_mdm_audit_integration::{AuditStore, budget::AuditBudget};
use rss_request_context::TenantId;
use std::time::Duration;

#[tokio::test]
#[ignore = "MODULE=audit.integrity: real capability storage and transactions"]
async fn audit_startup_rejects_each_borrowed_owner_snapshot_isolation() {
    let tenant = TenantId::parse(case::tenant()).unwrap();
    let access = pool("mdm_access").await.unwrap();
    let source = source_runtime(&access, tenant).await.unwrap();
    let budget = AuditBudget::new(Duration::from_secs(5));
    let store = AuditStore::new(
        access.clone(),
        integrity(false).unwrap(),
        source.clone(),
        tenant,
        Default::default(),
        &budget.control(),
    )
    .await
    .unwrap();
    for role in [
        "mdm_flow_runtime",
        "mdm_command_runtime",
        "mdm_software_driver",
    ] {
        let original = pg(&format!(
            "SELECT coalesce((SELECT split_part(setting,'=',2) FROM pg_roles r CROSS JOIN LATERAL unnest(r.rolconfig) setting WHERE r.rolname='{role}' AND setting LIKE 'default_transaction_isolation=%'),'')"
        )).unwrap();
        pg(&format!(
            "ALTER ROLE {role} SET default_transaction_isolation='repeatable read'"
        ))
        .unwrap();
        let owner = pool(role).await.unwrap();
        let runtime = source_runtime(&owner, tenant).await.unwrap();
        let result = store
            .on_runtime(
                runtime.clone(),
                tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                    .control(),
            )
            .await;
        runtime.close().await;
        owner.close().await;
        pg(&if original.is_empty() {
            format!("ALTER ROLE {role} RESET default_transaction_isolation")
        } else {
            format!(
                "ALTER ROLE {role} SET default_transaction_isolation='{}'",
                original.replace('\'', "''")
            )
        })
        .unwrap();
        assert!(result.is_err(), "{role}: owner isolation admission");
        let owner = pool(role).await.unwrap();
        let runtime = source_runtime(&owner, tenant).await.unwrap();
        store
            .on_runtime(
                runtime.clone(),
                tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                    .control(),
            )
            .await
            .unwrap();
        runtime.close().await;
        owner.close().await;
    }
    source.close().await;
    access.close().await;
}

#[tokio::test]
#[ignore = "MODULE=audit.integrity: actual borrowed worker startup permissions"]
async fn audit_startup_validates_each_borrowed_owner_permissions() {
    let tenant = TenantId::parse(case::tenant()).unwrap();
    let access = pool("mdm_access").await.unwrap();
    let source = source_runtime(&access, tenant).await.unwrap();
    let budget = AuditBudget::new(Duration::from_secs(5));
    let store = AuditStore::new(
        access.clone(),
        integrity(true).unwrap(),
        source.clone(),
        tenant,
        Default::default(),
        &budget.control(),
    )
    .await
    .unwrap();
    for role in [
        "mdm_flow_runtime",
        "mdm_command_runtime",
        "mdm_software_driver",
    ] {
        let owner = pool(role).await.unwrap();
        let runtime = source_runtime(&owner, tenant).await.unwrap();
        for table in [
            "mdm_audit.receipts",
            "rss_audit.records",
            "rss_ledger.entries",
        ] {
            pg(&format!("GRANT UPDATE ON {table} TO {role}")).unwrap();
            let result = store
                .on_runtime(
                    runtime.clone(),
                    tenant,
                    &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                        .control(),
                )
                .await;
            pg(&format!("REVOKE UPDATE ON {table} FROM {role}")).unwrap();
            assert!(result.is_err(), "{role} {table}: owner privilege admission");
            store
                .on_runtime(
                    runtime.clone(),
                    tenant,
                    &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                        .control(),
                )
                .await
                .unwrap();
        }
        runtime.close().await;
        owner.close().await;
    }
    source.close().await;
    access.close().await;
}
