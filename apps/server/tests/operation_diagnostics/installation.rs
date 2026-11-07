use super::*;
use rss_mdm_management_http::operation_diagnostics::{LocatorQuery, Lookup, Reads};
use serde_json::json;

#[tokio::test]
#[ignore = "T2: installation authority reads tenant receipts and preserves audit evidence after NotFound"]
async fn original_tenant_result_and_missing_result_have_independent_evidence() -> Result<()> {
    let business = Context::open("shared", &[]).await?;
    let c = Context::management("shared").await?;
    let account = c
        .account(&[Permission::TenantRead, Permission::AuditRead])
        .await?;
    let proof = Arc::new(c.authenticate(&account).await?);
    let mut config = crate::host_t2_support::configuration(
        &business.inputs,
        "shared",
        business.tenant,
        "127.0.0.1:1".parse()?,
        Uuid::new_v4(),
    )?;
    config["tenant_administration"] = json!({
        "registry_database":c.inputs.database("shared","mdm_tenant_registry"),
        "provisioning_database":c.inputs.database("shared","mdm_identity_provisioning"),
        "fingerprint_key_file":c.inputs.directory.join("fingerprint.key"),
    });
    let config: crate::config::Config = serde_json::from_value(config)?;
    let compiled = config.compile()?;
    let kdf = Arc::new(rss_identity_core::account::PasswordKdf::new());
    let service = crate::administration::tenants::service::Service::connect(
        &compiled.config,
        c.tenant,
        kdf.clone(),
        compiled.identity_management,
    )
    .await?
    .expect("configured registry owner");
    let operation = Uuid::new_v4();
    crate::administration::tenants::update(crate::administration::tenants::Update {
        database: c.inputs.database("shared", "mdm_owner"),
        installation: c.inputs.installation(),
        tenant_id: business.tenant.to_string(),
        expected_revision: 1,
        operation_id: operation,
        name: Some("original tenant result".into()),
        notes: None,
    })
    .await?;
    let adapter = super::super::operation_diagnostics::Installation {
        tenants: Some(service.clone()),
        audit: c.audit.clone(),
        timeline: c.database.timeline(c.audit.clone(), c.tenant, &[41; 32])?,
        tenant: c.tenant,
    };
    let auth = c.read_auth(proof);
    let query = LocatorQuery {
        include_audit: true,
        ..Default::default()
    };
    let headers = axum::http::HeaderMap::new();
    for (id, expected) in [(operation, "available"), (Uuid::new_v4(), "not_found")] {
        let audit = c.request(&auth.proof)?;
        let detail = adapter
            .operation(Lookup {
                auth: &auth,
                audit: &audit,
                owner: rss_mdm_audit_integration::operation::OperationOwner::TenantAdministration,
                operation: id,
                query: &query,
                headers: &headers,
                address: None,
            })
            .await?;
        let value = serde_json::to_value(detail)?;
        assert_eq!(value["originalResult"]["availability"], expected);
        assert_eq!(value["auditEvidence"]["availability"], "available");
        assert_eq!(value["requestEvidence"]["availability"], "available");
        if id == operation {
            assert_eq!(value["originalResult"]["value"]["revision"], 2);
        }
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        c.audit
            .settle_request(&audit, 200, "success", &budget.source_control())
            .await?;
        audit.finalize(None);
    }
    service.close().await;
    kdf.close();
    kdf.wait_closed().await;
    c.close().await;
    business.close().await;
    Ok(())
}
