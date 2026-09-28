use crate::test_support::*;
#[tokio::test]
#[ignore = "MODULE=assets.http: real read authorization and PostgreSQL projection"]
async fn persisted_inventory_read_respects_device_scope() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let (authorized, _) = app_with_access(&fixture.base, fixture.access.clone()).await?;
    let mut browser = fixture.browser("other")?;
    let query = "/api/v2/devices/device-1/inventory";
    ensure!(browser.call(&authorized, Method::GET, query, None).await?.0 == StatusCode::FORBIDDEN);
    set_device_grants(&mut browser, &authorized, "device-1", &["inventory_read"]).await?;
    let scope = serde_json::to_string(
        &json!({"tenant":TENANT,"object":"99999999-9999-4999-8999-999999999991","registration":"99999999-9999-4999-8999-999999999991","source":"mdm.windows","dataset":"inventory","epoch":"99999999-9999-4999-8999-999999999992"}),
    )?;
    // Use the public Scope encoder, not JSON map key order, for the persisted identity.
    let scope: rss_observation::Scope = serde_json::from_str(&scope)?;
    let encoded = scope.encode()?.replace('\'', "''");
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage())?;
    let projection = rss_mdm_inventory_postgres::projection_scope(scope.tenant());
    let journal = projection.source().source();
    let generation = projection.generation();
    // Read-path fixture only. Device registration/credential proof is exercised by device PG T2.
    pg(&format!(
        r#"
        INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','99999999-9999-4999-8999-999999999993','read-fixture','{INSTANCE}','device-1','enrollment','consumed',clock_timestamp()+interval '200 seconds');
        INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','99999999-9999-4999-8999-999999999994','99999999-9999-4999-8999-999999999993','mdm.windows');
        INSERT INTO mdm_access.devices VALUES('{TENANT}','device-1') ON CONFLICT DO NOTHING;
        INSERT INTO mdm_access.registrations VALUES('{TENANT}','99999999-9999-4999-8999-999999999991','device-1','mdm',1,'99999999-9999-4999-8999-999999999994','active');
        INSERT INTO mdm_access.credentials VALUES('{TENANT}','99999999-9999-4999-8999-999999999995','99999999-9999-4999-8999-999999999991','mdm',repeat('a',64),'active');
        INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','99999999-9999-4999-8999-999999999991','mdm.windows','99999999-9999-4999-8999-999999999992','{coverage}',true);
        INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch) VALUES('{TENANT}','{journal}','{generation}','{encoded}','{coverage}','device.model','Model-A','fixture',1,2,'known','99999999-9999-4999-8999-999999999991','mdm.windows','99999999-9999-4999-8999-999999999992');
    "#
    ))?;

    let (status, assets) = browser.call(&authorized, Method::GET, query, None).await?;
    ensure!(
        status == StatusCode::OK
            && assets["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
                == "Model-A"
    );
    ensure!(assets["tenantId"] == TENANT && assets["asset"]["device"]["device"] == "device-1");
    let outside = "/api/v2/devices/outside/inventory";
    ensure!(
        browser
            .call(&authorized, Method::GET, outside, None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    // RequestAudit is mandatory for both reads and denied requests; never disclose assets on failure.
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access,mdm_flow_runtime")?;
    let read = browser.call(&authorized, Method::GET, query, None).await?;
    let mut anonymous = Browser::default();
    let denied = anonymous
        .call(&authorized, Method::GET, query, None)
        .await?;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_access,mdm_flow_runtime")?;
    ensure!(
        read.0 == StatusCode::INTERNAL_SERVER_ERROR
            && read.1["code"] == "audit_contract_error"
            && read.1.get("asset").is_none()
    );
    ensure!(
        denied.0 == StatusCode::INTERNAL_SERVER_ERROR && denied.1["code"] == "audit_contract_error"
    );
    browser.operation = None;
    ensure!(browser.call(&authorized, Method::GET, query, None).await?.0 == StatusCode::OK);
    Ok(())
}
