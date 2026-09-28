use super::*;
use uuid::Uuid;
pub(crate) fn seed_source(
    device: &str,
    channel: &str,
    source: &str,
    value: &str,
) -> Result<(Uuid, Uuid)> {
    let registration = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let credential = Uuid::new_v4();
    let scope = crate::device::scope(
        rss_request_context::TenantId::parse(TENANT)?,
        registration,
        source,
        epoch,
    )?;
    let encoded = scope.encode()?.replace('\'', "''");
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage())?;
    pg(&format!(
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds'); INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','{request}','{grant}','{source}'); INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','{channel}',1,'{request}','active'); INSERT INTO mdm_access.credentials VALUES('{TENANT}','{credential}','{registration}','{channel}',md5('{credential}')||md5('{registration}'),'active'); INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','{source}','{epoch}','{coverage}',true); INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch) VALUES('{TENANT}','mdm.observation.v1','inventory-v3','{encoded}','{coverage}','device.model','{value}','fixture',1,2,'known','{value}','fixture',1,2,'{registration}','{source}','{epoch}');"
    ))?;
    Ok((registration, epoch))
}

/// One completed run for retained-quality fixtures; no projection or behavior matrix runs here.
pub(crate) async fn completed_windows_run(base: &Value, device: &str) -> Result<()> {
    let (registration, _) = seed_source(device, "mdm", "mdm.windows", "fixture")?;
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator=repeat('7c',32) WHERE registration='{registration}'"
    ))?;
    let access = database(base).await?;
    let service = crate::device::DeviceService::new(
        access.clone(),
        TENANT.into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let proof = crate::device::test_support::proof(TENANT, rss_mdm_inventory::Channel::Mdm, 124);
    crate::inventory_runtime::test_support::report(
        &service,
        &access,
        &proof,
        [Some("fixture"), Some("1")],
    )
    .await?;
    access.close().await;
    Ok(())
}
