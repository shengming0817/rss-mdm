use super::{process::*, runtime::*, *};
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
        rss_request_context::TenantId::parse(case_tenant())?,
        registration,
        source,
        epoch,
    )?;
    let encoded = scope.encode()?.replace('\'', "''");
    let definition = definition(
        "inventory",
        source,
        &[
            rss_mdm_inventory::builtin::MODEL,
            rss_mdm_inventory::builtin::OS_VERSION,
        ],
    );
    let coverage = serde_json::to_string(&definition.coverage()?)?;
    let document = serde_json::to_string(&definition)?.replace('\'', "''");
    let fingerprint = definition.fingerprint()?;
    let value = serde_json::to_string(&rss_mdm_inventory::Scalar::String(value.into()))?
        .replace('\'', "''");
    let origin = if channel == "agent" {
        format!(
            "INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES('{tenant}','{grant}','{request}','download','fixture','{instance}','{device}','macos',repeat('0',64),repeat('0',64),'consumed',clock_timestamp()+interval '24 hours');",
            tenant = case_tenant(),
            instance = INSTANCE
        )
    } else {
        format!(
            "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{tenant}','{grant}','fixture','{instance}','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds'); INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) VALUES('{tenant}','{request}','{grant}','{source}',CASE WHEN '{source}'='mdm.windows' THEN 'Device' END);",
            tenant = case_tenant(),
            instance = INSTANCE
        )
    };
    let origin_column = if channel == "agent" {
        "agent_grant_id"
    } else {
        "request_id"
    };
    let origin_id = if channel == "agent" { grant } else { request };
    pg(&format!(
        "SELECT mdm.lock_asset_watermark('{TENANT}'); INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{TENANT}','{device}') ON CONFLICT DO NOTHING; {origin}; INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,{origin_column},state,purpose,epoch) VALUES('{TENANT}','{registration}','{device}','{channel}',1,'{origin_id}','active','primary',gen_random_uuid()); INSERT INTO mdm_access.credentials VALUES('{TENANT}','{credential}','{registration}','{channel}',md5('{credential}')||md5('{registration}'),'active'); INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{TENANT}','{registration}','{source}','{epoch}',true); INSERT INTO mdm.collection_definitions(tenant_id,dataset,version,source,fingerprint,coverage,definition) VALUES('{TENANT}','inventory','fixture','{source}','{fingerprint}','{coverage}','{document}') ON CONFLICT DO NOTHING; INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{TENANT}','mdm.observation.v1','inventory-projection-v1','{encoded}','{coverage}','device.model','{value}','fixture',1,2,'known','{value}','fixture',1,2,'{registration}','{source}','{epoch}',0);",
        TENANT = case_tenant()
    ))?;
    Ok((registration, epoch))
}

/// One completed run for retained-quality fixtures; no projection or behavior matrix runs here.
pub(crate) async fn completed_windows_run(base: &Value, device: &str) -> Result<()> {
    let (registration, _) = seed_source(device, "mdm", "mdm.windows", "fixture")?;
    let proof =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 124);
    let locator = crate::test_support::runtime::secret("channel-proof-124")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator='{locator}' WHERE registration='{registration}'"
    ))?;
    let access = database(base).await?;
    let service = crate::device::DeviceService::new(
        access.registration(),
        case_tenant().into(),
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
    );
    crate::inventory_runtime::test_support::report(
        &service,
        &access.inventory(),
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?
            .as_ref(),
        &proof,
        [Some("fixture"), Some("1")],
    )
    .await?;
    access.close().await;
    Ok(())
}

/// Explicit contract for a fixture collector; production never has a default field roster.
pub(crate) fn definition(
    dataset: &str,
    source: &str,
    keys: &[rss_mdm_inventory::FieldKey],
) -> rss_mdm_inventory::CollectionDefinition {
    let catalog = rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    rss_mdm_inventory::CollectionDefinition::new(
        dataset,
        "fixture",
        rss_mdm_inventory::Source::parse(source).unwrap(),
        {
            let scope = rss_mdm_inventory::CollectionScope::Device;
            let fields: Vec<rss_mdm_inventory::FieldDefinition> = keys
                .iter()
                .map(|key| catalog.definition(*key).unwrap().clone())
                .collect();
            fields
                .into_iter()
                .map(|definition| rss_mdm_inventory::CollectionField {
                    definition,
                    scope: scope.clone(),
                })
                .collect()
        },
    )
    .unwrap()
}

/// Register a frozen definition for read-path fixtures using the current product schema.
pub(crate) fn register_definition(
    definition: &rss_mdm_inventory::CollectionDefinition,
) -> Result<()> {
    pg(&definition_sql(case_tenant(), definition)?)?;
    Ok(())
}
pub(crate) fn definition_sql(
    tenant: &str,
    definition: &rss_mdm_inventory::CollectionDefinition,
) -> Result<String> {
    let dataset = definition.dataset();
    let version = definition.version();
    let source = definition.source().as_str();
    let fingerprint = definition.fingerprint()?;
    let coverage = serde_json::to_string(&definition.coverage()?)?.replace('\'', "''");
    let document = serde_json::to_string(definition)?.replace('\'', "''");
    Ok(format!(
        "INSERT INTO mdm.collection_definitions(tenant_id,dataset,version,source,fingerprint,coverage,definition) VALUES('{tenant}','{dataset}','{version}','{source}','{fingerprint}','{coverage}','{document}') ON CONFLICT DO NOTHING"
    ))
}

/// A projected Agent fact before an enrollment-policy action; report intake has its own owner.
pub(crate) fn seed_unenrolled(device: &str) -> Result<()> {
    let device = device.replace('\'', "''");
    let coordinates: Value = serde_json::from_str(&pg(&format!(
        "SELECT jsonb_build_array(r.id,s.epoch) FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id='{}' AND r.device='{device}' AND r.channel='agent' AND r.state='active' AND s.source='agent.builtin' AND s.enabled",
        case_tenant()
    ))?)?;
    let registration: Uuid = serde_json::from_value(coordinates[0].clone())?;
    let epoch: Uuid = serde_json::from_value(coordinates[1].clone())?;
    let field = rss_mdm_inventory::FieldKey::parse("channel.mdm.enrollment")?;
    let definition = definition("mdm-enrollment-fixture", "agent.builtin", &[field]);
    register_definition(&definition)?;
    let scope = crate::device::scope_dataset(rss_request_context::TenantId::parse(case_tenant())?, registration, "agent.builtin", epoch, definition.dataset())?.encode()?.replace('\'', "''");
    let coverage = serde_json::to_string(&definition.coverage()?)?.replace('\'', "''");
    let value = serde_json::to_string(&rss_mdm_inventory::Scalar::String("unenrolled".into()))?;
    pg(&format!("SELECT mdm.lock_asset_watermark('{tenant}'); INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES('{{\"kind\":\"device\"}}','{tenant}','mdm.observation.v1','inventory-projection-v1','{scope}','{coverage}','channel.mdm.enrollment','{value}','fixture',1,2,'known','{value}','fixture',1,2,'{registration}','agent.builtin','{epoch}',0)", tenant=case_tenant()))?;
    Ok(())
}
