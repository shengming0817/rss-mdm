//! The scope directory reads real frozen attempts and retained facts under current authority.
use super::*;
use rss_mdm_inventory::{
    ApplicationRoot, CollectedValue, CollectionDefinition, CollectionField, CollectionProgress,
    CollectionScope, NativeValue, Scalar,
};

fn seed(
    registration: Uuid,
    epoch: Uuid,
    uid: u32,
    field: rss_mdm_inventory::FieldDefinition,
    value: Option<&str>,
) -> Result<Uuid> {
    let namespace = CollectionScope::MacosApplications {
        root: ApplicationRoot::User,
        uid: Some(uid),
    };
    let definition = CollectionDefinition::new(
        &format!("directory-{uid}"),
        "v1",
        rss_mdm_inventory::Source::AgentNative,
        vec![CollectionField {
            definition: field.clone(),
            scope: namespace.clone(),
        }],
    )?;
    crate::test_support::inventory::register_definition(&definition)?;
    let values = value
        .map(|value| {
            (
                field.key,
                NativeValue::Value(CollectedValue::Value(Scalar::String(value.into()))),
            )
        })
        .into_iter()
        .collect();
    let progress = CollectionProgress::native(definition.clone(), values, 1)?;
    let scope = crate::device::scope_dataset(
        rss_request_context::TenantId::parse(case_tenant())?,
        registration,
        "agent.native",
        epoch,
        definition.dataset(),
    )?
    .encode()?;
    let run = Uuid::new_v4();
    let attempts = serde_json::to_string(&progress)?;
    let terminal = if value.is_some() {
        "'snapshot','complete',2"
    } else {
        "'pending',NULL,NULL"
    };
    pg(&format!(
        "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,sealed_at) VALUES('{}','{run}','{registration}','agent.native','{epoch}','{scope}',{uid},1,'{attempts}',{terminal})",
        case_tenant()
    ))?;
    if let Some(value) = value {
        let value = serde_json::to_string(&Scalar::String(value.into()))?;
        let coverage = serde_json::to_string(&definition.coverage()?)?;
        let namespace = namespace.canonical()?;
        pg(&format!(
            "INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,field_scope,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES('{}','mdm.observation.v1','inventory-projection-v1','{scope}','{coverage}','{}','{namespace}','{value}','{run}',1,2,'known','{registration}','agent.native','{epoch}',{uid})",
            case_tenant(),
            field.key.as_str()
        ))?;
    }
    Ok(run)
}
fn next(path: &str, token: &str) -> String {
    format!(
        "{path}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("cursor", token)
            .append_pair("limit", "1")
            .finish()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.http: authorized device scope discovery, stable history and source fencing"]
async fn inventory_scopes_preserve_history_without_classification_permissions() -> Result<()> {
    let mut f = AssetHttp::open().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let device = case::name("scope-directory");
        let path = format!("/api/v1/devices/{device}/inventory-scopes");
        let (registration, epoch) = crate::test_support::inventory::seed_source(device, "agent", "agent.native", "device")?;
        let model = rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields())?.definition(rss_mdm_inventory::builtin::MODEL)?.clone();
        // Unrelated device partitions must not contribute to this device's directory.
        let (other_registration, other_epoch) = crate::test_support::inventory::seed_source(case::name("unrelated-directory"), "agent", "agent.native", "outside")?;
        seed(other_registration, other_epoch, 400, model.clone(), Some("unrelated"))?;
        // Regression: unrelated retained definitions cannot impose a tenant-wide
        // 4096-dataset availability gate on a single authorized device (PR #1379 F1).
        let mut unrelated = Vec::new();
        for index in 0..4097 {
            let definition = CollectionDefinition::new(
                &format!("unrelated-directory-{index}"), "v1",
                rss_mdm_inventory::Source::AgentNative,
                vec![CollectionField { definition: model.clone(), scope: CollectionScope::MacosApplications { root: ApplicationRoot::User, uid: Some(10000 + index) } }],
            )?;
            unrelated.push(crate::test_support::inventory::definition_sql(case_tenant(), &definition)?);
        }
        pg(&unrelated.join(";"))?;
        // A deleted partition remains fenced by its tombstone, not its older value.
        let deleted = seed(registration, epoch, 504, model.clone(), Some("removed"))?;
        pg(&format!("DELETE FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{deleted}'; DELETE FROM mdm.inventory WHERE tenant_id='{}' AND batch_id='{deleted}'", case_tenant(), case_tenant()))?;
        let first_run = seed(registration, epoch, 501, model.clone(), Some("first"))?;
        seed(registration, epoch, 502, model.clone(), Some("second"))?;
        let first = f.author.call(&f.router, Method::GET, &format!("{path}?limit=1"), None).await?;
        ensure!(first.0 == StatusCode::OK && first.1["asset"]["kind"] == "inventory_scopes");
        ensure!(first.1["asset"]["items"][0]["scope"]["uid"] == 501);
        let cursor = first.1["asset"]["nextCursor"].as_str().ok_or_else(|| anyhow::anyhow!("missing second scope page"))?;
        // New scope creation cannot enter the frozen result, even on the same authenticated source.
        seed(registration, epoch, 503, model.clone(), Some("later"))?;
        let second = f.author.call(&f.router, Method::GET, &next(&path, cursor), None).await?;
        ensure!(second.0 == StatusCode::OK && second.1["asset"]["watermark"] == first.1["asset"]["watermark"]);
        ensure!(second.1["asset"]["items"][0]["scope"]["uid"] == 502 && second.1["asset"]["nextCursor"].is_null());
        let wrong = format!("/api/v1/devices/{}/inventory-scopes", case::name("outside-scope-directory"));
        crate::test_support::inventory::seed_source(case::name("outside-scope-directory"), "agent", "agent.native", "outside")?;
        let foreign = f.author.call(&f.router, Method::GET, &next(&wrong, cursor), None).await?;
        ensure!(foreign.0 == StatusCode::CONFLICT);
        // Retaining a fact is sufficient after the original run was pruned.
        pg(&format!("DELETE FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{first_run}'", case_tenant()))?;
        let retained = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(retained.0 == StatusCode::OK && retained.1["asset"]["items"].as_array().unwrap().len() == 3);
        let mut grants = f.grants.clone();
        grants.push(crate::authorization::Grant { operation: crate::authorization::Permission::InventoryFieldsWrite, scope: crate::authorization::Scope::Tenant });
        crate::test_support::identity::seed_grants(case_tenant(), &f.author_id, grants.clone()).await?;
        let mut secret = model.clone();
        secret.key = rss_mdm_inventory::FieldKey::parse("custom.scope_secret")?;
        secret.sensitivity = rss_mdm_inventory::Sensitivity::Sensitive;
        let publish = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":secret}});
        ensure!(f.author.call(&f.router, Method::PUT, "/api/v1/asset-fields/custom.scope_secret", Some(publish)).await?.0 == StatusCode::OK);
        seed(registration, epoch, 900, secret, None)?;
        let hidden = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(hidden.0 == StatusCode::OK && hidden.1["asset"]["items"].as_array().unwrap().len() == 4 && hidden.1.to_string().contains("900"));
        grants.push(crate::authorization::Grant { operation: crate::authorization::Permission::InventorySensitiveRead, scope: crate::authorization::Scope::Tenant });
        crate::test_support::identity::change_grants(case_tenant(), &f.author_id, grants).await?;
        let visible = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(visible.0 == StatusCode::OK && visible.1["asset"]["items"].as_array().unwrap().len() == 4, "pending authorized scope missing: {visible:?}");
        // Permission changes invalidate a cursor rather than widening its frozen projection.
        ensure!(f.author.call(&f.router, Method::GET, &next(&path, cursor), None).await?.0 == StatusCode::CONFLICT);
        let source_page = f.author.call(&f.router, Method::GET, &format!("{path}?limit=1"), None).await?;
        let source_cursor = source_page.1["asset"]["nextCursor"].as_str().unwrap();
        pg(&format!("UPDATE mdm_access.registrations SET state='superseded' WHERE tenant_id='{}' AND id='{registration}'", case_tenant()))?;
        ensure!(f.author.call(&f.router, Method::GET, &next(&path, source_cursor), None).await?.0 == StatusCode::CONFLICT);
        ensure!(f.author.call(&f.router, Method::GET, &path, None).await?.1["asset"]["items"] == json!([]));
        ensure!(f.author.call(&f.router, Method::GET, &format!("{path}?limit=0"), None).await?.0 == StatusCode::BAD_REQUEST);
        crate::test_support::identity::change_grants(case_tenant(), &f.author_id, vec![]).await?;
        ensure!(f.author.call(&f.router, Method::GET, &path, None).await?.0 == StatusCode::FORBIDDEN);
        ensure!(Browser::default().call(&f.router, Method::GET, &path, None).await?.0 == StatusCode::UNAUTHORIZED);
        Ok(())
    }).await
}
