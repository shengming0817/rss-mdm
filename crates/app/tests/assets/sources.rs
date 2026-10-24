use super::*;
async fn source_matrix(browser: &mut Browser, router: &Router) -> Result<()> {
    let (mdm, _) = seed_source("asset-b", "mdm", "mdm.windows", "Same")?;
    let (agent, _) = seed_source("asset-b", "agent", "agent.builtin", "Same")?;
    let path = "/api/v1/devices/asset-b/inventory";
    pg(&format!(
        "UPDATE mdm.inventory SET value='{{\"kind\":\"string\",\"value\":\"Different\"}}' WHERE registration='{agent}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "conflict");
    let query = rsql_query(predicate("device.model", "string", json!("Same")));
    let found = ok(
        browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(query.clone()),
    )
    .await?;
    ensure!(found["asset"]["summary"]["matched"] == 0 && found["asset"]["summary"]["unknown"] == 2);
    pg(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{mdm}'; UPDATE mdm.inventory SET value='{{\"kind\":\"string\",\"value\":\"Late old value\"}}' WHERE registration='{mdm}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
            == "Different"
    );
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["sources"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    Ok(())
}
async fn retained_collection_quality(browser: &mut Browser, router: &Router) -> Result<()> {
    let (registration, epoch) = seed_source("tie-b", "agent", "agent.builtin", "quality-sequence")?;
    let scope = crate::device::scope(
        rss_request_context::TenantId::parse(case_tenant())?,
        registration,
        "agent.builtin",
        epoch,
    )?
    .encode()?
    .replace('\'', "''");
    let older = "80000000-0000-4000-8000-000000000001";
    let newer = "80000000-0000-4000-8000-000000000002";
    let definition = crate::test_support::inventory::definition(
        "inventory",
        "agent.builtin",
        &[
            rss_mdm_inventory::builtin::MODEL,
            rss_mdm_inventory::builtin::OS_VERSION,
        ],
    );
    let progress =
        rss_mdm_inventory::CollectionProgress::native(definition, Default::default(), 1)?;
    let attempts = serde_json::to_string(&progress)?;
    for id in [older, newer] {
        pg(&format!(
            "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,sealed_at,delivery_pending) VALUES('{TENANT}','{id}','{registration}','agent.builtin','{epoch}','{scope}',7,1,'{attempts}','failed','timeout',2,false)",
            TENANT = case_tenant()
        ))?;
    }
    let query = rsql_query(predicate(
        "device.model",
        "string",
        json!("quality-sequence"),
    ));
    for expected in [newer, older] {
        let detail = ok(
            browser,
            router,
            Method::GET,
            "/api/v1/devices/tie-b/inventory",
            None,
        )
        .await?;
        ensure!(detail["asset"]["device"]["quality"][0]["runId"] == expected);
        let page = ok(
            browser,
            router,
            Method::POST,
            "/api/v1/device-queries",
            Some(query.clone()),
        )
        .await?;
        ensure!(
            page["asset"]["items"][0]["quality"] == detail["asset"]["device"]["quality"],
            "retaining one run must not erase another with the same sequence"
        );
        if expected == newer {
            pg(&format!(
                "DELETE FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{newer}'",
                TENANT = case_tenant()
            ))?;
        }
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.sources: real Router and persisted assets"]
async fn sources_resolution_and_retained_quality() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    source_matrix(&mut browser, router).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','tie-b')",
        TENANT = case_tenant()
    ))?;
    retained_collection_quality(&mut browser, router).await?;
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.sources: scoped history, exact reads and shared Group evaluation"]
async fn historical_users_are_isolated_and_conditions_never_join_their_facts() -> Result<()> {
    use rss_mdm_inventory::{
        ApplicationRoot, CollectedValue, CollectionDefinition, CollectionField, CollectionProgress,
        CollectionScope, NativeValue, Scalar, Source, builtin,
    };
    let fixture = Fixture::open().await?;
    let mut browser = fixture.browser.clone();
    let (registration, epoch) = seed_source("asset-a", "agent", "agent.native", "device-default")?;
    let tenant = case_tenant();
    let catalog = rss_mdm_inventory::Catalog::new(builtin::fields())?;
    let mut scopes = Vec::new();
    for (uid, model, os) in [
        (501, "wanted-model", "other-os"),
        (502, "other-model", "wanted-os"),
    ] {
        let selected = CollectionScope::MacosApplications {
            root: ApplicationRoot::User,
            uid: Some(uid),
        };
        let dataset = format!("scope-fixture-{uid}");
        let definition = CollectionDefinition::new(
            &dataset,
            "v1",
            Source::AgentNative,
            [builtin::MODEL, builtin::OS_VERSION]
                .into_iter()
                .map(|key| {
                    Ok(CollectionField {
                        definition: catalog.definition(key)?.clone(),
                        scope: selected.clone(),
                    })
                })
                .collect::<rss_mdm_inventory::Result<Vec<_>>>()?,
        )?;
        crate::test_support::inventory::register_definition(&definition)?;
        let progress = CollectionProgress::native(
            definition.clone(),
            [
                (
                    builtin::MODEL,
                    NativeValue::Value(CollectedValue::Value(Scalar::String(model.into()))),
                ),
                (
                    builtin::OS_VERSION,
                    NativeValue::Value(CollectedValue::Value(Scalar::String(os.into()))),
                ),
            ]
            .into(),
            1,
        )?;
        let scope = crate::device::scope_dataset(
            rss_request_context::TenantId::parse(tenant)?,
            registration,
            "agent.native",
            epoch,
            &dataset,
        )?
        .encode()?;
        let run = Uuid::new_v4();
        let attempts = serde_json::to_string(&progress)?;
        let coverage = serde_json::to_string(&definition.coverage()?)?;
        let field_scope = selected.canonical()?;
        pg(&format!(
            "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,sealed_at) VALUES('{tenant}','{run}','{registration}','agent.native','{epoch}','{scope}',{uid},1,'{attempts}','snapshot','complete',2)"
        ))?;
        for (field, value) in [(builtin::MODEL, model), (builtin::OS_VERSION, os)] {
            let field = field.as_str();
            let value = serde_json::to_string(&Scalar::String(value.into()))?;
            pg(&format!(
                "INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,field_scope,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES('{tenant}','mdm.observation.v1','inventory-projection-v1','{scope}','{coverage}','{field}','{field_scope}','{value}','{run}',1,2,'known','{registration}','agent.native','{epoch}',{uid})"
            ))?;
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("scope", &field_scope)
            .finish();
        let detail = ok(
            &mut browser,
            &fixture.router,
            Method::GET,
            &format!("/api/v1/devices/asset-a/inventory?{query}"),
            None,
        )
        .await?;
        ensure!(
            detail["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"] == model
        );
        ensure!(
            detail["asset"]["device"]["quality"][0]["fields"][0]["scope"]
                == serde_json::to_value(&selected)?
        );
        scopes.push(selected);
    }
    let ast = json!({"kind":"and","children":[
        {"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"wanted-model"}},
        {"kind":"predicate","field":"device.os.version","op":"eq","value":{"kind":"string","value":"wanted-os"}}
    ]});
    let condition = json!({"selector":{"kind":"all_authorized"},"quantifier":"any","criteria":ast});
    let query = ok(
        &mut browser,
        &fixture.router,
        Method::POST,
        "/api/v1/device-queries",
        Some(rsql_query(condition.clone())),
    )
    .await?;
    ensure!(
        query["asset"]["summary"]["matched"] == 0,
        "cross-user match: {query}"
    );
    let group = format!("/api/v1/groups/{}", Uuid::new_v4());
    ok(&mut browser, &fixture.router, Method::POST, &group, Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"scope isolation","description":""},"criteria":condition})))).await?;
    let evidence = preview(&mut browser, &fixture.router, &group).await?;
    ensure!(
        evidence.members["page"]["items"] == json!([]),
        "cross-user group: {}",
        evidence.members
    );
    let one = json!({"selector":{"kind":"exact","scope":scopes[0]},"quantifier":"one","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"wanted-model"}}});
    let query = ok(
        &mut browser,
        &fixture.router,
        Method::POST,
        "/api/v1/device-queries",
        Some(rsql_query(one.clone())),
    )
    .await?;
    ensure!(query["asset"]["summary"]["matched"] == 1);
    fixture.close().await
}
