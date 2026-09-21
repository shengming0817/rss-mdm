//! Real authenticated Router, formal PostgreSQL schema and the current Group consumer.
use super::*;
use uuid::Uuid;
fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}
fn predicate(field: &str, kind: &str, value: Value) -> Value {
    json!({"kind":"predicate","field":field,"op":"eq","value":{"kind":kind,"value":value}})
}
async fn ok(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let (s, v) = browser.call(router, method, path, body).await?;
    ensure!(s == StatusCode::OK, "asset request {path}: {s} {v}");
    Ok(v)
}
async fn permissions(subject: &str, device: Option<&str>, write: bool) -> Result<()> {
    let mut grants = crate::identity_fixture::device_grants(
        device,
        if write {
            &["inventory_read", "inventory_assign"]
        } else {
            &["inventory_read"]
        },
    )?;
    for operation in [
        crate::authorization::Permission::GroupRead,
        crate::authorization::Permission::GroupWrite,
        crate::authorization::Permission::GroupRecompute,
    ] {
        grants.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::identity_fixture::set_grants(TENANT, subject, grants).await
}
fn seed_source(device: &str, channel: &str, source: &str, value: &str) -> Result<(Uuid, Uuid)> {
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
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds'); INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES('{TENANT}','{request}','{grant}'); INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','{channel}',1,'{request}','active'); INSERT INTO mdm_access.credentials VALUES('{TENANT}','{credential}','{registration}','{channel}',md5('{credential}')||md5('{registration}'),'active'); INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','{source}','{epoch}','{coverage}',true); INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch) VALUES('{TENANT}','mdm.observation.v1','inventory-v2','{encoded}','{coverage}','device.model','{value}','fixture',1,2,'known','{value}','fixture',1,2,'{registration}','{source}','{epoch}');"
    ))?;
    Ok((registration, epoch))
}
async fn source_matrix(browser: &mut Browser, router: &Router) -> Result<()> {
    let (mdm, _) = seed_source("asset-b", "mdm", "mdm.windows", "Same")?;
    let (agent, _) = seed_source("asset-b", "agent", "agent.builtin", "Same")?;
    let path = "/api/v1/devices/asset-b/inventory";
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "known");
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["sources"]
            .as_array()
            .unwrap()
            .len()
            == 2
    );
    pg(&format!(
        "UPDATE mdm.inventory SET value='Different' WHERE registration='{agent}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "conflict");
    let query = json!({"criteria":predicate("device.model","string",json!("Same"))});
    let found = ok(
        browser,
        router,
        Method::POST,
        "/api/v1/devices/search",
        Some(query.clone()),
    )
    .await?;
    ensure!(found["asset"]["summary"]["matched"] == 0 && found["asset"]["summary"]["unknown"] == 2);
    let group = format!("/api/v1/groups/{}", Uuid::new_v4());
    ok(browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","name":"conflict","description":"","criteria":query["criteria"]})))).await?;
    let preview = ok(
        browser,
        router,
        Method::GET,
        &format!("{group}/preview?expectedRevision=1"),
        None,
    )
    .await?;
    ensure!(
        preview["members"] == json!([])
            && preview["decisions"][1]["explanations"][0]["outcome"]["reason"] == "conflict"
    );
    pg(&format!(
        "UPDATE mdm.inventory SET state='deleted',value=NULL WHERE registration='{agent}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"] == "Same"
    );
    pg(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{mdm}'; UPDATE mdm.inventory SET value='Late old value' WHERE registration='{mdm}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "deleted");
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["sources"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "hack/asset-t2.py: real authenticated Router and TLS PostgreSQL"]
async fn asset_write_query_group_and_isolation() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
    let reader = Arc::new(
        InventoryReader::connect(
            config
                .access_database
                .options()?
                .username("mdm_api")
                .password("api-fixture"),
        )
        .await?,
    );
    let router = app(&base, reader.clone()).await?;
    let mut browser = Browser::default();
    ensure!(browser.login(&router, "admin").await? == StatusCode::OK);
    let subject = browser_subject(&browser, &router).await?;
    permissions(&subject, None, true).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','asset-a'),('{TENANT}','asset-b'),('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','foreign-asset');"
    ))?;
    let catalog = ok(
        &mut browser,
        &router,
        Method::GET,
        "/api/v1/asset-fields",
        None,
    )
    .await?;
    ensure!(catalog["asset"]["fields"].as_array().unwrap().len() == 6);
    let cases = [
        ("custom.asset_tag", "string", json!("A-2463")),
        ("custom.office_floor", "integer", json!(3)),
        ("custom.is_loaner", "boolean", json!(false)),
        ("custom.purchase_date", "time", json!(1_700_000_000)),
    ];
    for (field, kind, value) in cases {
        let path = format!("/api/v1/devices/asset-a/manual-fields/{field}");
        let write = request(
            0,
            json!({"action":"set","value":{"kind":kind,"value":value}}),
        );
        let first = ok(
            &mut browser,
            &router,
            Method::PUT,
            &path,
            Some(write.clone()),
        )
        .await?;
        ensure!(first["asset"]["revision"] == 1);
        ensure!(
            ok(
                &mut browser,
                &router,
                Method::PUT,
                &path,
                Some(write.clone())
            )
            .await?
                == first
        );
        let mut changed = write.clone();
        changed["input"] = json!({"action":"delete"});
        ensure!(
            browser
                .call(&router, Method::PUT, &path, Some(changed))
                .await?
                .0
                == StatusCode::CONFLICT
        );
        let detail = ok(
            &mut browser,
            &router,
            Method::GET,
            "/api/v1/devices/asset-a/inventory",
            None,
        )
        .await?;
        ensure!(
            detail["asset"]["device"]["fields"][field]["state"]["value"]
                == json!({"kind":kind,"value":value})
        );
        let criteria = predicate(field, kind, value);
        let result = ok(
            &mut browser,
            &router,
            Method::POST,
            "/api/v1/devices/search",
            Some(json!({"criteria":criteria})),
        )
        .await?;
        ensure!(
            result["asset"]["summary"]["matched"] == 1
                && result["asset"]["items"][0]["device"] == "asset-a"
        );
        let id = Uuid::new_v4();
        let group = format!("/api/v1/groups/{id}");
        ok(&mut browser,&router,Method::POST,&group,Some(request(0,json!({"action":"create","name":field,"description":"asset proof","criteria":criteria})))).await?;
        let preview = ok(
            &mut browser,
            &router,
            Method::GET,
            &format!("{group}/preview?expectedRevision=1"),
            None,
        )
        .await?;
        ensure!(preview["members"] == json!(["asset-a"]));
        ok(
            &mut browser,
            &router,
            Method::POST,
            &group,
            Some(request(
                1,
                json!({"action":"recompute","snapshot":preview["snapshot"]}),
            )),
        )
        .await?;
        ensure!(
            ok(&mut browser, &router, Method::GET, &group, None).await?["members"]
                == json!(["asset-a"])
        );
    }
    source_matrix(&mut browser, &router).await?;
    let floor = "/api/v1/devices/asset-a/manual-fields/custom.office_floor";
    for input in [
        json!({"action":"set","value":{"kind":"string","value":"3"}}),
        json!({"action":"set","value":{"kind":"integer","value":3},"validUntil":1}),
        json!({"action":"delete","ttl":1}),
    ] {
        ensure!(
            browser
                .call(&router, Method::PUT, floor, Some(request(1, input)))
                .await?
                .0
                .is_client_error()
        );
    }
    ensure!(
        browser
            .call(
                &router,
                Method::PUT,
                "/api/v1/devices/asset-a/manual-fields/device.model",
                Some(request(
                    0,
                    json!({"action":"set","value":{"kind":"string","value":"spoof"}})
                ))
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    ensure!(
        browser
            .call(
                &router,
                Method::GET,
                "/api/v1/devices/asset-a/inventory?source=mdm.windows",
                None
            )
            .await?
            .0
            .is_client_error()
    );
    let query = json!({"limit":1,"sort":{"field":"custom.office_floor"}});
    let first = ok(
        &mut browser,
        &router,
        Method::POST,
        "/api/v1/devices/search",
        Some(query.clone()),
    )
    .await?;
    ensure!(
        first["asset"]["summary"]["total"] == 2
            && first["asset"]["items"][0]["device"] == "asset-a"
    );
    let cursor = first["asset"]["nextCursor"].clone();
    let mut second = query.clone();
    second["cursor"] = cursor.clone();
    ensure!(
        ok(
            &mut browser,
            &router,
            Method::POST,
            "/api/v1/devices/search",
            Some(second.clone())
        )
        .await?["asset"]["items"][0]["device"]
            == "asset-b"
    );
    let saved = Uuid::new_v4();
    let saved_path = format!("/api/v1/saved-queries/{saved}");
    let put = request(
        0,
        json!({"action":"put","definition":{"name":"Floor 3","query":{"criteria":predicate("custom.office_floor","integer",json!(3))}}}),
    );
    let receipt = ok(
        &mut browser,
        &router,
        Method::PUT,
        &saved_path,
        Some(put.clone()),
    )
    .await?;
    ensure!(
        ok(
            &mut browser,
            &router,
            Method::PUT,
            &saved_path,
            Some(put.clone())
        )
        .await?
            == receipt
    );
    ensure!(
        ok(
            &mut browser,
            &router,
            Method::POST,
            &format!("{saved_path}/execute"),
            Some(json!({}))
        )
        .await?["asset"]["summary"]["matched"]
            == 1
    );
    let mut other = Browser::default();
    ensure!(other.login(&router, "other").await? == StatusCode::OK);
    let other_subject = browser_subject(&other, &router).await?;
    permissions(&other_subject, None, true).await?;
    ensure!(other.call(&router, Method::GET, &saved_path, None).await?.0 == StatusCode::NOT_FOUND);
    ensure!(
        other
            .call(
                &router,
                Method::POST,
                &format!("{saved_path}/execute"),
                Some(json!({}))
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    ensure!(
        ok(
            &mut other,
            &router,
            Method::GET,
            "/api/v1/saved-queries",
            None
        )
        .await?["asset"]["items"]
            == json!([])
    );
    ensure!(
        other
            .call(
                &router,
                Method::POST,
                "/api/v1/devices/search",
                Some(second.clone())
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    permissions(&subject, Some("asset-a"), false).await?;
    ensure!(
        browser
            .call(
                &router,
                Method::POST,
                "/api/v1/devices/search",
                Some(second.clone())
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ensure!(
        browser
            .call(
                &router,
                Method::GET,
                "/api/v1/devices/asset-b/inventory",
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        browser
            .call(
                &router,
                Method::PUT,
                floor,
                Some(request(1, json!({"action":"delete"})))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        ok(&mut browser, &router, Method::GET, "/api/v1/devices", None).await?["asset"]["summary"]
            ["total"]
            == 1
    );
    permissions(&subject, None, true).await?;
    let mut a = browser.clone();
    let mut b = browser.clone();
    let (a, b) = tokio::join!(
        a.call(
            &router,
            Method::PUT,
            floor,
            Some(request(
                1,
                json!({"action":"set","value":{"kind":"integer","value":4}})
            ))
        ),
        b.call(
            &router,
            Method::PUT,
            floor,
            Some(request(
                1,
                json!({"action":"set","value":{"kind":"integer","value":5}})
            ))
        )
    );
    let (a, b) = (a?, b?);
    ensure!(
        (a.0 == StatusCode::OK) ^ (b.0 == StatusCode::OK),
        "CAS admitted both/neither: {a:?} {b:?}"
    );
    ensure!(
        browser
            .call(
                &router,
                Method::POST,
                "/api/v1/devices/search",
                Some(second)
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ok(
        &mut browser,
        &router,
        Method::PUT,
        floor,
        Some(request(2, json!({"action":"null"}))),
    )
    .await?;
    let null = ok(
        &mut browser,
        &router,
        Method::GET,
        "/api/v1/devices/asset-a/inventory",
        None,
    )
    .await?;
    ensure!(null["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"] == "null");
    ok(
        &mut browser,
        &router,
        Method::PUT,
        floor,
        Some(request(3, json!({"action":"delete"}))),
    )
    .await?;
    let removed = ok(
        &mut browser,
        &router,
        Method::GET,
        "/api/v1/devices/asset-a/inventory",
        None,
    )
    .await?;
    ensure!(
        removed["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"] == "deleted"
    );
    ensure!(
        removed["asset"]["device"]["fields"]["custom.office_floor"]["sources"][0]["lastKnown"]["value"]
            ["kind"]
            == "integer"
    );
    // Audit failure rolls back an otherwise valid assignment and receipt.
    pg(
        "CREATE FUNCTION public.reject_asset_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='management_write' THEN RAISE EXCEPTION 'fixture'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_asset_audit BEFORE INSERT ON mdm_access.audit FOR EACH ROW EXECUTE FUNCTION public.reject_asset_audit();",
    )?;
    let rejected = browser
        .call(
            &router,
            Method::PUT,
            floor,
            Some(request(
                4,
                json!({"action":"set","value":{"kind":"integer","value":7}}),
            )),
        )
        .await?;
    pg(
        "DROP TRIGGER reject_asset_audit ON mdm_access.audit; DROP FUNCTION public.reject_asset_audit();",
    )?;
    ensure!(rejected.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(pg(&format!("SELECT revision FROM mdm.manual_assignments WHERE tenant_id='{TENANT}' AND device='asset-a' AND field='custom.office_floor'"))?.trim()=="4");
    let deletion = request(1, json!({"action":"delete"}));
    ok(
        &mut browser,
        &router,
        Method::PUT,
        &saved_path,
        Some(deletion),
    )
    .await?;
    ensure!(ok(&mut browser, &router, Method::PUT, &saved_path, Some(put)).await? == receipt);
    ensure!(
        browser
            .call(
                &router,
                Method::POST,
                &format!("{saved_path}/execute"),
                Some(json!({}))
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    reader.close().await;
    Ok(())
}
