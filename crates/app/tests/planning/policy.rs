use crate::test_support::planning_http::*;
use crate::test_support::*;
#[tokio::test]
#[ignore = "make t2 MODULE=planning.policy"]
async fn assignment_pagination_uses_published_scope_without_eager_execution() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {

    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let member = browser_subject(&browser, &router).await?;
    let mut grants = identity::device_grants(None, &["inventory_read", "configuration_write"])?;
    for permission in [
        "group_read",
        "group_write",
        "group_recompute",
        "scope_read",
        "scope_write",
        "policy_read",
        "policy_write",
        "resource_read",
        "resource_write",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(permission))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::set_grants(case_tenant(), &member, grants).await?;
    let automation = start_automation(&fixture.base).await?;
    let resource = Uuid::new_v4();
    native_configuration_resource(
        &mut browser,
        &router,
        resource,
        "windows",
        "x86_64",
        windows_configuration(),
    )
    .await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v1/policies/{id}");
    let policy = path.as_str();
    let browser = &mut browser;
    let router = &router;
    let prefix = uuid::Uuid::new_v4();
    // Cross the production assignment page of 64 with the smallest second page.
    pg(&format!(
        "CREATE TEMP TABLE scale_devices AS SELECT '{prefix}-'||n::text AS device,gen_random_uuid() AS grant_id,gen_random_uuid() AS request,gen_random_uuid() AS registration FROM generate_series(1,65) n;INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) SELECT '{TENANT}',grant_id,'fixture','{INSTANCE}',device,'enrollment','consumed',clock_timestamp()+interval '200 seconds' FROM scale_devices;INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) SELECT '{TENANT}',request,grant_id,'mdm.windows','Device' FROM scale_devices;INSERT INTO mdm_access.devices SELECT '{TENANT}',device FROM scale_devices;INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) SELECT '{TENANT}',registration,device,'mdm',1,request,'active','primary',gen_random_uuid() FROM scale_devices; INSERT INTO mdm_access.credentials SELECT '{TENANT}',gen_random_uuid(),registration,'mdm',md5(registration::text)||md5(registration::text),'active' FROM scale_devices; INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) SELECT '{TENANT}',registration,'mdm.windows','77777777-7777-4777-8777-777777777777',true FROM scale_devices;",
        TENANT = case_tenant()
    ))?;
    await_ingress().await?;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let group_path = format!("/api/v1/groups/{group}");
    call(
        browser,
        router,
        &group_path,
        0,
        json!({"action":"create","assetContext":"endpoint","presentation":{"name":"scale","description":""},"criteria":null}),
    )
    .await?;
    let devices = (1..=65)
        .map(|n| format!("{prefix}-{n}"))
        .collect::<Vec<_>>();
    for (index, batch) in devices.chunks(100).enumerate() {
        call(
            browser,
            router,
            &group_path,
            index as u64 + 1,
            json!({"action":"members","add":batch.iter().map(|id|json!({"kind":"endpoint","id":id})).collect::<Vec<_>>(),"remove":[]}),
        )
        .await?;
    }
    call(browser,router,&group_path,2,json!({"action":"members","add":[],"remove":[{"kind":"endpoint","id":devices[1]}]})).await?;
    let retained=browser.call(router,Method::GET,&format!("/api/v1/devices/{}/groups",devices[0]),None).await?;
    ensure!(retained.0==StatusCode::OK && retained.1["items"][0]["id"]==group.to_string(),"sparse membership lost unchanged endpoint: {retained:?}");
    let removed=browser.call(router,Method::GET,&format!("/api/v1/devices/{}/groups",devices[1]),None).await?;
    ensure!(removed.0==StatusCode::OK && removed.1["items"]==json!([]),"removed endpoint retained: {removed:?}");
    call(browser,router,&group_path,3,json!({"action":"members","add":[{"kind":"endpoint","id":devices[1]}],"remove":[]})).await?;
    call(browser,router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let definition = json!({"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"kind":"configuration","exit":"retain"}});
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    call(
        browser,
        router,
        policy,
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    // Scope publication is the fixture prerequisite. Stop its producer before the
    // bounded read/CAS checks, which do not measure background reconciliation throughput.
    crate::test_support::stop_worker(automation).await?;
    let membership_path=format!("/api/v1/devices/{}-1/groups?limit=1",prefix);
    let (status,memberships)=browser.call(router,Method::GET,&membership_path,None).await?;
    ensure!(status==StatusCode::OK && memberships["items"].as_array().is_some_and(|items|items.iter().any(|item|item["id"]==group.to_string())),"reverse memberships: {status} {memberships}");
    let deletion=json!({"operationId":Uuid::new_v4(),"expectedRevision":1});
    let rejected=settled_delete(browser,router,policy,deletion).await?;
    ensure!(rejected.0==StatusCode::CONFLICT,"enabled delete: {rejected:?}");
    let other_policy=Uuid::new_v4();
    call(browser,router,&format!("/api/v1/policies/{other_policy}"),0,json!({"action":"put","enabled":false,"definition":definition})).await?;
    let first=browser.call(router,Method::GET,&format!("/api/v1/policies?resource={resource}&limit=1"),None).await?;
    ensure!(first.0==StatusCode::OK,"policy directory: {first:?}");
    let token=first.1["nextCursor"].as_str().ok_or_else(||anyhow::anyhow!("policy cursor missing: {first:?}"))?;
    let second=browser.call(router,Method::GET,&format!("/api/v1/policies?resource={resource}&limit=1&cursor={token}"),None).await?;
    ensure!(second.0==StatusCode::OK && second.1["nextCursor"].is_null(),"policy paging: {second:?}");
    let page_id = |page: &serde_json::Value| -> Result<Uuid> {
        let items = page["items"].as_array().ok_or_else(|| anyhow::anyhow!("missing policy items: {page}"))?;
        ensure!(items.len() == 1, "expected one policy per page: {page}");
        Ok(Uuid::parse_str(items[0]["id"].as_str().ok_or_else(|| anyhow::anyhow!("missing policy ID: {page}"))?)?)
    };
    ensure!(page_id(&json!({"items":[],"nextCursor":null})).is_err(), "empty policy page must fail validation");
    let actual = std::collections::BTreeSet::from([page_id(&first.1)?, page_id(&second.1)?]);
    ensure!(actual == std::collections::BTreeSet::from([id, other_policy]), "incomplete policy pages: {actual:?}");
    let changed=browser.call(router,Method::GET,&format!("/api/v1/policies?resource={resource}&state=disabled&limit=1&cursor={token}"),None).await?;
    ensure!(changed.0==StatusCode::CONFLICT,"changed cursor filter: {changed:?}");
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let path = match &cursor {
            Some(after) => format!("{policy}/assignments?after={after}"),
            None => format!("{policy}/assignments"),
        };
        let (status, page) = browser.call(router, Method::GET, &path, None).await?;
        ensure!(status == StatusCode::OK, "assignment page {page}");
        let items = page["items"].as_array().unwrap();
        ensure!(items.len() <= 64);
        for item in items {
            let device = item["target"]["device"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing assignment target: {item}"))?;
            ensure!(
                seen.insert(device.to_owned()),
                "duplicate assignment: {device}"
            );
        }
        cursor = page["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    ensure!(
        seen == devices.into_iter().collect(),
        "assignment pagination lost or added devices"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}'",
            case_tenant()
        ))? == before
    );
    call(browser,router,policy,1,json!({"action":"disable"})).await?;
    let deletion=json!({"operationId":Uuid::new_v4(),"expectedRevision":2});
    let deleted=settled_delete(browser,router,policy,deletion.clone()).await?;
    ensure!(deleted.0==StatusCode::OK && deleted.1["state"]=="archived","disabled delete: {deleted:?}");
    let replay=settled_delete(browser,router,policy,deletion).await?;
    ensure!(replay==deleted,"delete replay changed receipt");
    let enabled=settled_write(browser,router,policy,json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"enable"}})).await?;
    ensure!(enabled.0==StatusCode::CONFLICT,"archived enable: {enabled:?}");
    let directory=browser.call(router,Method::GET,&format!("/api/v1/policies?resource={resource}"),None).await?;
    ensure!(directory.0==StatusCode::OK && directory.1["items"].as_array().is_some_and(|v|v.len()==1) && directory.1["items"][0]["id"]==other_policy.to_string());
    let directory=browser.call(router,Method::GET,&format!("/api/v1/policies?state=archived&resource={resource}"),None).await?;
    ensure!(directory.0==StatusCode::OK && directory.1["items"][0]["id"]==id.to_string());
    let legacy=browser.call(router,Method::GET,&format!("/api/v1/policies?after={id}"),None).await?;
    ensure!(legacy.0==StatusCode::BAD_REQUEST);
    let retained:Value=serde_json::from_str(&pg(&format!("SELECT jsonb_build_array(count(*),count(resource)) FROM mdm_policy.versions WHERE tenant_id='{}' AND policy='{id}'",case_tenant()))?)?;
    ensure!(retained==json!([1,1]),"archive lost immutable references: {retained}");


    Ok(())
    }).await

    }).await
}

async fn settled_delete(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    body: Value,
) -> Result<(StatusCode, Value)> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = browser
                .call(router, Method::DELETE, path, Some(body.clone()))
                .await?;
            if response.0 != StatusCode::SERVICE_UNAVAILABLE {
                return Ok(response);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("policy delete did not settle using its original operation identity")
    })?
}
