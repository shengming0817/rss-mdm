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
        json!({"action":"create","assetContext":"endpoint","name":"scale","description":"","criteria":null}),
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
    crate::test_support::stop_worker(automation).await?;

    Ok(())
    }).await

    }).await
}
