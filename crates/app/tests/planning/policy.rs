use crate::test_support::planning_http::*;
use crate::test_support::*;
#[tokio::test]
#[ignore = "make t2 MODULE=planning.policy"]
async fn large_assignment_uses_published_scope_without_eager_execution() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let reader = authority::reader(&fixture.base).await?;
    let router = app(&fixture.base, reader.clone()).await?;
    let mut browser = fixture.browser("other")?;
    let member = browser_subject(&browser, &router).await?;
    let mut grants = identity::device_grants(None, &["inventory_read", "firewall_write"])?;
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
    let path = format!("/api/v3/resources/{resource}");
    call(
        &mut browser,
        &router,
        &path,
        0,
        json!({"action":"create","kind":"configuration"}),
    )
    .await?;
    call(
        &mut browser,
        &router,
        &path,
        1,
        json!({"action":"firewall_version","version":"v1","enabled":true}),
    )
    .await?;
    call(
        &mut browser,
        &router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let scope = Uuid::new_v4();
    call(
        &mut browser,
        &router,
        &format!("/api/v2/scopes/{scope}"),
        0,
        json!({"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}),
    )
    .await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v2/policies/{id}");
    call(&mut browser,&router,&path,0,json!({"action":"put","enabled":true,"definition":{"resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"domain-firewall"},"scope":scope,"behavior":{"kind":"configuration","exit":"retain"}}})).await?;
    let policy = path.as_str();
    let revision = 1;
    let browser = &mut browser;
    let router = &router;
    let prefix = uuid::Uuid::new_v4();
    pg(&format!(
        "CREATE TEMP TABLE scale_devices AS SELECT '{prefix}-'||n::text AS device,gen_random_uuid() AS grant_id,gen_random_uuid() AS request,gen_random_uuid() AS registration FROM generate_series(1,1001) n;INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) SELECT '{TENANT}',grant_id,'fixture','{INSTANCE}',device,'enrollment','consumed',clock_timestamp()+interval '200 seconds' FROM scale_devices;INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) SELECT '{TENANT}',request,grant_id,'mdm.windows' FROM scale_devices;INSERT INTO mdm_access.devices SELECT '{TENANT}',device FROM scale_devices;INSERT INTO mdm_access.registrations SELECT '{TENANT}',registration,device,'mdm',1,request,'active' FROM scale_devices; INSERT INTO mdm_access.credentials SELECT '{TENANT}',gen_random_uuid(),registration,'mdm',md5(registration::text)||md5(registration::text),'active' FROM scale_devices; INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) SELECT '{TENANT}',registration,'mdm.windows','77777777-7777-4777-8777-777777777777','device-basics/2/model-os/typed-v2',true FROM scale_devices;",
        TENANT = case_tenant()
    ))?;
    await_ingress().await?;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let group_path = format!("/api/v2/groups/{group}");
    call(
        browser,
        router,
        &group_path,
        0,
        json!({"action":"create","name":"scale","description":"","criteria":null}),
    )
    .await?;
    let devices = (1..=1001)
        .map(|n| format!("{prefix}-{n}"))
        .collect::<Vec<_>>();
    for (index, batch) in devices.chunks(100).enumerate() {
        call(
            browser,
            router,
            &group_path,
            index as u64 + 1,
            json!({"action":"members","add":batch,"remove":[]}),
        )
        .await?;
    }
    call(browser,router,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let current = browser.call(router, Method::GET, policy, None).await?.1;
    let mut definition = current["definition"].clone();
    definition["scope"] = json!(scope);
    // This fixture grants publish authority separately from scope/member read authority.
    let member = browser_subject(browser, router).await?;
    let grants =
        crate::test_support::identity::device_grants(None, &["firewall_write", "inventory_read"])?;
    let mut grants = grants;
    for permission in [
        crate::authorization::Permission::PolicyRead,
        crate::authorization::Permission::PolicyWrite,
        crate::authorization::Permission::ScopeRead,
        crate::authorization::Permission::ResourceRead,
        crate::authorization::Permission::ResourceWrite,
        crate::authorization::Permission::GroupRead,
        crate::authorization::Permission::GroupWrite,
    ] {
        grants.push(crate::authorization::Grant {
            operation: permission,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::test_support::identity::set_grants(case_tenant(), &member, grants).await?;
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    call(
        browser,
        router,
        policy,
        revision,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    let mut cursor = None;
    let mut count = 0;
    loop {
        let path = match &cursor {
            Some(after) => format!("{policy}/devices?after={after}"),
            None => format!("{policy}/devices"),
        };
        let (status, page) = browser.call(router, Method::GET, &path, None).await?;
        ensure!(status == StatusCode::OK, "assignment page {page}");
        let items = page["items"].as_array().unwrap();
        ensure!(items.len() <= 64);
        count += items.len();
        cursor = page["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    ensure!(count == 1001);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}'",
            case_tenant()
        ))? == before
    );
    crate::test_support::stop_worker(automation).await?;
    reader.close().await;
    Ok(())
}
