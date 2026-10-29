use crate::test_support::planning_http::*;
use crate::test_support::{http::*, process::*, runtime::*, *};
#[tokio::test]
#[ignore = "make t2 MODULE=policy.service"]
async fn assignment_pagination_uses_published_scope_without_eager_execution() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {

        let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = crate::planning::test_support::cursor_key(tenant).await;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(crate::planning::test_support::OwnerFixture::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects)).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { scopes:crate::planning::test_support::scopes(&planning).await, groups }));
    let content = crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
    if let Some(store) = &content { app_resources.resource(crate::execution_assembly::ContentResource(store.clone())); }
    let catalog = {
            let owner=crate::planning::test_support::owner(audit.clone(),tenant,"mdm_resource_runtime").await;
            crate::resource_assembly::catalog(owner.audit,owner.runtime,tenant,clock.clone(),crate::planning::test_support::cursor_key(tenant).await)
        }.await?;
    let content_access = Arc::new({ let content_owner=crate::planning::test_support::owner(audit.clone(),tenant,"mdm_content_runtime").await; rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: content_owner.runtime.clone(), audit_store: content_owner.audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    } });
    let routes = {
 rss_mdm_http_contract::route_module! { struct AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule2 for [Browser] { base, http_routes } }
 AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule2 { base: routes,
http_routes: rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: catalog.clone(), content: Some(content_access.clone()) })) }.assemble()
};
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let input_materials = Arc::new(rss_mdm_execution_service::InputMaterials {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: config.recovery_credentials.is_some(), protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(),  content: content.clone(), signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    });
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::bind(command_runtime.clone(), tenant, input_materials.clone()));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
read_pool: crate::test_support::query_reads::command_pool(&mut app_resources,&config).await?,
        source: Arc::new(rss_mdm_execution_service::scope::source::ExecutionSource { objects: planning.objects.clone(), policies:Arc::new(rss_mdm_policy_service::management::source::PolicySource{objects:planning.objects.clone()}), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs: inputs.clone(), signed: false, content_available: content.is_some(),
    }));
    let policies = Arc::new(rss_mdm_policy_service::management::Policies::new(rss_mdm_policy_service::management::Dependencies {
profile_validator: std::sync::Arc::new(rss_mdm_telemetry_service::profile_validation::ProfileValidator),
cursor_key: (key).to_vec(),
runtime: runtime.clone(),
reconcile_messaging: rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?,
audit_store: audit.clone(),
tenant,
policy_store: Arc::new(rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?),
inputs: Arc::new(rss_mdm_execution_service::Inputs::bind(runtime.clone(),tenant,input_materials.clone())),
}));
    let routes = {
 rss_mdm_http_contract::route_module! { struct AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule3 for [Browser] { base, http_routes } }
 AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule3 { base: routes,
http_routes: rss_mdm_management_http::planning::policies::http::routes(queries.clone(), rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor")).with_state(policies) }.assemble()
};
    let routes = {
 rss_mdm_http_contract::route_module! { struct AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule4 for [Browser] { base, http_previews } }
 AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule4 { base: routes,
http_previews: rss_mdm_management_http::planning::policies::http::previews(queries, None, rss_mdm_query::cursor::CursorCodec::new(&[31;32])?) }.assemble()
};
    let router = fixture.router({
 rss_mdm_http_contract::route_module! { struct AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule1 for [Browser] { api_v1 at "/api/v1", fixture } }
 AssignmentPaginationUsesPublishedScopeWithoutEagerExecutionModule1 { api_v1: routes,
fixture: fixture.authorization() }.assemble()
})?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let member = prepared_subject(&browser)?;
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
    identity::seed_grants(case_tenant(), &member, grants.clone()).await?;
    let resource = Uuid::new_v4();
    native_configuration_resource(&planning.resource.runtime, planning.tenant, content.as_deref().expect("native content"),
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
    // An explicit small window exercises continuation independently of the default 1000.
    pg(&format!(
        "CREATE TEMP TABLE scale_devices AS SELECT '{prefix}-'||n::text AS device,gen_random_uuid() AS grant_id,gen_random_uuid() AS request,gen_random_uuid() AS registration FROM generate_series(1,65) n;INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) SELECT '{TENANT}',grant_id,'fixture','{INSTANCE}',device,'enrollment','consumed',clock_timestamp()+interval '200 seconds' FROM scale_devices;INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) SELECT '{TENANT}',request,grant_id,'mdm.windows','Device' FROM scale_devices;INSERT INTO mdm_access.devices SELECT '{TENANT}',device FROM scale_devices;INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) SELECT '{TENANT}',registration,device,'mdm',1,request,'active','primary',gen_random_uuid() FROM scale_devices; INSERT INTO mdm_access.credentials SELECT '{TENANT}',gen_random_uuid(),registration,'mdm',md5(registration::text)||md5(registration::text),'active' FROM scale_devices; INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) SELECT '{TENANT}',registration,'mdm.windows','77777777-7777-4777-8777-777777777777',true FROM scale_devices;",
        TENANT = case_tenant()
    ))?;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let group_path = format!("/api/v1/groups/{group}");
    let devices = (1..=65).map(|n| format!("{prefix}-{n}")).collect::<Vec<_>>();
    let automation = start_automation(&fixture.base).await?;
    await_ingress().await?;
    call(browser, router, &group_path, 0, json!({"action":"create","assetContext":"endpoint","presentation":{"name":"scale","description":""},"criteria":null})).await?;
    call(browser, router, &group_path, 1, json!({"action":"members","add":devices.iter().map(|id|json!({"kind":"endpoint","id":id})).collect::<Vec<_>>(),"remove":[]})).await?;
    call(browser,router,&group_path,2,json!({"action":"members","add":[],"remove":[{"kind":"endpoint","id":devices[1]}]})).await?;
    let retained=browser.call(router,Method::GET,&format!("/api/v1/devices/{}/groups",devices[0]),None).await?;
    ensure!(retained.0==StatusCode::OK && retained.1["items"][0]["id"]==group.to_string(),"sparse membership lost unchanged endpoint: {retained:?}");
    let removed=browser.call(router,Method::GET,&format!("/api/v1/devices/{}/groups",devices[1]),None).await?;
    ensure!(removed.0==StatusCode::OK && removed.1["items"]==json!([]),"removed endpoint retained: {removed:?}");
    call(browser,router,&group_path,3,json!({"action":"members","add":[{"kind":"endpoint","id":devices[1]}],"remove":[]})).await?;
    crate::test_support::agent_execution::seed_scope(&planning, scope, json!([{"kind":"group","id":group}])).await?;
    let definition = json!({"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"kind":"configuration","exit":"retain"}});
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    // Scope publication is the fixture prerequisite. Stop its producer before the
    // bounded read/CAS checks, which do not measure background reconciliation throughput.
    crate::test_support::runtime::stop_worker(automation).await?;
    // Real policy publication must wait for the asset fence without holding authority:
    // native completion holds that fence before revalidating its frozen authority.
    use sqlx::Connection;
    let mut fence = sqlx::PgConnection::connect_with(&crate::planning::test_support::options().username("postgres").password("local-fixture")).await?;
    sqlx::query("BEGIN").execute(&mut fence).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut fence).await?;
    sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)").bind(case_tenant()).execute(&mut fence).await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut fence).await?;
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT mdm.lock_asset_watermark%')").fetch_one(&mut fence).await?;
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2363))").bind(format!("{}:{INSTANCE}",case_tenant())).fetch_one(&mut fence).await?;
            ensure!(free, "policy retained authority while waiting for the asset watermark");
            Ok::<_, anyhow::Error>(())
        }).await;
        // Release even on a failed assertion so the original request can settle.
        sqlx::query("ROLLBACK").execute(&mut fence).await?;
        observed.map_err(|_| anyhow::anyhow!("policy did not reach its asset fence"))?
    };
    let (published, released) = tokio::join!(call(browser, router, policy, 0, json!({"action":"put","enabled":true,"definition":definition})), release);
    released?;
    published?;
    fence.close().await?;
    let mut preview_cursor = None;
    let mut preview_objects = std::collections::BTreeSet::new();
    loop {
        let path = match &preview_cursor { Some(cursor) => format!("/api/v1/policies/previews?limit=32&cursor={cursor}"), None => "/api/v1/policies/previews?limit=32".into() };
        let (status,page) = browser.call(router,Method::POST,&path,Some(json!({"definition":definition}))).await?;
        ensure!(status == StatusCode::OK, "preview page: {status} {page}");
        let items=page["items"].as_array().unwrap();
        ensure!(!items.is_empty() && items.len() <= 32);
        for item in items { ensure!(preview_objects.insert(item["object"].to_string()), "duplicate preview object"); }
        if let Some(cursor)=page["nextCursor"].as_str() {
            let mut changed=definition.clone();changed["action"]["exit"]=json!("remove");
            let response=browser.call(router,Method::POST,&format!("/api/v1/policies/previews?limit=32&cursor={cursor}"),Some(json!({"definition":changed}))).await?;
            ensure!(response.0 == StatusCode::CONFLICT,"preview definition binding: {response:?}");
            preview_cursor=Some(cursor.to_owned());
        } else { break; }
        ensure!(preview_objects.len() <= 65);
    }
    ensure!(preview_objects.len()==65,"preview continuation lost objects");
    let membership_path=format!("/api/v1/devices/{}-1/groups?limit=1",prefix);
    let (status,memberships)=browser.call(router,Method::GET,&membership_path,None).await?;

    ensure!(status==StatusCode::OK && memberships["items"].as_array().is_some_and(|items|items.iter().any(|item|item["id"]==group.to_string())),"reverse memberships: {status} {memberships}");
    let deletion=json!({"operationId":Uuid::new_v4(),"expectedRevision":1});
    let rejected=settled_delete(browser,router,policy,deletion).await?;
    ensure!(rejected.0==StatusCode::CONFLICT,"enabled delete: {rejected:?}");
    let other_policy=Uuid::new_v4();
    let written = settled_write(browser,router,&format!("/api/v1/policies/{other_policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":false,"definition":definition}})).await?;
    ensure!(written.0 == StatusCode::OK && written.1["definition"].get("customEvent") == Some(&Value::Null), "Policy write must emit customEvent:null: {written:?}");
    let first=browser.call(router,Method::GET,&format!("/api/v1/policies?filter=resource=={resource}&limit=1"),None).await?;
    ensure!(first.0==StatusCode::OK,"policy directory: {first:?}");
    ensure!(first.1["items"][0].get("customEvent") == Some(&Value::Null), "Policy list must emit customEvent:null, not omit it");
    let detail = browser.call(router, Method::GET, policy, None).await?;
    ensure!(detail.0 == StatusCode::OK && detail.1["definition"].get("customEvent") == Some(&Value::Null), "Policy detail must emit customEvent:null");
    let token=first.1["nextCursor"].as_str().ok_or_else(||anyhow::anyhow!("policy cursor missing: {first:?}"))?;
    let second=browser.call(router,Method::GET,&format!("/api/v1/policies?filter=resource=={resource}&limit=1&cursor={token}"),None).await?;
    ensure!(second.0==StatusCode::OK && second.1["nextCursor"].is_null(),"policy paging: {second:?}");
    let page_id = |page: &serde_json::Value| -> Result<Uuid> {
        let items = page["items"].as_array().ok_or_else(|| anyhow::anyhow!("missing policy items: {page}"))?;
        ensure!(items.len() == 1, "expected one policy per page: {page}");
        Ok(Uuid::parse_str(items[0]["id"].as_str().ok_or_else(|| anyhow::anyhow!("missing policy ID: {page}"))?)?)
    };
    ensure!(page_id(&json!({"items":[],"nextCursor":null})).is_err(), "empty policy page must fail validation");
    let actual = std::collections::BTreeSet::from([page_id(&first.1)?, page_id(&second.1)?]);
    ensure!(actual == std::collections::BTreeSet::from([id, other_policy]), "incomplete policy pages: {actual:?}");
    let changed=browser.call(router,Method::GET,&format!("/api/v1/policies?filter=resource=={resource};state==disabled&limit=1&cursor={token}"),None).await?;
    ensure!(changed.0==StatusCode::CONFLICT,"changed cursor filter: {changed:?}");
    let default_page = browser.call(router, Method::GET, &format!("{policy}/assignments"), None).await?;
    ensure!(default_page.0 == StatusCode::OK && default_page.1["items"].as_array().unwrap().len() == 65 && default_page.1["nextCursor"].is_null());
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let path = match &cursor {
            Some(after) => format!("{policy}/assignments?limit=64&cursor={after}"),
            None => format!("{policy}/assignments?limit=64"),
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
    // Pause after the continuation stamp is read but before Scope admission finishes.
    let (status, first_page)=browser.call(router,Method::GET,&format!("{policy}/assignments?limit=1"),None).await?;
    ensure!(status==StatusCode::OK);
    let token=first_page["nextCursor"].as_str().unwrap();
    let mut holder=sqlx::PgConnection::connect_with(&crate::planning::test_support::options().username("postgres").password("local-fixture")).await?;
    sqlx::query("BEGIN").execute(&mut holder).await?;
    sqlx::query("SELECT id FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(case_tenant()).bind(scope).fetch_one(&mut holder).await?;
    let change_source=async {
        let waiting=tokio::time::timeout(Duration::from_secs(4),async {
            loop {
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut holder).await?;
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%scope_admission%')").fetch_one(&mut holder).await?;
                if blocked { return Ok::<_,anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        if let Ok(Ok(()))=waiting {
            sqlx::query("INSERT INTO mdm_devices.query_revisions(tenant_id,bucket,revision) VALUES($1::uuid,0,1) ON CONFLICT(tenant_id,bucket) DO UPDATE SET revision=mdm_devices.query_revisions.revision+1").bind(case_tenant()).execute(&mut holder).await?;
            sqlx::query("COMMIT").execute(&mut holder).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut holder).await?;
            anyhow::bail!("continuation did not reach the Scope admission barrier");
        }
        Ok::<_,anyhow::Error>(())
    };
    let continuation=format!("{policy}/assignments?limit=1&cursor={token}");
    let (response,changed)=tokio::join!(browser.call(router,Method::GET,&continuation,None),change_source);
    holder.close().await?;changed?;
    ensure!(response?.0==StatusCode::CONFLICT,"source changed inside a successful page");
    call(browser,router,policy,1,json!({"action":"disable"})).await?;
    let deletion=json!({"operationId":Uuid::new_v4(),"expectedRevision":2});
    let deleted=settled_delete(browser,router,policy,deletion.clone()).await?;
    ensure!(deleted.0==StatusCode::OK && deleted.1["state"]=="archived","disabled delete: {deleted:?}");
    // Receipt replay must use current complete management authority, including readers
    // and the action permission. Neither a replay nor a new request may write after revocation.
    let retained_state = || pg(&format!("SELECT jsonb_build_array((SELECT revision FROM mdm_policy.policies WHERE tenant_id='{tenant}' AND id='{id}'),(SELECT count(*) FROM mdm_policy.requests WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.work WHERE tenant_id='{tenant}'))", tenant=case_tenant()));
    let prior = retained_state()?;
    for permission in [crate::authorization::Permission::PolicyWrite, crate::authorization::Permission::ScopeRead, crate::authorization::Permission::InventoryRead, crate::authorization::Permission::ConfigurationWrite] {
        let limited = grants.iter().filter(|grant| grant.operation != permission).cloned().collect();
        identity::change_grants(case_tenant(), &member, limited).await?;
        let replay = settled_delete(browser,router,policy,deletion.clone()).await?;
        ensure!(replay.0 == StatusCode::FORBIDDEN, "revoked {permission:?} permitted receipt replay: {replay:?}");
        let fresh = settled_write(browser,router,policy,json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"enable"}})).await?;
        ensure!(fresh.0 == StatusCode::FORBIDDEN, "revoked {permission:?} permitted new request: {fresh:?}");
    }
    identity::change_grants(case_tenant(), &member, grants).await?;
    ensure!(retained_state()? == prior, "revoked requests changed Policy state, receipts or work");
    let replay=settled_delete(browser,router,policy,deletion).await?;
    ensure!(replay==deleted,"delete replay changed receipt");
    let enabled=settled_write(browser,router,policy,json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"enable"}})).await?;
    ensure!(enabled.0==StatusCode::CONFLICT,"archived enable: {enabled:?}");
    let directory=browser.call(router,Method::GET,&format!("/api/v1/policies?filter=resource=={resource}"),None).await?;
    ensure!(directory.0==StatusCode::OK && directory.1["items"].as_array().is_some_and(|v|v.len()==1) && directory.1["items"][0]["id"]==other_policy.to_string());
    let directory=browser.call(router,Method::GET,&format!("/api/v1/policies?filter=state==archived;resource=={resource}"),None).await?;
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
