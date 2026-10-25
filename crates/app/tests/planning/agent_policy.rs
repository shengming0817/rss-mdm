use crate::audit_test_support::audit_records;
use crate::test_support::agent_execution::*;
use crate::test_support::{agent::*, http::*, process::*, runtime::*, *};
async fn business_event(operation: Uuid) -> Result<String> {
    let operation = operation.to_string();
    let records = audit_records().await?;
    let matching: Vec<_> = records
        .iter()
        .filter(|record| {
            record.source() == "mdm.business" && record.operation() == Some(operation.as_str())
        })
        .collect();
    ensure!(
        matching.len() == 1,
        "operation must retain one business event"
    );
    Ok(matching[0]
        .event
        .event()
        .identity()
        .event_id()
        .as_str()
        .to_owned())
}

async fn policy(
    author: &mut Browser,
    router: &Router,
    resource: Uuid,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let body = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}});
    let before = run_count(id)?;
    runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitPending,
    );
    let path = format!("/api/v1/policies/{id}");
    ensure!(
        author
            .call(router, Method::POST, &path, Some(body.clone()))
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let result = post(author, router, &path, body.clone()).await?;
    ensure!(result["id"] == id.to_string() && result["revision"] == 1);
    let event = business_event(operation).await?;
    ensure!(result == post(author, router, &path, body).await?);
    ensure!(business_event(operation).await? == event);
    ensure!(
        run_count(id)? == before,
        "publication must not fan out runs"
    );
    Ok(id)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn preview_publish_authorization_and_commit_replay() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.router = fixture.router.clone().merge(fixture.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(
                fixture.queries.clone(),
                None,
            ),
        ),
    )?);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    claim_request(&fixture.router, Uuid::new_v4()).await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let (identity, identity_resources) = crate::test_support::identity::identity(case_tenant()).await?;
    identity_resources.finish(async {
    let stale = crate::authorization::context::AuthorizedPrincipal::new(
        identity
            .authority
            .inspect_session(
                identity.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    fixture.author.cookies["__Host-identity-session"].clone(),
                )?,
                crate::identity::deadline(),
            )
            .await?,
    )?
    .load_authorization(&fixture.authority.authorization)
    .await?;
    for permission in [
        crate::authorization::Permission::PolicyRead,
        crate::authorization::Permission::ResourceRead,
    ] {
        let grants = fixture
            .grants
            .iter()
            .filter(|grant| grant.operation != permission)
            .cloned()
            .collect();
        crate::test_support::identity::seed_grants(case_tenant(), &fixture.author_id, grants)
            .await?;
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "management_read", rss_mdm_audit_integration::AuditIntent::Routine);
        stale.bind_audit(&audit)?;
        let result = rss_mdm_execution_service::queries::preview::preview(
            &fixture.queries,
            &stale,
            &audit,
            &rss_mdm_execution_service::queries::preview::Preview {
                definition: serde_json::from_value(policy_definition(id, case_task_scope()))?,
                after: None,
                scope_result: None,
            },
        )
        .await;
        crate::test_support::identity::change_grants(
            case_tenant(),
            &fixture.author_id,
            fixture.grants.clone(),
        )
        .await?;
        ensure!(
            matches!(
                result,
                Err(rss_mdm_execution_service::queries::QueryError::Forbidden)
            ),
            "cached preview proof admitted revoked {permission:?}"
        );
    }
    let router = fixture.router;
    let plan_runtime = fixture.plan_runtime;
    let mut author = fixture.author;
    let author_id = fixture.author_id;
    let grants = fixture.grants;
    let without_resource = grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::ResourceRead)
        .cloned()
        .collect();
    crate::test_support::identity::change_grants(case_tenant(), &author_id, without_resource).await?;
    let denied=author.call(&router,Method::POST,&format!("/api/v1/policies/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,case_task_scope())}}))).await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "publishing without ResourceRead: {denied:?}"
    );
    crate::test_support::identity::change_grants(case_tenant(), &author_id, grants.clone()).await?;
    let preview_before = pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'))",
        tenant = case_tenant()
    ))?;
    let preview = post(
        &mut author,
        &router,
        "/api/v1/policies/previews",
        json!({"definition":policy_definition(id,case_task_scope())}),
    )
    .await?;
    ensure!(preview["items"][0]["eligibility"]["state"] == "eligible");
    ensure!(
        pg(&format!(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'))",
            tenant = case_tenant()
        ))? == preview_before,
        "draft preview published work"
    );
    let _policy_id = policy(&mut author, &router, id, &plan_runtime).await?;
    ensure!(
        author
            .call(
                &router,
                Method::POST,
                &format!("/api/v1/resources/{id}"),
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}})),
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    Ok(())
    }).await
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn explicit_rerun_deduplicates() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.router = fixture.router.clone().merge(fixture.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(
                fixture.queries.clone(),
                None,
            ),
        ),
    )?);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    claim_request(&fixture.router, Uuid::new_v4()).await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = crate::test_support::software_execution::worker(&fixture.base, fixture.execution.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let policy_id = publish(&mut author, &router, id).await?;
    let task = claim(&router).await?;
    complete(&router, &task).await?;
    let completed = run_count(policy_id)?;
    let empty = claim_request(&router, Uuid::new_v4()).await?;
    ensure!(empty.0 == StatusCode::OK && empty.1["task"].is_null());
    ensure!(
        run_count(policy_id)? == completed,
        "once-per-version repeated"
    );
    let rerun = Uuid::new_v4();
    let body = json!({"operationId":rerun,"expectedRevision":1,"input":{"deadline":now+600}});
    let path = format!("/api/v1/policies/{policy_id}/reruns");
    let receipt = post(&mut author, &router, &path, body.clone()).await?;
    ensure!(post(&mut author, &router, &path, body).await? == receipt);
    ensure!(
        run_count(policy_id)? == completed,
        "rerun eagerly expanded devices"
    );
    let (a, b) = tokio::join!(
        claim_request(&router, Uuid::new_v4()),
        claim_request(&router, Uuid::new_v4())
    );
    let a = a?;
    let b = b?;
    ensure!(a.0 == StatusCode::OK && b.0 == StatusCode::OK);
    let again = if !a.1["task"].is_null() {
        a.1["task"].clone()
    } else if !b.1["task"].is_null() {
        b.1["task"].clone()
    } else {
        claim(&router).await?
    };
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE occurrence='explicit:{rerun}'"
        ))?
        .trim()
            == "1",
        "concurrent admission duplicated rerun"
    );
    task_event(&router, &again, json!({"kind":"received"})).await?;
    task_event(&router, &again, json!({"kind":"start"})).await?;
    task_event(&router,&again,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn policy_scan_reaches_late_match() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.router = fixture.router.clone().merge(fixture.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(
                fixture.queries.clone(),
                None,
            ),
        ),
    )?);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    claim_request(&fixture.router, Uuid::new_v4()).await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    fixture.scope(case_empty_scope(), json!([])).await?;
    let stack = crate::test_support::software_execution::worker(&fixture.base, fixture.execution.clone()).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND device='{}'",
        case_tenant(),
        case_device_id()
    ))?;
    let ordered_namespace = case::id("policy-scan") & !0xffff;
    let template_id = Uuid::from_u128(ordered_namespace | 1);
    post(author,router,&format!("/api/v1/policies/{template_id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_empty_scope())}})).await?;
    let policy_store = rss_mdm_policy_postgres::PolicyStore::new(fixture.planning.runtime.clone(), fixture.planning.tenant, crate::identity::deadline()).await?;
    let template = policy_store.get(template_id, crate::identity::deadline()).await?.unwrap();
    let frozen: Value = serde_json::from_str(&pg(&format!("SELECT frozen FROM mdm_policy.versions WHERE tenant_id='{}' AND id='{}'", case_tenant(), template.version))?)?;
    let at = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let prepared: Vec<_> = (2..=64).map(|n| {
        let policy = rss_mdm_policy::Policy::apply(Uuid::from_u128(ordered_namespace | n), None, 0,
            &rss_mdm_policy::Change::Put { definition: Box::new(template.definition.clone()), enabled: true }, Uuid::new_v4(), template.execution_binding).unwrap().policy;
        rss_mdm_policy_postgres::Publication { change: rss_mdm_policy::Change::Put { definition: Box::new(policy.definition.clone()), enabled: policy.state.is_enabled() }, policy, frozen: Some(frozen.clone()), author: json!({"subject":fixture.author_id}), at }
    }).collect();
    fixture.planning.runtime.local_tx_with_context(fixture.planning.tenant, crate::identity::deadline(), (&policy_store, &prepared), |(store, publications), tx| Box::pin(async move {
        for publication in publications.iter() { store.publish_in(tx, publication).await?.unwrap(); }
        Ok(())
    })).await.fold(|_| (), |e|panic!("{e:?}"), |e|panic!("{e:?}"), |e|panic!("{e:?}"), |e|panic!("{e:?}"), |e|panic!("{e:?}"));
    let id = Uuid::from_u128(ordered_namespace | 0xffff);
    post(author,router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}})).await?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND device='{}'",
            case_tenant(),
            case_device_id()
        ))? == before
    );
    pg(&format!(
        "UPDATE mdm_commands.action_polls SET policy_after=NULL WHERE tenant_id='{}' AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{}')",
        case_tenant(),
        case_tenant(),
        case_device_id()
    ))?;
    let task = claim(router)
        .await
        .map_err(|e| anyhow::anyhow!("policy pagination: {e}"))?;
    let task_id = task["payload"]["task"]["taskId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT v.policy FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE r.id='{task_id}'"))?.trim()==id.to_string(),"later policy starved");
    task_event(router, &task, json!({"kind":"received"})).await?;
    task_event(router, &task, json!({"kind":"start"})).await?;
    task_event(router,&task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn policy_reference_and_archive_are_serialized() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.router = fixture.router.clone().merge(fixture.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(
                fixture.queries.clone(),
                None,
            ),
        ),
    )?);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture.scope(case_empty_scope(), json!([])).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    // Both authenticated requests contend on the same active resource version.
    let policy = Uuid::new_v4();
    let create = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,case_empty_scope())}});
    let policy_path = format!("/api/v1/policies/{policy}");
    let archive = json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}});
    let path = format!("/api/v1/resources/{id}");
    let mut archiver = author.clone();
    use sqlx::Connection;
    let mut holder = sqlx::PgConnection::connect_with(&crate::planning::test_support::options().username("postgres").password("local-fixture")).await?;
    let lock = format!("mdm_resource:{}:resource:{id}", case_tenant());
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,2388))").bind(&lock).execute(&mut holder).await?;
    let release = async {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked").fetch_one(&mut holder).await?;
                if waiting >= 2 { return Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,2388))").bind(&lock).execute(&mut holder).await?;
        Ok::<_, anyhow::Error>(())
    };
    let (created, archived, released) = tokio::join!(
        author.call(router, Method::POST, &policy_path, Some(create)),
        archiver.call(router, Method::POST, &path, Some(archive.clone())), release);
    holder.close().await?;
    released?;
    let (created, archived) = (created?, archived?);
    ensure!(
        created.0.is_success() != archived.0.is_success(),
        "archive race: {created:?} / {archived:?}"
    );
    if created.0.is_success() {
        ensure!(archived.0 == StatusCode::CONFLICT);
        post(
            author,
            router,
            &policy_path,
            json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
        )
        .await?;
        let historical = archiver
            .call(router, Method::POST, &path, Some(archive))
            .await?;
        ensure!(
            historical.0 == StatusCode::CONFLICT,
            "disabled policy lost historical reference: {historical:?}"
        );
    } else {
        ensure!(
            created.0 == StatusCode::CONFLICT,
            "archived resource admitted: {created:?}"
        );
    }
    Ok(())
    }).await
}

async fn reject_script_at_all_entrances(
    fixture: &mut Fixture,
    definition: Value,
    expected: StatusCode,
) -> Result<()> {
    let requests = [
        (
            "/api/v1/policies/previews".to_owned(),
            json!({"definition":definition}),
        ),
        (
            format!("/api/v1/policies/{}", Uuid::new_v4()),
            json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}}),
        ),
    ];
    let mut code = None;
    for (path, body) in requests {
        let response = fixture
            .author
            .call(&fixture.router, Method::POST, &path, Some(body))
            .await?;
        ensure!(response.0 == expected, "{path}: {response:?}");
        if let Some(code) = &code {
            ensure!(
                &response.1 == code,
                "inconsistent script rejection: {response:?}"
            );
        }
        code = Some(response.1);
    }
    Ok(())
}

async fn script_resource(
    fixture: &mut Fixture,
    definition: &Value,
    length: u64,
    digest: [u8; 32],
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let author = &mut fixture.author;
    let router = &fixture.router;
    resource(
        author,
        router,
        id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    resource(author, router, id, 1, json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"prepared-script","length":length,"sha256":digest},"definition":definition}}]})).await?;
    resource(
        author,
        router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    Ok(id)
}

fn script_effects() -> Result<String> {
    pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm.collection_definitions WHERE tenant_id='{tenant}'))",
        tenant = case_tenant()
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn script_preparation_is_shared_without_preview_effects() -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut fixture = Fixture::new().await?;
    fixture.router = fixture.router.clone().merge(fixture.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(
                fixture.queries.clone(),
                None,
            ),
        ),
    )?);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let _server =
        crate::test_support::software::HttpServer::start(listener, fixture.router.clone());
    fixture.author.network = Some((
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()?,
        format!("http://{address}"),
    ));
    fixture.register().await?;
    claim_request(&fixture.router, Uuid::new_v4()).await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let (id, _, declaration) = fixture.resource().await?;
    let before = script_effects()?;
    let definition = policy_definition(id, case_task_scope());
    let preview = post(
        &mut fixture.author,
        &fixture.router,
        "/api/v1/policies/previews",
        json!({"definition":definition}),
    )
    .await?;
    ensure!(preview["items"][0]["eligibility"]["state"] == "eligible");
    let mut invalid = definition.clone();
    invalid["action"]["parameters"] = json!({"unexpected":true});
    reject_script_at_all_entrances(&mut fixture, invalid, StatusCode::BAD_REQUEST).await?;
    // Unique bytes isolate the missing/corrupt content checks from other T2 cases.
    let bytes = format!("#!/bin/sh\n# {}\nprintf '{{}}'\n", Uuid::new_v4());
    let digest: [u8; 32] = Sha256::digest(bytes.as_bytes()).into();
    let content_id =
        script_resource(&mut fixture, &declaration, bytes.len() as u64, digest).await?;
    let content_definition = policy_definition(content_id, case_task_scope());
    reject_script_at_all_entrances(
        &mut fixture,
        content_definition.clone(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    ensure!(
        upload(
            &fixture.author,
            &fixture.router,
            content_id,
            bytes.as_bytes()
        )
        .await?
            == StatusCode::CREATED
    );
    let newer=format!("#!/bin/sh\n# new {}\nprintf 'new'\n",Uuid::new_v4());
    let newer_digest:[u8;32]=Sha256::digest(newer.as_bytes()).into();
    resource(&mut fixture.author,&fixture.router,content_id,3,json!({"action":"version","version":"v2","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"new-script","length":newer.len(),"sha256":newer_digest},"definition":declaration}}]})).await?;
    let cookie=fixture.author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    let request=Request::builder().method(Method::POST).uri(format!("/api/v1/resources/{content_id}/content?version=v2&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4())).header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",fixture.author.csrf.as_ref().unwrap()).header("cookie",&cookie).body(Body::from(newer.clone()))?;
    ensure!(fixture.router.clone().oneshot(request).await?.status()==StatusCode::CREATED);
    resource(&mut fixture.author,&fixture.router,content_id,4,json!({"action":"activate","version":"v2"})).await?;
    let download=format!("/api/v1/resources/{content_id}/versions/v1/script?platform=macos&architecture=aarch64&variant=default");
    let cookie=fixture.author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    for (range,expected_status,expected) in [(None,StatusCode::OK,bytes.as_bytes()),(Some("bytes=0-8"),StatusCode::PARTIAL_CONTENT,&bytes.as_bytes()[..9])] {
        let mut request=Request::builder().uri(&download).header("host","mdm.example.test").header("cookie",&cookie);
        if let Some(range)=range {request=request.header("range",range);}
        let response=fixture.router.clone().oneshot(request.body(Body::empty())?).await?;
        ensure!(response.status()==expected_status,"script download: {}",response.status());
        ensure!(response.headers()["cache-control"]=="no-store");
        ensure!(response.headers().contains_key("content-disposition"));
        ensure!(axum::body::to_bytes(response.into_body(),16777216).await?.as_ref()==expected);
    }
    let denied=fixture.router.clone().oneshot(Request::builder().uri(&download).header("host","mdm.example.test").body(Body::empty())?).await?;
    ensure!(denied.status()==StatusCode::UNAUTHORIZED);
    // The old-version download proof is complete; restore the original active input
    // before testing the independent corruption rejection at Policy entrances.
    resource(&mut fixture.author,&fixture.router,content_id,5,json!({"action":"activate","version":"v1"})).await?;
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let path = std::path::Path::new(fixture.base["content"]["storage"]["directory"].as_str().unwrap())
        .join(case_tenant())
        .join(crate::test_support::process::pg(&format!("SELECT document->'value'->'pieces'->0->'coordinate'->>'id' FROM mdm_content.manifests WHERE tenant_id='{}' AND class='artifact' AND encode(sha256,'hex')='{}'",case_tenant(),hex))?.trim());
    std::fs::write(&path, "x".repeat(bytes.len()))?;
    let rejected = reject_script_at_all_entrances(
        &mut fixture,
        content_definition,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let corrupt=fixture.router.clone().oneshot(Request::builder().uri(&download).header("host","mdm.example.test").header("cookie",&cookie).body(Body::empty())?).await?;
    ensure!(corrupt.status()==StatusCode::SERVICE_UNAVAILABLE,"corrupt script download: {}",corrupt.status());
    std::fs::write(&path, &bytes)?;
    rejected?;
    ensure!(
        script_effects()? == before,
        "preview or rejected script wrote execution facts"
    );
    let mut without_signing = fixture.base.clone();
    without_signing["task_signing"] = serde_json::Value::Null;
    let mut unsigned = Fixture::from_config(without_signing).await?;
    unsigned.router = unsigned.router.clone().merge(unsigned.authority.protect(rss_mdm_http_contract::Router::new().nest("/api/v1", rss_mdm_management_http::planning::policies::http::previews(unsigned.queries.clone(), None)))?);
    let resources = std::mem::take(&mut unsigned.resources);
    resources.finish(async {
    reject_script_at_all_entrances(&mut unsigned, definition.clone(), StatusCode::CONFLICT).await?;
    ensure!(
        script_effects()? == before,
        "unsigned draft or publication wrote execution facts"
    );
    Ok(())
    }).await
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn registered_script_eligibility_gates_preview_and_automatic() -> Result<()> {
    use crate::test_support::software_execution::{Platform, context};
    let mut f = Fixture::new().await?;
    f.router = f.router.clone().merge(f.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(f.queries.clone(), None),
        ),
    )?);
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    f.register().await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.resource().await?;
    let definition = policy_definition(resource, case_task_scope());
    let policy = publish(&mut f.author, &f.router, resource).await?;
    let stack = crate::test_support::software_execution::worker(&f.base, f.execution.clone()).await?;
    for (platform, architecture, profiles, state) in [
        ("macos", "aarch64", None, "channel_unknown"),
        (
            "macos",
            "aarch64",
            Some(json!(["bash"])),
            "unsupported_capability",
        ),
        (
            "macos",
            "x86_64",
            Some(json!(["posix_sh"])),
            "unsupported_capability",
        ),
        (
            "windows",
            "aarch64",
            Some(json!(["posix_sh"])),
            "unsupported_capability",
        ),
    ] {
        let execution_context = context(if platform == "windows" {
            Platform::Windows
        } else {
            Platform::MacOs
        });
        let profile_sql = profiles
            .as_ref()
            .map(|p| format!("'{}'::jsonb", json!({"profiles":p,"environment":{"osVersion":"14.0.0.0","build":0,"edition":null,"tools":{}}})))
            .unwrap_or_else(|| "NULL".into());
        pg(&format!(
            "UPDATE mdm_agent.bindings SET platform='{platform}',architecture='{architecture}',execution_context='{execution_context}'::jsonb WHERE tenant_id='{tenant}'; UPDATE mdm_commands.action_polls SET profiles={profile_sql} WHERE tenant_id='{tenant}'",
            tenant = case_tenant()
        ))?;
        // Publication and valid content stay unchanged; only registration facts differ.
        let before = script_effects()?;
        let preview = post(
            &mut f.author,
            &f.router,
            "/api/v1/policies/previews",
            json!({"definition":definition}),
        )
        .await?;
        ensure!(preview["items"][0]["eligibility"]["state"] == "eligible");
        ensure!(
            preview["items"][0]["taskAdmission"]["state"] == state,
            "{platform}/{architecture}/{profiles:?}: {preview}"
        );
        ensure!(script_effects()? == before, "preview wrote execution facts");
        // A real check-in announces its current profiles; the absent-profile case
        // announces a mismatched profile, so it still cannot admit an automatic Run.
        let announced = profiles.unwrap_or_else(|| json!(["bash"]));
        let poll=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(json!({"wireVersion":1,"executionContext":execution_context,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":announced,"operationId":Uuid::new_v4()}))).await?;
        ensure!(
            poll.0 == StatusCode::OK && poll.1["task"].is_null(),
            "ineligible check-in: {poll:?}"
        );
        ensure!(
            run_count(policy)?.trim() == "0",
            "ineligible automatic Run was persisted"
        );
    }
    let execution_context = context(Platform::MacOs);
    pg(&format!(
        "UPDATE mdm_agent.bindings SET platform='macos',architecture='aarch64',execution_context='{execution_context}'::jsonb WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    let task = claim(&f.router).await?;
    ensure!(run_count(policy)?.trim() == "1");
    complete(&f.router, &task).await?;
    let before = script_effects()?;
    let preview = post(
        &mut f.author,
        &f.router,
        "/api/v1/policies/previews",
        json!({"definition":definition}),
    )
    .await?;
    ensure!(preview["items"][0]["taskAdmission"]["state"] == "eligible");
    ensure!(script_effects()? == before);
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn management_accepts_large_legal_policy_parameters() -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut fixture = Fixture::new().await?;
    fixture.router = fixture.router.clone().merge(fixture.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::planning::policies::http::previews(
                fixture.queries.clone(),
                None,
            ),
        ),
    )?);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture
        .scope(
            case_task_scope(),
            json!([]),
        )
        .await?;
    let id = Uuid::new_v4();
    let bytes = b"#!/bin/sh\nexit 0\n";
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    resource(
        &mut fixture.author,
        &fixture.router,
        id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    let definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8", "parameters":{"type":"object","properties":{"text":{"type":"string","maxLength":65536}},"required":["text"],"additionalProperties":false},"bindings":{"text":{"kind":"environment","name":"RSS_PARAM_TEXT"}},"output":{"type":"object","properties":{},"additionalProperties":false},"purpose":{"kind":"action"},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
    resource(&mut fixture.author, &fixture.router, id, 1, json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"large-policy-script","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(upload(&fixture.author, &fixture.router, id, bytes).await? == StatusCode::CREATED);
    resource(
        &mut fixture.author,
        &fixture.router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let mut definition = policy_definition(id, case_task_scope());
    definition["action"]["parameters"] =
        json!({"text":{"kind":"fixed","value":"x".repeat(20 * 1024)}});
    let parsed: rss_mdm_policy::Definition = serde_json::from_value(definition.clone())?;
    parsed.validate()?;
    let policy = Uuid::new_v4();
    let path = format!("/api/v1/policies/{policy}");
    let body = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}});
    ensure!(serde_json::to_vec(&body)?.len() > 16384);
    let receipt = post(&mut fixture.author, &fixture.router, &path, body.clone()).await?;
    ensure!(receipt["revision"] == 1);
    ensure!(post(&mut fixture.author, &fixture.router, &path, body).await? == receipt);
    let (status, read) = fixture
        .author
        .call(&fixture.router, Method::GET, &path, None)
        .await?;
    ensure!(
        status == StatusCode::OK
            && read["definition"]["action"]["parameters"]["text"]["value"] == "x".repeat(20 * 1024),
        "policy read omitted authored parameters: {read}"
    );
    let (status, rejected) = fixture
        .author
        .call(
            &fixture.router,
            Method::POST,
            &path,
            Some(json!("wrong DTO")),
        )
        .await?;
    ensure!(status == StatusCode::BAD_REQUEST && rejected["code"] == "malformed_request");
    Ok(())
    }).await
}
