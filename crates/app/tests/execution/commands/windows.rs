use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_audit_integration::RequestAudit;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn console_mixed_kind_cursor_and_device_visibility() -> anyhow::Result<()> {
    use crate::test_support::query_reads::QueryReadCounts;
    use crate::test_support::{agent_execution as agent, identity};
    use std::sync::atomic::Ordering::Relaxed;
    use tracing_subscriber::layer::SubscriberExt;
    // Provider work runs in owned runtime tasks, so a future-local subscriber
    // cannot see it. T2 executes this case in its own nextest process.
    let measured = QueryReadCounts::new("execution.");
    let unselected_runs = QueryReadCounts::new("execution.runs");
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(measured.clone())
            .with(unselected_runs.clone()),
    )?;

    let base: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let mut fixture = agent::Fixture::from_config(base).await?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        &fixture.author_id,
        fixture.grants.clone(),
    )
    .await?;
    fixture.register().await?;
    let (resource, _, _) = fixture.resource().await?;
    fixture
        .scope(
            agent::case_task_scope(),
            json!([{"kind":"device","id":agent::case_device_id()}]),
        )
        .await?;
    let policy = agent::seed_script_policy(&fixture, resource).await?;
    let id = agent::seed_script_run(&fixture, policy).await?;
    agent::seed_script_result(
        &fixture,
        id,
        json!({"version":"1.2","healthy":true}),
        "retained result",
    )
    .await?;
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    // IDs belong to their original owners; equal IDs must not lose either kind.
    client.operation = id;
    let grants = crate::test_support::identity::device_grants(
        None,
        &["device_control", "operation_read", "operation_cancel"],
    )?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    client
        .execution_runtime
        .local_tx_with_context(
            client.tenant,
            crate::identity::deadline(),
            (&client.execution, &proof),
            |(service, proof), tx| {
                Box::pin(async move {
                    service
                        .seed_published_restart_in(tx, proof, case_device(), id)
                        .await
                        .map_err(|e| {
                            rss_transactional_messaging_postgres::PgError::from(
                                sqlx::Error::Protocol(e.to_string()),
                            )
                        })
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let mut grants = fixture.grants.clone();
    grants.extend(identity::device_grants(None, &["operation_read"])?);
    identity::seed_grants(case_tenant(), &fixture.author_id, grants).await?;
    for descending in [false, true] {
        let sort = if descending { "-id,-kind" } else { "id,kind" };
        let mut path = format!("/api/v1/operations?limit=1&sort={sort}");
        let mut kinds = Vec::new();
        loop {
            let (status, page) = fixture
                .author
                .call(&fixture.router, Method::GET, &path, None)
                .await?;
            ensure!(status == StatusCode::OK, "mixed directory: {status} {page}");
            let (_, statistics) = fixture
                .author
                .call(
                    &fixture.router,
                    Method::GET,
                    "/api/v1/operations/statistics",
                    None,
                )
                .await?;
            ensure!(
                statistics["statistics"]["total"] == 2
                    && statistics["statistics"]["commands"] == 1
                    && statistics["statistics"]["actionRuns"] == 1,
                "mixed statistics: {page}"
            );
            let item = &page["items"][0];
            ensure!(item["id"] == id.to_string(), "mixed ID: {item}");
            let kind = item["kind"].as_str().unwrap();
            kinds.push(kind.to_owned());
            if kind == "command" {
                ensure!(
                    item["evidence"]["commandStatus"] == "published"
                        && item["evidence"]["observation"]["effect"] == "waiting",
                    "receipt became effect: {item}"
                );
                ensure!(item["evidence"]["observation"].get("value").is_none());
                ensure!(
                    item["detailUrl"]
                        == format!("/api/v1/devices/{}/operations/{id}", case_device())
                );
            } else {
                ensure!(item["evidence"]["result"].get("output").is_none());
                ensure!(
                    item["evidence"]["result"]["diagnostics"]
                        .get("stdout")
                        .is_none()
                );
            }
            let detail_path = item["detailUrl"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing execution detail URL"))?;
            let detail = fixture
                .author
                .call(&fixture.router, Method::GET, detail_path, None)
                .await?;
            ensure!(
                detail.0 == StatusCode::OK,
                "unusable execution detail URL {detail_path}: {:?}",
                detail
            );
            let Some(cursor) = page["nextCursor"].as_str() else {
                break;
            };
            path = format!("/api/v1/operations?limit=1&sort={sort}&cursor={cursor}");
            ensure!(kinds.len() <= 2, "cursor repeated: {kinds:?}");
        }
        let expected = if descending {
            vec!["command", "action_run"]
        } else {
            vec!["action_run", "command"]
        };
        ensure!(kinds == expected, "mixed cursor lost an owner: {kinds:?}");
    }
    // The derived filter scans beyond a complete candidate batch, but returns only
    // the matching command. These terminal run facts need no device execution.
    crate::test_support::process::pg(&format!(
        "INSERT INTO mdm_commands.action_runs SELECT (jsonb_populate_record(NULL::mdm_commands.action_runs,to_jsonb(r)||jsonb_build_object('id',lpad(to_hex(n),32,'0')::uuid,'occurrence','authorization-scan-'||n::text,'result',NULL))).* FROM mdm_commands.action_runs r CROSS JOIN generate_series(1,1001) n WHERE r.tenant_id=current_setting('rss.tenant_id')::uuid AND r.id='{id}'"
    ))?;
    for filter in [
        "authorization.state==authorized",
        "authorization.state==authorized;reauthorization.state==unavailable",
    ] {
        let before = crate::test_support::process::pg(
            "SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=current_setting('rss.tenant_id')::uuid",
        )?;
        let path = format!(
            "/api/v1/operations?filter={filter}&fields=id,kind,authorization,reauthorization&limit=1"
        );
        let (status, page) = fixture
            .author
            .call(&fixture.router, Method::GET, &path, None)
            .await?;
        ensure!(
            status == StatusCode::OK
                && page["items"].as_array().is_some_and(|v| v.len() == 1)
                && page["items"][0]["id"] == id.to_string()
                && page["items"][0]["kind"] == "command"
                && page["nextCursor"].is_null(),
            "sparse authorization page: {status} {page}"
        );
        ensure!(
            page["items"][0]["reauthorization"]["reason"] == "permission_denied",
            "read permission became control permission: {page}"
        );
        let (status, stats) = fixture
            .author
            .call(
                &fixture.router,
                Method::GET,
                &format!("/api/v1/operations/statistics?filter={filter}"),
                None,
            )
            .await?;
        ensure!(
            status == StatusCode::OK
                && stats["statistics"]["total"] == 1
                && stats["statistics"]["commands"] == 1,
            "authorization totals: {stats}"
        );
        ensure!(
            before
                == crate::test_support::process::pg(
                    "SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=current_setting('rss.tenant_id')::uuid"
                )?,
            "read changed business revision"
        );
    }
    let last = Uuid::from_u128(1001);
    for sort in ["id,kind", "-id,-kind"] {
        let filter = format!("(id=={id};authorization.state==authorized),id=={last}");
        let mut path = format!(
            "/api/v1/operations?filter={filter}&fields=id,kind,authorization&limit=1&sort={sort}"
        );
        let mut found = Vec::new();
        loop {
            let (status, page) = fixture
                .author
                .call(&fixture.router, Method::GET, &path, None)
                .await?;
            ensure!(
                status == StatusCode::OK,
                "derived mixed OR: {status} {page}"
            );
            for item in page["items"].as_array().unwrap() {
                found.push((
                    item["id"].as_str().unwrap().to_owned(),
                    item["kind"].as_str().unwrap().to_owned(),
                ));
            }
            let Some(cursor) = page["nextCursor"].as_str() else {
                break;
            };
            path = format!(
                "/api/v1/operations?filter={filter}&fields=id,kind,authorization&limit=1&sort={sort}&cursor={cursor}"
            );
            ensure!(found.len() < 3, "derived cursor repeated");
        }
        let mut expected = vec![
            (last.to_string(), "action_run".to_owned()),
            (id.to_string(), "command".to_owned()),
        ];
        if sort.starts_with('-') {
            expected.reverse()
        }
        ensure!(
            found == expected,
            "mixed OR lost or repeated an owner: {found:?}"
        );
    }
    crate::test_support::process::pg(
        "DELETE FROM mdm_commands.action_runs WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND occurrence LIKE 'authorization-scan-%'",
    )?;
    let (status, page) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations?limit=1&fields=id,kind,authorization",
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK, "authority cursor seed: {page}");
    let token = page["nextCursor"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("authority continuation"))?;
    crate::test_support::process::pg(
        "UPDATE mdm_commands.capabilities SET observed_at=observed_at+1 WHERE tenant_id=current_setting('rss.tenant_id')::uuid",
    )?;
    let stale = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v1/operations?limit=1&fields=id,kind,authorization&cursor={token}"),
            None,
        )
        .await?;
    ensure!(
        stale.0 == StatusCode::CONFLICT,
        "capability change retained authorization cursor: {stale:?}"
    );
    // An unrelated protected input larger than the entire hydration budget must
    // never be transferred or decrypted when selecting another command.
    let revision_sql = "SELECT coalesce((SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=current_setting('rss.tenant_id')::uuid),0)";
    let before = crate::test_support::process::pg(revision_sql)?;
    let rejected = Uuid::new_v4();
    client
        .execution
        .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(client.call(Method::POST,"",Some(json!({"operationId":rejected,"action":{"kind":"restart"},"deadline":client.clock.unix_seconds()?+300}))).await?.0==StatusCode::SERVICE_UNAVAILABLE);
    ensure!(
        crate::test_support::process::pg(revision_sql)? == before,
        "rolled-back command advanced query generation"
    );
    ensure!(
        crate::test_support::process::pg(&format!(
            "SELECT count(*) FROM rss_device_command.commands WHERE command_id='{rejected}'"
        ))?
        .trim()
            == "0",
        "command rollback leaked state"
    );
    let large = Uuid::new_v4();
    ensure!(client.call(Method::POST, "", Some(json!({"operationId":large,"action":{"kind":"restart"},"deadline":client.clock.unix_seconds()?+300}))).await?.0 == StatusCode::ACCEPTED);
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_commands.operations SET request=convert_to(repeat('x',20000000),'UTF8') WHERE id='{large}'"
    ))?;
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_commands.action_runs SET result=jsonb_set(result,'{{output}}',jsonb_build_object('canary',repeat('off-page-',100000))) WHERE id='{id}'"
    ))?;
    measured.reset();
    unselected_runs.reset();
    let selected = format!("/api/v1/operations?limit=1&filter=id=={id}&sort=-id,-kind");
    let response = fixture
        .author
        .call(&fixture.router, Method::GET, &selected, None)
        .await?;
    ensure!(
        response.0 == StatusCode::OK,
        "bounded selected evidence: {response:?}"
    );
    ensure!(measured.calls.load(Relaxed) <= 5 && measured.rows.load(Relaxed) <= 16);
    ensure!(
        unselected_runs.calls.load(Relaxed) == 0,
        "off-page action run evidence reached hydration"
    );
    ensure!(
        measured.bytes.load(Relaxed) > 0 && measured.bytes.load(Relaxed) < 65536,
        "provider read budget: calls={} rows={} bytes={}",
        measured.calls.load(Relaxed),
        measured.rows.load(Relaxed),
        measured.bytes.load(Relaxed)
    );
    println!(
        "QUERY-05 execution calls={} rows={} payload_bytes={}",
        measured.calls.load(Relaxed),
        measured.rows.load(Relaxed),
        measured.bytes.load(Relaxed)
    );
    let cursor = response.1["nextCursor"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mixed continuation"))?;
    let continuation = format!("{selected}&cursor={cursor}");
    let audit = RequestAudit::new(
        case_tenant().into(),
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    client.execution.recover_operation(id, &audit).await?;
    audit.finalize(None);
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::GET, &continuation, None)
            .await?
            .0
            == StatusCode::OK,
        "no-op recovery invalidated a cursor"
    );
    measured.reset();
    let response = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations?filter=kind==command&fields=id,kind&limit=100",
            None,
        )
        .await?;
    ensure!(
        response.0 == StatusCode::OK,
        "metadata projection read protected payload: {response:?}"
    );
    ensure!(
        measured.calls.load(Relaxed) == 0,
        "unrequested evidence reached a provider read"
    );
    println!(
        "QUERY-05 execution metadata-only provider_calls={}",
        measured.calls.load(Relaxed)
    );
    let oversized = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v1/operations?filter=id=={large}"),
            None,
        )
        .await?;
    ensure!(
        oversized.0 == StatusCode::SERVICE_UNAVAILABLE,
        "budget overflow became conflict: {oversized:?}"
    );
    identity::change_grants(case_tenant(), &fixture.author_id, fixture.grants.clone()).await?;
    let (status, page) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations?limit=1",
            None,
        )
        .await?;
    let (_, statistics) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations/statistics",
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK
            && statistics["statistics"]["total"] == 1
            && statistics["statistics"]["commands"] == 0
            && page["items"][0]["kind"] == "action_run"
            && page["nextCursor"].is_null(),
        "hidden command affected count or cursor: {page}"
    );
    let hidden = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v1/operations?filter=device=={}", case_device()),
            None,
        )
        .await?;
    ensure!(hidden.0 == StatusCode::OK && hidden.1["items"] == json!([]));
    host.resources.finish(async { Ok(()) }).await?;
    fixture.resources.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn authorization_directory_registration_and_terminal_reasons() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    client.accept_authorized().await?;
    let id = client.operation;
    let read = client.call(Method::GET, &format!("/{id}"), None).await?;
    ensure!(
        read.0 == StatusCode::OK
            && read.1["authorization"]["state"] == "authorized"
            && read.1["reauthorization"]["state"] == "available",
        "current control: {read:?}"
    );
    // Retiring the endpoint cannot retarget this sealed command to another registration.
    let registration=crate::test_support::process::pg(&format!("SELECT registration FROM mdm_commands.operations WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND id='{id}'"))?.trim().to_owned();
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND id='{registration}'"
    ))?;
    let blocked = client.call(Method::GET, &format!("/{id}"), None).await?;
    ensure!(
        blocked.0 == StatusCode::OK
            && blocked.1["authorization"]["reason"] == "registration_changed"
            && blocked.1["reauthorization"]["reason"] == "registration_changed",
        "retired control: {blocked:?}"
    );
    let filter = "authorization.state==blocked;authorization.reason==registration_changed";
    let (status, page) = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!(
                "/api/v1/operations?filter={filter}&fields=id,kind,authorization,reauthorization"
            ),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK
            && page["items"].as_array().is_some_and(|v| v.len() == 1)
            && page["items"][0]["id"] == id.to_string(),
        "blocked directory: {status} {page}"
    );
    let (status, stats) = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/operations/statistics?filter={filter}"),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK && stats["statistics"]["total"] == 1,
        "blocked statistics: {stats}"
    );
    let denied = client
        .call(
            Method::POST,
            &format!("/{id}/reauthorize"),
            Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":blocked.1["revision"]})),
        )
        .await?;
    ensure!(
        denied.0 == StatusCode::CONFLICT,
        "retired registration authorized: {denied:?}"
    );
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_access.registrations SET state='active' WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND id='{registration}'"
    ))?;
    let cancelled = client
        .call(
            Method::POST,
            &format!("/{id}/cancel"),
            Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":read.1["revision"]})),
        )
        .await?;
    ensure!(cancelled.0 == StatusCode::OK, "cancel: {cancelled:?}");
    let terminal = client.call(Method::GET, &format!("/{id}"), None).await?;
    ensure!(
        terminal.0 == StatusCode::OK && terminal.1["reauthorization"]["reason"] == "terminal",
        "terminal: {terminal:?}"
    );
    host.resources.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn authorization_cursor_expires_without_command_mutation() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    client.set_authorized(true).await?;
    let deadline = client.clock.unix_seconds()? + 8;
    for id in [client.operation, Uuid::new_v4()] {
        let accepted = client
            .call(
                Method::POST,
                "",
                Some(json!({"operationId":id,"action":{"kind":"restart"},"deadline":deadline})),
            )
            .await?;
        ensure!(accepted.0 == StatusCode::ACCEPTED, "accept: {accepted:?}");
    }
    let path = "/api/v1/operations?filter=reauthorization.state==available&fields=id,kind,reauthorization&limit=1";
    let page = client
        .browser
        .call(&client.router, Method::GET, path, None)
        .await?;
    ensure!(page.0 == StatusCode::OK, "page: {page:?}");
    let cursor = page.1["nextCursor"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing cursor: {:?}", page.1))?;
    let seconds = deadline.saturating_sub(client.clock.unix_seconds()?).max(0) + 1;
    tokio::time::sleep(std::time::Duration::from_secs(seconds as u64)).await;
    let stale = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("{path}&cursor={cursor}"),
            None,
        )
        .await?;
    ensure!(stale.0 == StatusCode::CONFLICT, "expired cursor: {stale:?}");
    let stats = client
        .browser
        .call(
            &client.router,
            Method::GET,
            "/api/v1/operations/statistics?filter=reauthorization.state==available",
            None,
        )
        .await?;
    ensure!(
        stats.0 == StatusCode::OK && stats.1["statistics"]["total"] == 0,
        "expired statistics: {stats:?}"
    );
    let detail = client
        .call(Method::GET, &format!("/{}", client.operation), None)
        .await?;
    ensure!(
        detail.0 == StatusCode::OK && detail.1["reauthorization"]["reason"] == "expired",
        "expired detail: {detail:?}"
    );
    host.resources.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn unrelated_scope_history_does_not_bound_command_reads() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    client.accept_authorized().await?;
    use sqlx::Connection;
    let run = Uuid::new_v4();
    let scope = Uuid::new_v4();
    crate::test_support::process::pg(&format!(
        "INSERT INTO mdm_scope.scopes(tenant_id,id,revision,deleted) VALUES(current_setting('rss.tenant_id')::uuid,'{scope}',1,true); INSERT INTO mdm_scope.scope_runs(tenant_id,id,scope,definition_revision,asset_watermark,input,fingerprint,phase) VALUES(current_setting('rss.tenant_id')::uuid,'{run}','{scope}',1,0,'{{}}',decode(repeat('00',32),'hex'),'project'); INSERT INTO mdm_commands.scope_projection_runs(tenant_id,id,scope,next_entry,phase) VALUES(current_setting('rss.tenant_id')::uuid,'{run}','{scope}',1,'sources')"
    ))?;
    let mut db =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut db)
        .await?;
    // Materialize immutable history as production-sized commits; each batch retains all owner triggers.
    for start in (1..=350_000i64).step_by(1000) {
        sqlx::query("INSERT INTO mdm_commands.scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) SELECT $1::uuid,$2,'mdm','historical-'||n,false,false,'{}',0 FROM generate_series($3::bigint,$4::bigint) n")
            .bind(case_tenant()).bind(run).bind(start).bind(start+999).execute(&mut db).await?;
    }
    sqlx::query(
        "UPDATE mdm_scope.scope_runs SET phase='superseded' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(run)
    .execute(&mut db)
    .await?;
    db.close().await?;
    let detail = client
        .call(Method::GET, &format!("/{}", client.operation), None)
        .await?;
    ensure!(
        detail.0 == StatusCode::OK && detail.1["authorization"]["state"] == "authorized",
        "history bounded detail: {detail:?}"
    );
    for path in [
        "/api/v1/operations?filter=authorization.state==authorized&fields=id,authorization&limit=1",
        "/api/v1/operations/statistics?filter=authorization.state==authorized",
    ] {
        let response = client
            .browser
            .call(&client.router, Method::GET, path, None)
            .await?;
        ensure!(
            response.0 == StatusCode::OK,
            "history bounded {path}: {response:?}"
        );
    }
    host.resources.finish(async { Ok(()) }).await?;
    Ok(())
}
