use super::*;
use crate::audit_test_support::audit_count;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.recovery: real HTTP and durable worker contract"]
async fn mutation_unknown_commit_recovers_original_response() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    let inventory_runtime = &fixture.inventory_runtime;
    let id = Uuid::new_v4();
    let path = format!("/api/v1/compliance-rules/{id}");
    let body = request(0, definition(json!({"kind":"all"})));
    inventory_runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    let (s, _) = browser
        .call(router, Method::PUT, &path, Some(body.clone()))
        .await?;
    ensure!(
        s == StatusCode::SERVICE_UNAVAILABLE,
        "lost commit ACK must remain unknown"
    );
    let persisted: Value = serde_json::from_str(&pg(&format!(
        "SELECT response FROM mdm_compliance.operations WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        body["operationId"].as_str().unwrap()
    ))?)?;
    ensure!(persisted["task"].as_str().is_some());
    let written = ok(&mut browser, router, Method::PUT, &path, Some(body.clone())).await?;
    ensure!(
        written == persisted,
        "recovery must replay the original receipt"
    );
    ensure!(
        ok(&mut browser, router, Method::PUT, &path, Some(body)).await? == written,
        "operation replay changed response"
    );
    fixture.close().await;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.recovery: real HTTP and durable worker contract"]
async fn publication_terminal_page_and_audit_are_atomic() -> Result<()> {
    let mut fixture = Fixture::open().await?;
    let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    fixture.resources.resource(SourceResource(runtime.clone()));
    let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
        rss_transactional_messaging::fence::StorageIdentity::new(
            config.storage_binding.target,
            config.storage_binding.lineage,
        )?,
        vec![(
            tenant,
            rss_transactional_messaging::fence::Epoch::new(config.storage_binding.epoch)?,
        )],
    )?;
    let protection = config.native_protector()?;
    let webhooks = crate::webhooks::Backend::open(
        config.webhooks,
        runtime,
        tenant,
        fixture.audit.clone(),
        Arc::new(crate::clock::SystemClock),
        protection,
        binding,
        rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?,
    )
    .await?;
    fixture
        .resources
        .resource(crate::webhooks::Resource(webhooks.clone()));
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    pg(&format!(
        "INSERT INTO mdm_access.devices SELECT '{TENANT}', 'page-'||lpad(n::text,2,'0') FROM generate_series(1,31) n",
        TENANT = case_tenant()
    ))?;
    let (rule, path, _) = fixture.rule().await?;
    assign(&mut browser, router, "compliance-a", 0, true).await?;
    let automation = start_automation(base).await?;
    status(&mut browser, router, "compliance-a", "non_compliant")
        .await
        .map_err(|e| anyhow::anyhow!("initial compliance publication: {e}"))?;
    let initial = pg(&format!(
        "SELECT current_run FROM mdm_compliance.rules WHERE tenant_id='{}' AND id='{rule}'",
        case_tenant()
    ))?;
    let initial = Uuid::parse_str(initial.trim())?;
    // Publication and its terminal audit must roll back together, including the final page.
    pg(
        "CREATE SEQUENCE public.compliance_publish_attempts; GRANT USAGE ON SEQUENCE public.compliance_publish_attempts TO mdm_inventory_runtime; CREATE FUNCTION public.reject_compliance_publish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.compliance_publish_attempts'); RAISE EXCEPTION 'publication fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_compliance_publish AFTER UPDATE ON mdm_compliance.rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.current_run IS DISTINCT FROM OLD.current_run) EXECUTE FUNCTION public.reject_compliance_publish()",
    )?;
    let recompute = request(1, json!({}));
    let restarted_run = ok(
        &mut browser,
        router,
        Method::POST,
        &format!("{path}/recompute"),
        Some(recompute.clone()),
    )
    .await?;
    ensure!(
        ok(
            &mut browser,
            router,
            Method::POST,
            &format!("{path}/recompute"),
            Some(recompute.clone())
        )
        .await?
            == restarted_run
    );
    ensure!(
        audit_count(
            |r| r.source() == "mdm.business" && r.operation() == recompute["operationId"].as_str()
        )
        .await?
            == 1
    );
    let task = restarted_run["task"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if pg("SELECT is_called FROM public.compliance_publish_attempts")?.trim() == "t" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("deferred publication trigger: {e}"))??;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.results WHERE task='{task}'"
        ))?
        .trim()
            == "32"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.rules WHERE current_run='{task}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_completed")
            .await?
            == 0
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_webhook.compliance_sources WHERE document->>'run'='{task}'"
        ))?
        .trim()
            == "0",
        "failed publication leaked a webhook source"
    );
    pg(
        "DROP TRIGGER reject_compliance_publish ON mdm_compliance.rules; DROP FUNCTION public.reject_compliance_publish(); DROP SEQUENCE public.compliance_publish_attempts",
    )?;
    let completed = task_phase(
        &mut browser,
        router,
        &format!("{path}/tasks/{task}"),
        "published",
    )
    .await
    .map_err(|e| anyhow::anyhow!("publication recovery after trigger removal: {e}"))?;
    ensure!(
        completed["completed"] == true && completed["failure"].is_null(),
        "{completed}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_compliance.rules WHERE tenant_id='{}' AND current_run='{task}'", case_tenant()))?.trim() == "1");
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.results WHERE tenant_id='{}' AND task='{task}'",
            case_tenant()
        ))?
        .trim()
            == "33"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.devices d WHERE d.tenant_id='{}' AND NOT EXISTS(SELECT 1 FROM mdm_compliance.results r WHERE r.tenant_id=d.tenant_id AND r.device=d.id AND r.task='{task}')", case_tenant()))?.trim() == "0");
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    ensure!(
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_completed")
            .await?
            == 1
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.compliance_sources s JOIN rss_transactional_messaging.outbox o ON(o.tenant_id,o.message_id)=(s.tenant_id,s.id::text) WHERE s.document->>'run'='{task}' AND o.domain='mdm-webhook-source'"))?.trim()=="1", "published run must atomically append one webhook source");
    crate::test_support::runtime::stop_worker(automation).await?;
    // Consume actual publication sources with command-runtime ACLs. The first run
    // changes PAGE+1 devices; recomputing identical assessments must emit none.
    let cancellation = tokio_util::sync::CancellationToken::new();
    let mut relay = tokio::spawn(webhooks.clone().work(cancellation.clone()));
    let derived = async {
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                if pg(&format!("SELECT count(*) FROM mdm_webhook.compliance_sources WHERE tenant_id='{}' AND document->>'run' IN('{initial}','{task}') AND complete",case_tenant()))?.trim()=="2" { return Ok::<_,anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.events WHERE tenant_id='{}' AND document->>'eventType'='compliance.status.changed' AND document->'data'->>'runId'='{initial}'",case_tenant()))?.trim()=="33");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.events e JOIN mdm_compliance.results r ON(r.tenant_id,r.device)=(e.tenant_id,e.document->>'deviceId') WHERE e.tenant_id='{}' AND r.task='{initial}' AND e.document->'data'->>'runId'='{initial}' AND e.document->'data'->>'status'=r.document->>'status' AND e.document->'data'->>'reason'=r.document->>'reason'",case_tenant()))?.trim()=="33","derived assessments lost status/reason or paging");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.events WHERE tenant_id='{}' AND document->'data'->>'runId'='{task}'",case_tenant()))?.trim()=="0","unchanged publication emitted changes");
        let config:Config=serde_json::from_value(base.clone())?;
        let hex=|bytes:&[u8]|bytes.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let source=rss_mdm_webhook_service::events::identity(initial,"compliance-publication");
        pg(&format!("SET LOCAL rss.storage_target='{}'; SET LOCAL rss.storage_lineage='{}'; SET LOCAL rss.execution_epoch='{}'; UPDATE rss_transactional_messaging.outbox SET status='pending',lease_token=NULL,lease_until=NULL,retry_after=clock_timestamp() WHERE tenant_id='{}' AND message_id='{source}'",hex(&config.storage_binding.target),hex(&config.storage_binding.lineage),config.storage_binding.epoch,case_tenant()))?;
        tokio::time::timeout(Duration::from_secs(10),async {
            loop {
                if pg(&format!("SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='{source}'",case_tenant()))?.trim()=="published" { return Ok::<_,anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.events WHERE tenant_id='{}' AND document->'data'->>'runId'='{initial}'",case_tenant()))?.trim()=="33","source redelivery duplicated events");
        Ok::<_,anyhow::Error>(())
    }.await;
    cancellation.cancel();
    let stopped = match tokio::time::timeout(Duration::from_secs(20), &mut relay).await {
        Ok(Ok(result)) => result.map_err(anyhow::Error::from),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => {
            relay.abort();
            let _ = relay.await;
            Err(anyhow::anyhow!("webhook relay shutdown timed out"))
        }
    };
    fixture.close().await;
    stopped?;
    derived?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.recovery: real HTTP and durable worker contract"]
async fn rule_and_fact_revisions_fence_stale_publication() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    pg(&format!(
        "INSERT INTO mdm_access.devices SELECT '{TENANT}', 'page-'||lpad(n::text,2,'0') FROM generate_series(1,33) n",
        TENANT = case_tenant()
    ))?;
    let (id, path, _) = fixture.rule().await?;
    assign(&mut browser, router, "compliance-a", 0, true).await?;
    // Rule-only race: unchanged facts cannot allow an older revision to publish.
    let restarted_definition = definition(json!({"kind":"all"}));
    let stale = ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(1, restarted_definition.clone())),
    )
    .await?;
    ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(2, restarted_definition.clone())),
    )
    .await?;
    let restarted = start_automation(base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, router, "compliance-a", "non_compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 3);
    let old_task = stale["task"].as_str().unwrap();
    let old = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/tasks/{old_task}"),
        None,
    )
    .await?;
    ensure!(
        old["completed"] == true && old["failure"] == "superseded",
        "stale run was published: {old}"
    );
    crate::test_support::runtime::stop_worker(restarted).await?;
    // Fact-only race: the rule revision remains unchanged across restart.
    let stale_fact = ok(
        &mut browser,
        router,
        Method::POST,
        &format!("{path}/recompute"),
        Some(request(3, json!({}))),
    )
    .await?;
    assign(&mut browser, router, "compliance-a", 1, false).await?;
    let restarted = start_automation(base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, router, "compliance-a", "compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 3);
    let old = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/tasks/{}", stale_fact["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(old["phase"] == "superseded");
    let current_task = pg(&format!(
        "SELECT current_run FROM mdm_compliance.rules WHERE id='{id}'"
    ))?;
    let progress = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/tasks/{}", current_task.trim()),
        None,
    )
    .await?;
    ensure!(progress["phase"] == "published" && progress["processed"].as_i64().unwrap() > 32);
    crate::test_support::runtime::stop_worker(restarted).await?;
    // A late transaction failure must roll back definition, receipt, enqueue and staged audit.
    pg(
        "CREATE FUNCTION public.reject_compliance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_compliance AFTER UPDATE ON mdm_compliance.rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_compliance()",
    )?;
    let failed = request(3, restarted_definition.clone());
    let op = failed["operationId"].as_str().unwrap().to_owned();
    let (s, _) = browser
        .call(router, Method::PUT, &path, Some(failed))
        .await?;
    pg(
        "DROP TRIGGER reject_compliance ON mdm_compliance.rules; DROP FUNCTION public.reject_compliance()",
    )?;
    ensure!(s == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(ok(&mut browser, router, Method::GET, &path, None).await?["revision"] == 3);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.operations WHERE id='{op}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(op.as_str())).await?
            == 0
    );
    fixture.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.recovery: owner cut windows survive reverse commits and restart"]
async fn late_low_event_reaches_group_scope_compliance_and_device_after_restart() -> Result<()> {
    use sqlx::Connection;
    let fixture = Fixture::open().await?;
    let mut browser = fixture.browser.clone();
    let router = &fixture.router;
    let tenant = case_tenant();
    let (low_registration, _) = crate::test_support::inventory::seed_source(
        "compliance-a",
        "mdm",
        "mdm.windows",
        "late-low",
    )?;
    let (high_registration, _) = crate::test_support::inventory::seed_source(
        "compliance-b",
        "mdm",
        "mdm.windows",
        "early-high",
    )?;
    let mut granted = grants(None)?;
    for operation in [
        crate::authorization::Permission::ScopeRead,
        crate::authorization::Permission::ScopeWrite,
    ] {
        granted.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::seed_grants(tenant, &fixture.subject, granted).await?;
    assign(&mut browser, router, "compliance-a", 0, false).await?;
    assign(&mut browser, router, "compliance-b", 0, false).await?;
    let automation = start_automation(&fixture.base).await?;
    let (rule, _, _) = fixture.rule().await?;
    status(&mut browser, router, "compliance-a", "compliant").await?;
    let group = Uuid::new_v4();
    crate::test_support::planning_http::call(&mut browser,router,&format!("/api/v1/groups/{group}"),0,
        json!({"action":"create","assetContext":"endpoint","presentation":{"name":"late event group"},"criteria":definition(json!({"kind":"all"}))["criteria"]})).await?;
    let scope = Uuid::new_v4();
    crate::test_support::planning_http::call(&mut browser,router,&format!("/api/v1/scopes/{scope}"),0,
        json!({"action":"put","definition":{"targets":[{"kind":"device","id":"compliance-a"}],"limitations":null,"exclusions":[]}})).await?;
    async fn covered(event: i64) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(40),async {
            loop {
                let t=case_tenant();
                let yes=pg(&format!("WITH cuts AS (SELECT from_cut,to_cut FROM mdm_assets.group_dispatch WHERE tenant_id='{t}' UNION ALL SELECT from_cut,to_cut FROM mdm_scope.asset_dispatch WHERE tenant_id='{t}' UNION ALL SELECT from_cut,to_cut FROM mdm_compliance.dispatch WHERE tenant_id='{t}' UNION ALL SELECT from_cut,to_cut FROM mdm_devices.checkpoints WHERE tenant_id='{t}') SELECT count(*)=4 AND bool_and(to_cut IS NULL AND mdm.asset_visible(from_cut,{event})) FROM cuts"))?;
                if yes.trim()=="t" {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await?
    }
    let initial: i64 = pg(&format!(
        "SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id='{tenant}'"
    ))?
    .trim()
    .parse()?;
    covered(initial).await?;
    let mut root =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant)
        .execute(&mut root)
        .await?;
    let mut low = root.begin().await?;
    sqlx::query("UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(&low_registration).execute(&mut *low).await?;
    let low_event: i64 =
        sqlx::query_scalar("SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id=$1::uuid")
            .bind(tenant)
            .fetch_one(&mut *low)
            .await?;
    pg(&format!(
        "UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id='{tenant}' AND registration='{high_registration}'"
    ))?;
    let high_event: i64 = pg(&format!(
        "SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id='{tenant}'"
    ))?
    .trim()
    .parse()?;
    ensure!(low_event < high_event);
    covered(high_event).await?;
    ensure!(pg(&format!("SELECT NOT mdm.asset_visible(from_cut,{low_event}) FROM mdm_assets.group_dispatch WHERE tenant_id='{tenant}'"))?.trim()=="t");
    crate::test_support::runtime::stop_worker(automation).await?;
    low.commit().await?;
    root.close().await?;
    let automation = start_automation(&fixture.base).await?;
    covered(low_event).await?;
    // Each owner must have a real effect, beyond merely advancing an empty checkpoint.
    tokio::time::timeout(Duration::from_secs(40),async {
        loop {
            let effects=pg(&format!("SELECT EXISTS(SELECT FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{tenant}' AND j.target='{group}' AND j.completed AND j.failure IS NULL AND mdm.asset_visible(substring(r.input_version FROM 8)::jsonb,{low_event})) AND EXISTS(SELECT FROM mdm_scope.scope_runs r WHERE r.tenant_id='{tenant}' AND r.scope='{scope}' AND r.phase='published' AND mdm.asset_visible(r.asset_cut,{low_event})) AND EXISTS(SELECT FROM mdm_compliance.runs r WHERE r.tenant_id='{tenant}' AND r.rule_id='{rule}' AND r.completed AND r.failure IS NULL AND mdm.asset_visible(r.input->'assetCut',{low_event})) AND EXISTS(SELECT FROM mdm_devices.object_cuts c WHERE c.tenant_id='{tenant}' AND mdm.asset_visible(c.asset_cut,{low_event}))"))?;
            if effects.trim()=="t" {break;}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    crate::test_support::runtime::stop_worker(automation).await?;
    fixture.close().await;
    Ok(())
}
