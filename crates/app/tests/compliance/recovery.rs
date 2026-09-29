use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.recovery: real HTTP and durable worker contract"]
async fn mutation_unknown_commit_recovers_original_response() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    let plan_runtime = &fixture.plan_runtime;
    let id = Uuid::new_v4();
    let path = format!("/api/v2/compliance-rules/{id}");
    let body = request(0, definition(json!({"kind":"all"})));
    plan_runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    let (s, _) = browser
        .call(router, Method::PUT, &path, Some(body.clone()))
        .await?;
    ensure!(
        s == StatusCode::SERVICE_UNAVAILABLE,
        "lost commit ACK must remain unknown"
    );
    let written = ok(&mut browser, router, Method::PUT, &path, Some(body.clone())).await?;
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
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    pg(&format!(
        "INSERT INTO mdm_access.devices SELECT '{TENANT}', 'page-'||lpad(n::text,2,'0') FROM generate_series(1,33) n",
        TENANT = case_tenant()
    ))?;
    let (_, path, _) = fixture.rule().await?;
    assign(&mut browser, router, "compliance-a", 0, true).await?;
    let automation = start_automation(base).await?;
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    // Publication and its terminal audit must roll back together, including the final page.
    pg(
        "CREATE SEQUENCE public.compliance_publish_attempts; GRANT USAGE ON SEQUENCE public.compliance_publish_attempts TO mdm_flow_runtime; CREATE FUNCTION public.reject_compliance_publish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.compliance_publish_attempts'); RAISE EXCEPTION 'publication fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_compliance_publish AFTER UPDATE ON mdm_compliance.rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.current_run IS DISTINCT FROM OLD.current_run) EXECUTE FUNCTION public.reject_compliance_publish()",
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
        )? == 1
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
    .await??;
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
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_completed")? == 0
    );
    pg(
        "DROP TRIGGER reject_compliance_publish ON mdm_compliance.rules; DROP FUNCTION public.reject_compliance_publish(); DROP SEQUENCE public.compliance_publish_attempts",
    )?;
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    ensure!(
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_completed")? == 1
    );
    crate::test_support::stop_worker(automation).await?;
    fixture.close().await;
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
    crate::test_support::stop_worker(restarted).await?;
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
    crate::test_support::stop_worker(restarted).await?;
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
        audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(op.as_str()))? == 0
    );
    fixture.close().await;
    Ok(())
}
