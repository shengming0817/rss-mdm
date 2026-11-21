//! Live optional providers on the installed host, through operator and tenant entrances.
use super::*;
#[path = "lifecycle_telemetry_data.rs"]
mod data;
#[path = "lifecycle_telemetry_recovery.rs"]
mod recovery;
use crate::installation::{configure, install, providers::telemetry, runtime_files};

async fn resources(
    root: &Path,
    first: &install::Receipt,
    pg: &crate::config::Database,
    inputs: &Path,
) -> Result<Vec<Value>> {
    let providers: Value =
        serde_json::from_slice(&std::fs::read(inputs.join("telemetry-providers.json"))?)?;
    let base = maintenance::desired(root, first.host_id)?["telemetry"][0].clone();
    let area = std::path::PathBuf::from(
        providers["area"]
            .as_str()
            .context("ClickHouse fixture directory")?,
    );
    let password = root.join("metric-password");
    private(&password, Uuid::new_v4().simple().to_string())?;
    let key = root.join("metric-cursor");
    private(&key, [5u8; 32])?;
    let mut requests = Vec::new();
    for kind in ["click_house", "timescale_shared"] {
        let administrator = if kind == "click_house" {
            let mut admin = pg.clone();
            admin.name = "ch_control".into();
            admin
        } else {
            serde_json::from_value(providers["timescale"].clone())?
        };
        let mut db = administrator.clone();
        db.user = format!("metrics_{kind}");
        db.password_file = password.clone();
        let mut config = base.clone();
        config["connections"] = json!(1);
        config["resource_id"] = json!(Uuid::new_v4());
        let mut ch = Value::Null;
        if kind == "click_house" {
            config.as_object_mut().unwrap().remove("cursor_key_file");
            config["backend"] = json!({"kind":kind,"control":db,"endpoint":providers["endpoint"],"ca_file":providers["ca"],
                "writer":{"user":"metric_writer","password_file":password},"maintenance":{"user":"metric_maint","password_file":password},
                "max_scan_rows":100000,"max_scan_bytes":16777216,"max_memory_bytes":67108864});
            ch = json!({"installer":{"user":"installer","password_file":area.join("installer-password")},"guard":{"user":"ch_guard","password_file":area.join("guard-password")},"backup_directory":area.join("backup"),"server_configuration_files":[area.join("config.d/telemetry.xml"),area.join("users.xml")]});
        } else {
            config["cursor_key_file"] = json!(key);
            config["backend"] = json!({"kind":kind,"database":db,"chunk_micros":86400000000u64});
        }
        let request = json!({"operationId":Uuid::new_v4(),"directory":root.join(kind),"configuration":config,
            "administrator":administrator,"owner":format!("metrics_owner_{kind}"),"partitions":[],"clickhouse":ch});
        telemetry::prepare(serde_json::from_value(request.clone())?)
            .await
            .with_context(|| format!("install {kind}"))?;
        requests.push(request);
    }
    Ok(requests)
}
async fn attach(
    source: &Value,
    resource: &Value,
    tenant: Uuid,
    rev: i64,
    action: Value,
) -> Result<Value> {
    let request = json!({"product":source,"installation":resource,"operationId":Uuid::new_v4(),"tenant":tenant,"expectedRevision":rev,"action":action});
    replay_selection(request, resource, rev).await
}
async fn replay_selection(request: Value, resource: &Value, rev: i64) -> Result<Value> {
    let receipt = serde_json::to_value(
        telemetry::prepare_tenant(serde_json::from_value(request.clone())?).await?,
    )?;
    let replay =
        serde_json::to_value(telemetry::prepare_tenant(serde_json::from_value(request)?).await?)?;
    ensure!(
        receipt == replay
            && receipt["materialRevision"] == rev + 1
            && receipt["installationId"] == resource["configuration"]["resource_id"],
        "selection receipt and replay"
    );
    Ok(receipt)
}
async fn available(browser: &mut Browser, tenant: Uuid, expected: bool) -> Result<()> {
    let (status, value) = browser
        .call(
            Method::GET,
            &format!("/api/v1/tenants/{tenant}/runtime/diagnostics"),
            None,
            None,
        )
        .await?;
    ensure!(status == 200, "runtime diagnostics returned {status}");
    let telemetry = value["components"]
        .as_array()
        .context("diagnostic components")?
        .iter()
        .find(|c| c["name"] == "telemetry")
        .context("mounted telemetry")?;
    let storage = telemetry["dependencies"]
        .as_array()
        .context("telemetry dependencies")?
        .iter()
        .find(|d| d["name"] == "telemetry_storage")
        .context("telemetry backend probe")?;
    ensure!(
        storage["state"] == if expected { "available" } else { "unavailable" },
        "real backend qualification: {storage}"
    );
    Ok(())
}
async fn provision(platform: &mut Browser) -> Result<(Uuid, Browser)> {
    let operation = Uuid::new_v4();
    let (status,value)=platform.call(Method::POST,"/api/v1/tenant-administration/provisionings",Some(json!({"name":format!("Metrics {operation}"),"administratorLogin":"administrator","administratorPassword":"Telemetry-admin-password!42"})),Some(operation)).await?;
    ensure!(
        matches!(status, 200 | 202) || status == 503 && value["code"] == "operation_unknown",
        "provision live tenant: {status}: {value}"
    );
    let receipt = platform.configured(operation).await?;
    let tenant = Uuid::parse_str(
        receipt["result"]["tenantId"]
            .as_str()
            .context("tenant identity")?,
    )?;
    let mut browser = Browser::new(platform.address)?;
    browser
        .login(
            &tenant.to_string(),
            "administrator",
            "Telemetry-admin-password!42",
        )
        .await?;
    Ok((tenant, browser))
}
#[allow(
    clippy::cognitive_complexity,
    reason = "one installed host proves tenant isolation, interrupted rotation, and cold recovery across the same receipts"
)]
pub(super) async fn exercise(
    root: &Path,
    source: &Value,
    first: &install::Receipt,
    management: &str,
    pg: &crate::config::Database,
    inputs: &Path,
) -> Result<()> {
    let mut primary = pg.clone();
    primary.name = source["database"]["name"]
        .as_str()
        .context("product database")?
        .to_owned();
    let resources = resources(root, first, pg, inputs).await?;
    let mut runtime = maintenance::desired(root, first.host_id)?;
    let bad = root.join("incorrect-writer");
    private(&bad, Uuid::new_v4().simple().to_string())?;
    let mut unavailable = resources[0]["configuration"].clone();
    unavailable["backend"]["writer"]["password_file"] = json!(bad);
    let request = json!({"installation":source,"operation_id":Uuid::new_v4(),"tenant":null,"expected_revision":runtime["runtime_binding"]["revision"],"change":{"kind":"telemetry","settings":unavailable}});
    ensure!(
        configure::run(serde_json::from_value(request)?)
            .await
            .is_err(),
        "physical credentials must qualify before acceptance"
    );
    for resource in &resources {
        let request = json!({"installation":source,"operation_id":Uuid::new_v4(),"tenant":null,"expected_revision":runtime["runtime_binding"]["revision"],"change":{"kind":"telemetry","settings":resource["configuration"]}});
        let receipt = configure::run(serde_json::from_value(request)?).await?;
        ensure!(receipt.deployment_required);
        runtime = maintenance::desired(root, first.host_id)?;
    }
    recovery::unrelated_rotation(root, source, first, &resources[0]).await?;
    runtime = maintenance::desired(root, first.host_id)?;
    let running = Box::pin(maintenance::Running::open(&runtime)).await?;
    runtime_files::observe_installation(serde_json::from_value(source.clone())?).await?;
    let address = source["listen"]
        .as_str()
        .context("host listener")?
        .parse()?;
    let mut platform = Browser::new(address)?;
    platform
        .login(management, "platform", "Installation-platform-admin!42")
        .await?;
    let (a, mut first_browser) = provision(&mut platform).await?;
    let reader = |name: &str| -> Result<Value> {
        let password = root.join(format!("{name}-password"));
        let strong = || {
            (0..3)
                .map(|_| Uuid::new_v4().simple().to_string())
                .collect::<String>()
        };
        private(
            &password,
            if name == "a" {
                Uuid::new_v4().simple().to_string()
            } else {
                strong()
            },
        )?;
        let worker = root.join(format!("{name}-worker-password"));
        private(&worker, strong())?;
        let key = root.join(format!("{name}-cursor"));
        private(&key, [if name == "a" { 3 } else { 4 }; 32])?;
        Ok(
            json!({"kind":"reader","password_file":password,"worker_password_file":worker,"cursor_key_file":key}),
        )
    };
    let mut a_reader = reader("a")?;
    attach(source, &resources[0], a, 0, a_reader.clone()).await?;
    a_reader
        .as_object_mut()
        .unwrap()
        .remove("worker_password_file");
    available(&mut first_browser, a, true).await?;
    let a_data = Box::pin(data::Upload::publish(
        &running,
        &mut first_browser,
        a,
        &primary,
        &runtime,
        inputs,
        11,
    ))
    .await
    .context("A product intake")?;
    let (_, before) = platform.call(Method::GET, "/readyz", None, None).await?;
    let mut control = pg.clone();
    control.name = "ch_control".into();
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(control.options()?)
        .await?;
    let sessions = || {
        sqlx::query_scalar::<_,i32>("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename='metrics_click_house' ORDER BY pid").fetch_all(&observer)
    };
    let original = sessions().await?;
    ensure!(original.len() == 1, "one admitted control pool session");
    let (b, mut peer) = provision(&mut platform).await?;
    recovery::password_policy(inputs, &resources[0], true).await?;
    let mut b_reader = reader("b")?;
    let mut reused = b_reader.clone();
    reused["worker_password_file"] = b_reader["password_file"].clone();
    ensure!(
        attach(source, &resources[0], b, 0, reused).await.is_err(),
        "independent worker password on first enrollment"
    );
    attach(source, &resources[0], b, 0, b_reader.clone()).await?;
    b_reader
        .as_object_mut()
        .unwrap()
        .remove("worker_password_file");
    available(&mut peer, b, true).await?;
    let b_data = Box::pin(data::Upload::publish(
        &running, &mut peer, b, &primary, &runtime, inputs, 22,
    ))
    .await
    .context("B product intake")?;
    recovery::reader_isolation(root, &resources[0], a, b).await?;
    a_data
        .reject_foreign_cursor(&mut first_browser, &b_data)
        .await?;
    let (_, after) = platform.call(Method::GET, "/readyz", None, None).await?;
    ensure!(
        before["observation"].is_object()
            && before["observation"] == after["observation"]
            && runtime == maintenance::desired(root, first.host_id)?,
        "tenant access changed host generation or runtime resources"
    );
    ensure!(
        sessions().await? == original,
        "tenant B must reuse the live A control connection"
    );
    recovery::rejected_rotation(root, source, &resources[0], a, &a_reader).await?;
    recovery::password_policy(inputs, &resources[0], false).await?;
    let mut rotation = b_reader.clone();
    let password = root.join("b-next-password");
    private(&password, Uuid::new_v4().simple().to_string())?;
    rotation["password_file"] = json!(password);
    let request = json!({"product":source,"installation":resources[0],"operationId":Uuid::new_v4(),"tenant":b,"expectedRevision":1,"action":rotation});
    // Interrupt after the provider changed the password and before PostgreSQL accepts the probe.
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(primary.options()?)
        .await?;
    let service = running.telemetry.get().context("installed ingress")?;
    let query = json!({"product":source,"tenant":b,"operationId":request["operationId"]});
    let mut unchanged = request.clone();
    unchanged["action"] = b_reader.clone();
    ensure!(
        matches!(
            telemetry::prepare_tenant(serde_json::from_value(unchanged)?).await,
            Err(crate::installation::Error::Conflict)
        ),
        "same password cannot rotate"
    );
    sqlx::raw_sql("CREATE FUNCTION public.pause_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'hold published receipt'; END $$; CREATE TRIGGER pause_receipt BEFORE UPDATE OF delivery ON mdm_telemetry.batches FOR EACH ROW WHEN (NEW.delivery='published') EXECUTE FUNCTION public.pause_receipt()").execute(&admin).await?;
    let expired = b_data
        .more(service, 2)
        .await
        .context("intake before retry expiry")?;
    let mut tx = admin.begin().await?;
    sqlx::query("SELECT set_config('rss.storage_target',encode(s.target,'hex'),true),set_config('rss.storage_lineage',encode(s.lineage,'hex'),true),set_config('rss.tenant_id',e.tenant_id::text,true),set_config('rss.execution_epoch',e.epoch::text,true) FROM rss_transactional_messaging.storage_lineage s CROSS JOIN rss_transactional_messaging.tenant_epoch e WHERE s.singleton AND e.tenant_id=$1")
        .bind(b).fetch_one(&mut *tx).await?;
    let advanced = sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second',retry_after=clock_timestamp() WHERE tenant_id=$1 AND domain='mdm-telemetry' AND message_id=$2")
        .bind(b).bind(expired.to_string()).execute(&mut *tx).await?.rows_affected();
    ensure!(
        advanced == 1,
        "expire the original batch under the installed storage fence"
    );
    tx.commit().await?;
    tokio::time::timeout(Duration::from_secs(45),async {
        loop{
            let status:String=sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND message_id=$2").bind(b).bind(expired.to_string()).fetch_one(&admin).await?;
            if status=="dead_letter" {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.context("relay placed expired original in dead letter")??;
    let awaiting = b_data
        .more(service, 4)
        .await
        .context("intake before reader rotation")?;
    sqlx::raw_sql("CREATE FUNCTION public.interrupt_reader_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'interrupted reader'; END $$; CREATE TRIGGER interrupt_reader_probe BEFORE UPDATE ON mdm_telemetry.storage_binding FOR EACH ROW WHEN (NEW.probe_ready AND NOT OLD.probe_ready) EXECUTE FUNCTION public.interrupt_reader_probe()").execute(&admin).await?;
    ensure!(
        matches!(
            telemetry::prepare_tenant(serde_json::from_value(request.clone())?).await,
            Err(crate::installation::Error::Storage)
        ),
        "interrupted reader must remain pending"
    );
    sqlx::raw_sql(
        "DROP TRIGGER pause_receipt ON mdm_telemetry.batches; DROP FUNCTION public.pause_receipt()",
    )
    .execute(&admin)
    .await?;
    b_data
        .published(service, awaiting)
        .await
        .context("publish previously accepted batch during rotation")?;
    recovery::login(root, &resources[0], b, "b-password", false).await?;
    let mut different = request.clone();
    different["action"] = json!({"kind":"retire"});
    ensure!(matches!(
        telemetry::prepare_tenant(serde_json::from_value(different)?).await,
        Err(crate::installation::Error::Conflict)
    ));
    let mut cancellation = query.clone();
    cancellation["installation"] = resources[0].clone();
    ensure!(
        serde_json::to_value(telemetry::cancel(serde_json::from_value(cancellation)?).await?)?["state"]
            == "cancelled"
    );
    recovery::login(root, &resources[0], b, "b-password", true).await?;
    let mut request = request;
    request["operationId"] = json!(Uuid::new_v4());
    ensure!(matches!(
        telemetry::prepare_tenant(serde_json::from_value(request.clone())?).await,
        Err(crate::installation::Error::Storage)
    ));
    sqlx::raw_sql("DROP TRIGGER interrupt_reader_probe ON mdm_telemetry.storage_binding; DROP FUNCTION public.interrupt_reader_probe()").execute(&admin).await?;
    let mut competing = request.clone();
    competing["operationId"] = json!(Uuid::new_v4());
    ensure!(
        matches!(
            telemetry::prepare_tenant(serde_json::from_value(competing)?).await,
            Err(crate::installation::Error::Conflict)
        ),
        "only the durable original operation can resume"
    );
    available(&mut peer, b, false).await?;
    available(&mut first_browser, a, true).await?;
    let committed_query = json!({"product":source,"tenant":b,"operationId":request["operationId"]});
    replay_selection(request, &resources[0], 1)
        .await
        .context("resume original reader rotation")?;
    available(&mut first_browser, a, true).await?;
    available(&mut peer, b, true).await?;
    relay_isolation(&admin, service, a, &a_data, &b_data)
        .await
        .context("relay peer after reader rotation")?;
    let (t, mut shared) = provision(&mut platform).await?;
    attach(source, &resources[1], t, 0, json!({"kind":"select"})).await?;
    available(&mut shared, t, true).await?;
    let shared_data = Box::pin(data::Upload::publish(
        &running,
        &mut shared,
        t,
        &primary,
        &runtime,
        inputs,
        33,
    ))
    .await
    .context("SharedRls product intake")?;
    a_data
        .replay(running.telemetry.get().unwrap(), &mut first_browser)
        .await?;
    ensure!(
        sessions().await? == original,
        "reader rotation must retain the shared control session"
    );
    observer.close().await;
    // Keep the original outbox head durable across process shutdown and the cold restore.
    let ddl = sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION public.pause_cold_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'hold accepted batch'; END $$; CREATE TRIGGER pause_cold_receipt BEFORE UPDATE OF delivery ON mdm_telemetry.batches FOR EACH ROW WHEN (NEW.tenant_id='{t}'::uuid AND NEW.delivery='published') EXECUTE FUNCTION public.pause_cold_receipt()"
    ));
    sqlx::raw_sql(ddl).execute(&admin).await?;
    let pending = shared_data
        .more(running.telemetry.get().unwrap(), 2)
        .await?;
    let (gate, blocker) = hold_receipt(&admin, a).await?;
    let draining = a_data.more(running.telemetry.get().unwrap(), 4).await?;
    crate::authority_t2_support::wait_for_blocked_attempt(&admin, blocker, "mdm_telemetry.batches")
        .await?;
    let mut shutdown = Box::pin(running.close());
    ensure!(
        tokio::time::timeout(Duration::from_millis(100), &mut shutdown)
            .await
            .is_err()
    );
    gate.rollback().await?;
    shutdown.await?;
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT delivery='published' FROM mdm_telemetry.batches WHERE tenant_id=$1 AND id=$2"
        )
        .bind(a)
        .bind(draining)
        .fetch_one(&admin)
        .await?
    );
    sqlx::raw_sql("DROP TRIGGER wait_one_receipt ON mdm_telemetry.batches; DROP FUNCTION public.wait_one_receipt()").execute(&admin).await?;
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT delivery <> 'published' FROM mdm_telemetry.batches WHERE tenant_id=$1 AND id=$2"
        )
        .bind(t)
        .bind(pending)
        .fetch_one(&admin)
        .await?
    );
    sqlx::raw_sql("DROP TRIGGER pause_cold_receipt ON mdm_telemetry.batches; DROP FUNCTION public.pause_cold_receipt()").execute(&admin).await?;
    admin.close().await;
    Box::pin(recovery::cold(
        root,
        source,
        first,
        management,
        &primary,
        &resources,
        [a, b, t],
    ))
    .await
    .context("shared storage cold recovery")?;
    let restarted = Box::pin(maintenance::Running::open(&runtime)).await?;
    shared_data
        .published(restarted.telemetry.get().unwrap(), pending)
        .await?;
    peer.login(
        &b.to_string(),
        "administrator",
        "Telemetry-admin-password!42",
    )
    .await?;
    first_browser
        .login(
            &a.to_string(),
            "administrator",
            "Telemetry-admin-password!42",
        )
        .await?;
    shared
        .login(
            &t.to_string(),
            "administrator",
            "Telemetry-admin-password!42",
        )
        .await?;
    available(&mut peer, b, true).await?;
    available(&mut shared, t, true).await?;
    ensure!(
        serde_json::to_value(telemetry::status(serde_json::from_value(committed_query)?).await?)?["state"]
            == "published"
    );
    shared_data
        .replay(restarted.telemetry.get().unwrap(), &mut shared)
        .await?;
    b_data
        .replay(restarted.telemetry.get().unwrap(), &mut peer)
        .await?;
    recovery::interrupt_retirement(&resources[0], b).await?;
    attach(source, &resources[0], b, 2, json!({"kind":"retire"})).await?;
    available(&mut peer, b, false).await?;
    b_data
        .original_receipt(restarted.telemetry.get().unwrap())
        .await?;
    available(&mut first_browser, a, true).await?;
    attach(source, &resources[0], a, 1, json!({"kind":"retire"})).await?;
    available(&mut first_browser, a, false).await?;
    recovery::retained(&primary, a, b, expired).await?;
    restarted.close().await?;
    Ok(())
}

async fn relay_isolation(
    pool: &sqlx::PgPool,
    service: &Arc<rss_mdm_telemetry_service::Service>,
    tenant: Uuid,
    a: &data::Upload,
    b: &data::Upload,
) -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    let (held, pid) = hold_receipt(pool, tenant).await?;
    let accepted = a.more(service, 2).await.context("blocked tenant intake")?;
    let update = "mdm_telemetry.batches";
    let check = async {
        let attempt = wait_for_blocked_attempt(pool, pid, update).await?;
        let peer = b
            .more(service, 6)
            .await
            .context("peer intake during blocked receipt")?;
        b.published(service, peer).await?;
        ensure!(blocked_attempt(pool, pid, update).await? == Some(attempt));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    held.rollback().await?;
    sqlx::raw_sql("DROP TRIGGER wait_one_receipt ON mdm_telemetry.batches; DROP FUNCTION public.wait_one_receipt()").execute(pool).await?;
    check?;
    a.published(service, accepted).await
}

async fn hold_receipt(
    pool: &sqlx::PgPool,
    tenant: Uuid,
) -> Result<(sqlx::Transaction<'static, sqlx::Postgres>, i32)> {
    // Only the first tenant's published receipt waits. Uploads and the other tenant use the ordinary service.
    let ddl = sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION public.wait_one_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text,3210)); RETURN NEW; END $$; CREATE TRIGGER wait_one_receipt BEFORE UPDATE OF delivery ON mdm_telemetry.batches FOR EACH ROW WHEN (NEW.delivery='published' AND NEW.tenant_id='{tenant}'::uuid) EXECUTE FUNCTION public.wait_one_receipt()"
    ));
    sqlx::raw_sql(ddl).execute(pool).await?;
    let mut held = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3210))")
        .bind(tenant.to_string())
        .execute(&mut *held)
        .await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    Ok((held, pid))
}
