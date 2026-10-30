//! Real PG cost and permission evidence; fixtures seed only the unrelated idle population.
use crate::windows::test_support::{Host, case_tenant};
use anyhow::{Result, ensure};
use rss_mdm_native_protection::ProtectionContext;
use sqlx::Row;
use uuid::Uuid;

#[allow(
    clippy::disallowed_methods,
    reason = "T2 measures actual elapsed PostgreSQL work"
)]
async fn idle_costs(host: &Host, pool: &sqlx::PgPool, template: Uuid) -> Result<SqlCounts> {
    let configuration = host.windows.channel.push.as_ref().unwrap().configuration;
    let counts = observe()?;
    sqlx::query("SELECT 1").execute(pool).await?;
    ensure!(
        counts.snapshot()["queries"].as_u64().unwrap() > 0,
        "SQL observer positive control"
    );
    let mut installed = 0;
    for total in [1_000, 10_000] {
        seed_idle(host, pool, template, configuration, installed, total).await?;
        installed = total;
        // Holding the authorization fence proves the idle scan never attempts it.
        let mut fence = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2363))")
            .bind(format!(
                "{}:{}",
                case_tenant(),
                host.authority.identity.instance
            ))
            .execute(&mut *fence)
            .await?;
        counts.reset();
        let start = std::time::Instant::now();
        let scan = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rss_mdm_windows_channel::push::wake_once(
                &host.windows.channel,
                &host.commands.service,
                &host.commands.protection,
                &host.windows_state.access,
                &host.authority.audit,
                case_tenant(),
            ),
        )
        .await??;
        ensure!(scan.candidates == 0);
        let current_sql = counts.snapshot();
        ensure!(current_sql["authorizationQueries"] == 0);
        ensure!(scan.transactions == 0);
        ensure!(scan.sent == 0);
        ensure!(scan.failures == 0);
        fence.rollback().await?;
        let elapsed = start.elapsed().as_micros();
        // Reference query is the discovery predicate from immutable baseline f8ab37a2.
        // The old route TTL column was renamed; only that spelling differs here.
        let baseline: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_windows.push_channels p JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(p.tenant_id,p.registration,p.generation) WHERE p.tenant_id=$1::uuid AND p.configuration=$2 AND p.attempt_until>clock_timestamp() AND p.next_push<=clock_timestamp() AND (p.lease_until IS NULL OR p.lease_until<=clock_timestamp()) AND (p.outcome IS NULL OR p.outcome IN ('accepted','retryable','unknown')) AND r.state='active'")
            .bind(case_tenant()).bind(configuration.as_slice()).fetch_one(pool).await?;
        ensure!(baseline == i64::from(total));
        counts.reset();
        let baseline_start = std::time::Instant::now();
        let baseline_transactions = baseline_idle_sweep(host, pool, configuration).await?;
        let baseline_micros = baseline_start.elapsed().as_micros();
        let baseline_sql = counts.snapshot();
        ensure!(baseline_transactions == total as usize);
        ensure!(baseline_sql["authorizationQueries"].as_u64().unwrap() == total as u64);
        ensure!(
            baseline_sql["queries"].as_u64().unwrap() > current_sql["queries"].as_u64().unwrap()
        );
        let mut read = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE mdm_access")
            .execute(&mut *read)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *read)
            .await?;
        let explain: serde_json::Value = sqlx::query("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT registration FROM mdm_commands.windows_wake_candidates($1)")
            .bind(Uuid::nil()).fetch_one(&mut *read).await?.try_get(0)?;
        read.rollback().await?;
        println!(
            "{}",
            serde_json::json!({"event":"wns_idle_cost","analyzed":true,"baseline":"f8ab37a2c938e26b546492fd19ed87e89c4a137c","channels":total,"baselineCandidates":baseline,"candidates":scan.candidates,"claimTransactions":scan.transactions,"sends":scan.sent,"authorizationFence":"held_by_other_connection","micros":elapsed,"sql":current_sql,"baselineTransactions":baseline_transactions,"baselineMicros":baseline_micros,"baselineSql":baseline_sql,"plan":explain})
        );
    }
    Ok(counts)
}

/// Retained, no-longer-authorized work precedes live work; history must not become candidates.
pub(super) async fn pending_costs(host: &Host, pool: &sqlx::PgPool, operation: Uuid) -> Result<()> {
    use serde_json::{Value, json};
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        operation: Uuid,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Metadata<'a> {
        platform: &'a str,
        deadline: i64,
        input_version: &'a str,
        target: &'a rss_mdm_execution_service::NativeTarget,
    }
    fn bytes(value: &[u8]) -> Value {
        Value::String(format!(
            "\\x{}",
            value.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }
    let row = sqlx::query("SELECT to_jsonb(o) AS operation,to_jsonb(d) AS command,to_jsonb(v) AS device,to_jsonb(a) AS authority,o.request FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) JOIN mdm_commands.devices v ON(v.tenant_id,v.device)=(o.tenant_id,o.device) JOIN rss_device_command.authorities a ON(a.tenant_id,a.device_id)=(d.tenant_id,d.device_id) WHERE o.tenant_id=$1::uuid AND o.id=$2")
        .bind(case_tenant()).bind(operation).fetch_one(pool).await?;
    let template: Value = row.try_get("operation")?;
    let command: Value = row.try_get("command")?;
    let device: Value = row.try_get("device")?;
    let authority: Value = row.try_get("authority")?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let registration = Uuid::parse_str(template["registration"].as_str().unwrap())?;
    let identity = Identity {
        operation,
        device: template["device"].as_str().unwrap(),
        registration,
        generation: template["registration_generation"].as_i64().unwrap(),
    };
    let target: rss_mdm_execution_service::NativeTarget =
        serde_json::from_value(template["input_context"]["target"].clone())?;
    let metadata = Metadata {
        platform: "windows",
        deadline: template["input_context"]["deadline"].as_i64().unwrap(),
        input_version: template["input_context"]["inputVersion"].as_str().unwrap(),
        target: &target,
    };
    let aad = ProtectionContext::new(
        tenant,
        &serde_json::to_string(&identity)?,
        &serde_json::to_string(&("native.operation.input/v1", &metadata))?,
        1,
    )?
    .derive();
    let plain = host
        .commands
        .protection
        .open_bytes(&row.try_get::<Vec<u8>, _>("request")?, &aad)?;
    let input: rss_mdm_execution_service::Create = serde_json::from_slice(plain.expose())?;
    seed_idle(
        host,
        pool,
        registration,
        host.windows.channel.push.as_ref().unwrap().configuration,
        0,
        66,
    )
    .await?;
    let idle=sqlx::query("SELECT id,device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device LIKE 'wns-idle:%' ORDER BY id LIMIT 66")
        .bind(case_tenant()).fetch_all(pool).await?;
    ensure!(idle.len() == 66);
    let mut operations = Vec::new();
    let mut commands = Vec::new();
    let mut devices = Vec::new();
    let mut authorities = Vec::new();
    for idle_row in idle.iter().map(Some).chain(std::iter::repeat_n(None, 1000)) {
        let mut op = template.clone();
        let mut cmd = command.clone();
        let mut input = input.clone();
        input.operation_id = Uuid::new_v4();
        let (reg, name) = if let Some(row) = idle_row {
            (
                row.try_get::<Uuid, _>("id")?,
                row.try_get::<String, _>("device")?,
            )
        } else {
            (registration, identity.device.to_owned())
        };
        if idle_row.is_some() {
            let command_device = Uuid::new_v4();
            let mut dev = device.clone();
            let mut auth = authority.clone();
            dev["device"] = json!(name);
            dev["registration"] = json!(reg);
            dev["registration_generation"] = json!(1);
            dev["command_device"] = json!(command_device);
            auth["device_id"] = json!(command_device);
            cmd["device_id"] = json!(command_device);
            devices.push(dev);
            authorities.push(auth);
        } else {
            cmd["status"] = json!("cancelled");
            cmd["terminal_at"] = cmd["published_at"].clone();
        }
        let id = Identity {
            operation: input.operation_id,
            device: &name,
            registration: reg,
            generation: 1,
        };
        let aad = ProtectionContext::new(
            tenant,
            &serde_json::to_string(&id)?,
            &serde_json::to_string(&("native.operation.input/v1", &metadata))?,
            1,
        )?
        .derive();
        op["id"] = json!(input.operation_id);
        op["device"] = json!(name);
        op["registration"] = json!(reg);
        op["registration_generation"] = json!(1);
        op["request"] = bytes(
            &host
                .commands
                .protection
                .seal_bytes(&serde_json::to_vec(&input)?, &aad)?,
        );
        cmd["command_id"] = json!(input.operation_id.to_string());
        cmd["outbox_message_id"] = json!(input.operation_id.to_string());
        cmd["expected_digest"] = bytes(
            input
                .digest(&host.commands.protection, tenant, &name)?
                .as_bytes(),
        );
        operations.push(op);
        commands.push(cmd);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    for (table, records) in [
        ("rss_device_command.authorities", authorities),
        ("mdm_commands.devices", devices),
        ("rss_device_command.commands", commands),
        ("mdm_commands.operations", operations),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {table} SELECT * FROM jsonb_populate_recordset(NULL::{table},$1)"
        )))
        .bind(json!(records))
        .execute(&mut *tx)
        .await?;
    }
    let retained: Vec<Uuid> = idle.iter().map(|row| row.get("id")).collect();
    sqlx::query("UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id=$1::uuid AND registration=ANY($2)")
        .bind(case_tenant()).bind(retained).execute(&mut *tx).await?;
    tx.commit().await?;
    sqlx::query("ANALYZE mdm_commands.operations,mdm_commands.devices,rss_device_command.commands,rss_device_command.authorities,mdm_access.collection_runs").execute(pool).await?;
    verify_pending_pages(host, pool, registration).await
}

async fn verify_pending_pages(host: &Host, pool: &sqlx::PgPool, registration: Uuid) -> Result<()> {
    use serde_json::json;
    let mut read = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE mdm_access")
        .execute(&mut *read)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *read)
        .await?;
    let mut found = Vec::new();
    let mut after = Uuid::nil();
    let mut pages = 0;
    loop {
        let page = host
            .commands
            .service
            .windows_wake_candidates_in(&mut read, after)
            .await?;
        pages += 1;
        ensure!(page.len() <= 32);
        let count = page.len();
        if let Some(last) = page.last() {
            after = *last;
        }
        found.extend(page);
        if count < 32 {
            break;
        }
    }
    ensure!(found.len() == 67 && pages == 3 && found.contains(&registration));
    ensure!(found.windows(2).all(|pair| pair[0] < pair[1]));
    explain_pending(&mut read, &found).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(crate::test_support::case::peer())
        .execute(&mut *read)
        .await?;
    ensure!(
        host.commands
            .service
            .windows_wake_candidates_in(&mut read, Uuid::nil())
            .await?
            .is_empty()
    );
    read.rollback().await?;
    println!(
        "{}",
        json!({"event":"wns_pending_cost","idleChannels":66,"completedCommands":1000,"pendingRegistrations":found.len(),"pages":pages})
    );
    Ok(())
}

#[derive(Clone, Default)]
pub(super) struct SqlCounts(std::sync::Arc<std::sync::Mutex<(u64, u64, f64)>>);
impl SqlCounts {
    pub(super) fn reset(&self) {
        *self.0.lock().unwrap() = (0, 0, 0.0);
    }
    pub(super) fn snapshot(&self) -> serde_json::Value {
        let (queries, authorization, seconds) = *self.0.lock().unwrap();
        serde_json::json!({"queries":queries,"authorizationQueries":authorization,"authorizationQuerySeconds":seconds})
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SqlCounts {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" {
            return;
        }
        #[derive(Default)]
        struct Statement {
            authorization: bool,
            seconds: f64,
        }
        impl tracing::field::Visit for Statement {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if matches!(field.name(), "db.statement" | "summary") {
                    let sql = format!("{value:?}");
                    self.authorization |=
                        sql.contains("pg_advisory_xact_lock") && sql.contains("2363");
                }
            }
            fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
                if field.name() == "elapsed_secs" {
                    self.seconds = value;
                }
            }
        }
        let mut statement = Statement::default();
        event.record(&mut statement);
        let mut counts = self.0.lock().unwrap();
        counts.0 += 1;
        if statement.authorization {
            counts.1 += 1;
            counts.2 += statement.seconds;
        }
    }
}

/// Comparison-only reproduction of f8ab37a2's idle discovery and write-mode eligibility loop.
/// No production fallback or command send lives here. Every count is an executed transaction.
async fn baseline_idle_sweep(
    host: &Host,
    pool: &sqlx::PgPool,
    configuration: [u8; 32],
) -> Result<usize> {
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let mut after = Uuid::nil();
    let mut transactions = 0;
    loop {
        let mut read = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE mdm_access")
            .execute(&mut *read)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *read)
            .await?;
        let rows=sqlx::query("SELECT p.registration,p.generation,r.device FROM mdm_windows.push_channels p JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(p.tenant_id,p.registration,p.generation) WHERE p.tenant_id=$1::uuid AND p.registration>$3 AND p.configuration=$2 AND p.attempt_until>clock_timestamp() AND p.next_push<=clock_timestamp() AND (p.lease_until IS NULL OR p.lease_until<=clock_timestamp()) AND (p.outcome IS NULL OR p.outcome IN ('accepted','retryable','unknown')) AND r.state='active' ORDER BY p.registration LIMIT 32")
            .bind(case_tenant()).bind(configuration.as_slice()).bind(after).fetch_all(&mut *read).await?;
        read.rollback().await?;
        let count = rows.len();
        for row in rows {
            let registration: Uuid = row.try_get("registration")?;
            let generation: i64 = row.try_get("generation")?;
            let device: String = row.try_get("device")?;
            after = registration;
            let budget = rss_mdm_audit_integration::budget::AuditBudget::new(
                std::time::Duration::from_secs(3),
            );
            let outcome = host
                .authority
                .audit
                .write(
                    tenant,
                    &budget.source_control(),
                    (
                        &host.commands.service,
                        device.as_str(),
                        registration,
                        generation,
                    ),
                    |inputs, tx| {
                        Box::pin(async move {
                            let (service, device, registration, generation) = *inputs;
                            let pending = tx
                                .with_connection_context(
                                    &mut (service, device, registration, generation),
                                    |(service, device, registration, generation), c| {
                                        Box::pin(async move {
                                            service
                                                .windows_wake_pending_in(
                                                    c,
                                                    device,
                                                    *registration,
                                                    *generation,
                                                )
                                                .await
                                                .map_err(rss_mdm_windows_channel::Error::from)
                                        })
                                    },
                                )
                                .await?;
                            Ok::<_, rss_mdm_windows_channel::Error>(pending)
                        })
                    },
                )
                .await;
            let pending = outcome.fold(
                Ok,
                |e| Err(anyhow::anyhow!("{e:?}")),
                |e| Err(anyhow::anyhow!("{e:?}")),
                |_| Err(anyhow::anyhow!("rollback unknown")),
                |_| Err(anyhow::anyhow!("commit unknown")),
                |e| Err(anyhow::anyhow!("{e:?}")),
            )?;
            ensure!(!pending, "idle comparison acquired actual work");
            transactions += 1;
        }
        if count < 32 {
            return Ok(transactions);
        }
    }
}

async fn seed_idle(
    host: &Host,
    pool: &sqlx::PgPool,
    template: Uuid,
    configuration: [u8; 32],
    installed: i32,
    total: i32,
) -> Result<()> {
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let mut ids = Vec::new();
    let mut sealed = Vec::new();
    let mut digests = Vec::new();
    for _ in installed..total {
        let id = Uuid::new_v4();
        let owner = serde_json::to_string(&(id, 1i64, configuration))?;
        let aad = ProtectionContext::new(tenant, &owner, "windows.push.channel", 1)?.derive();
        let uri = b"https://db5.notify.windows.com/idle";
        ids.push(id);
        sealed.push(host.commands.protection.seal_bytes(uri, &aad)?);
        digests.push(host.commands.protection.mac(uri, &aad)?.to_vec());
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) SELECT $1::uuid,'wns-idle:'||id::text FROM unnest($2::uuid[]) id")
            .bind(case_tenant()).bind(&ids).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.grants SELECT (jsonb_populate_record(NULL::mdm_access.grants,to_jsonb(g)||jsonb_build_object('id',ids.id,'device','wns-idle:'||ids.id::text))).* FROM mdm_access.grants g CROSS JOIN unnest($2::uuid[]) ids(id) WHERE g.tenant_id=$1::uuid AND g.id=(SELECT q.grant_id FROM mdm_access.requests q JOIN mdm_access.registrations r ON(r.tenant_id,r.request_id)=(q.tenant_id,q.id) WHERE r.tenant_id=$1::uuid AND r.id=$3)")
        .bind(case_tenant()).bind(&ids).bind(template).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.requests SELECT (jsonb_populate_record(NULL::mdm_access.requests,to_jsonb(q)||jsonb_build_object('id',ids.id,'grant_id',ids.id,'issuance_operation',ids.id))).* FROM mdm_access.requests q CROSS JOIN unnest($2::uuid[]) ids(id) WHERE q.tenant_id=$1::uuid AND q.id=(SELECT request_id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$3)")
            .bind(case_tenant()).bind(&ids).bind(template).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,purpose,epoch,generation,request_id,state) SELECT $1::uuid,id,'wns-idle:'||id::text,'mdm','primary',id,1,id,'active' FROM unnest($2::uuid[]) id")
            .bind(case_tenant()).bind(&ids).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) SELECT $1::uuid,id,id,'mdm',repeat(replace(id::text,'-',''),2),'active' FROM unnest($2::uuid[]) id")
        .bind(case_tenant()).bind(&ids).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) SELECT $1::uuid,id,'mdm.windows',id,true FROM unnest($2::uuid[]) id")
        .bind(case_tenant()).bind(&ids).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_windows.push_channels(tenant_id,registration,generation,revision,configuration,uri,digest,attempt_until) SELECT $1::uuid,id,1,1,$3,uri,digest,clock_timestamp()+interval '1 day' FROM unnest($2::uuid[],$4::bytea[],$5::bytea[]) k(id,uri,digest)")
            .bind(case_tenant()).bind(&ids).bind(configuration.as_slice()).bind(&sealed).bind(&digests).execute(&mut *tx).await?;
    tx.commit().await?;
    // Bulk fixtures need representative planner statistics before measuring either path.
    sqlx::query("ANALYZE mdm_access.devices,mdm_access.grants,mdm_access.requests,mdm_access.registrations,mdm_access.credentials,mdm_access.report_sources,mdm_windows.push_channels").execute(pool).await?;
    Ok(())
}

async fn explain_pending(read: &mut sqlx::PgConnection, found: &[Uuid]) -> Result<()> {
    use serde_json::json;
    // Inspect the definer's actual SQL with its role, search_path and tenant context.
    // EXPLAIN of Function Scan alone hides the candidate join/aggregation cost.
    sqlx::query("SET LOCAL ROLE mdm_owner")
        .execute(&mut *read)
        .await?;
    sqlx::query("SET LOCAL search_path=pg_catalog")
        .execute(&mut *read)
        .await?;
    let body: String = sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='mdm_commands.windows_wake_candidates(uuid)'::regprocedure").fetch_one(&mut *read).await?;
    for after in [Uuid::nil(), found[31], found[63]] {
        let plan: serde_json::Value = sqlx::query(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) {}",
            body.replace("p_after", "$1")
        )))
        .bind(after)
        .fetch_one(&mut *read)
        .await?
        .try_get(0)?;
        println!(
            "{}",
            json!({"event":"wns_pending_plan","after":after,"plan":plan})
        );
    }
    sqlx::query("SET LOCAL ROLE mdm_access")
        .execute(&mut *read)
        .await?;

    Ok(())
}

pub(super) fn observe() -> Result<SqlCounts> {
    use tracing_subscriber::layer::SubscriberExt;
    let counts = SqlCounts::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(counts.clone()))?;
    Ok(counts)
}
#[tokio::test]
#[ignore = "MODULE=windows.management: real PG idle fleet cost under the authorization fence"]
async fn idle_fleet_cost_is_independent_of_channel_count() -> Result<()> {
    let host = Host::with_push().await?;
    let peer = host.peer().await?;
    let pool =
        sqlx::PgPool::connect_with(crate::device::test_support::options("postgres")?).await?;
    idle_costs(&host, &pool, peer.intent.registration).await?;
    pool.close().await;
    host.close().await
}
