//! The union belongs to a stream incarnation, independently of the maximum fields per upload.
use super::*;
mod checkpoints;
use checkpoints::{copy_batches, fixed_budget};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_registration_service::DevicePrincipal;
use rss_mdm_telemetry_service::Service;
use sha2::{Digest, Sha256};

async fn upload(
    c: &Context,
    service: &Arc<Service>,
    signing: &rss_mdm_task_trust::Signing,
    principal: &DevicePrincipal,
    epoch: Uuid,
    page: usize,
) -> Result<Uuid> {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../crates/agent-wire/tests/fixtures/telemetry-v1-vectors.json"
    ))?;
    let mut wire = vector["signed"]["configuration"].clone();
    let mut fields = Vec::new();
    let mut references = Vec::new();
    let mut mappings = serde_json::Map::new();
    let mut values = std::collections::BTreeMap::new();
    for n in 0..if page >= 16 { 1 } else { 64 } {
        let key = format!("custom.history_{:04}", page.min(16) * 64 + n);
        let mut field = wire["fields"][0].clone();
        field["key"] = json!(key);
        field["platforms"] = json!(["windows"]);
        if page == 2 && n == 0 {
            field["sensitivity"] = json!("sensitive");
        }
        if page == 0 && n != 0 {
            field["timeSeries"] = Value::Null;
        }
        let typed: inv::FieldDefinition = serde_json::from_value(field.clone())?;
        typed.validate()?;
        fields.push(field);
        references.push(json!({"key":key,"version":1}));
        mappings.insert(
            key.clone(),
            wire["collector"]["mappings"]["custom.load"].clone(),
        );
        values.insert(
            wire::FieldKey::parse(&key)?,
            wire::TelemetryReading::Valid {
                value: wire::Scalar::Integer(42),
                interval_start: None,
            },
        );
    }
    let policy = Uuid::from_u128(page as u128 + 1);
    let version = Uuid::new_v4();
    let profile: rss_mdm_resource::TelemetryProfile = serde_json::from_value(json!({
        "template":{"resource":"metric-script","version":"v1","variant":"default","platform":"windows","architecture":"x86_64"},
        "parameters":{},"fields":references,"projection":if page==16 {"history"} else {"current"},"sampleMillis":5000,"uploadMillis":10000,
        "budget":{"points":64,"bytes":65536,"resources":64,"executionMillis":1000,"outputBytes":4096},
        "boost":null,"backfillSeconds":3600}))?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    wire["policy"] = json!(policy);
    wire["policyVersion"] = json!(version);
    wire["fields"] = json!(fields);
    wire["tenantId"] = json!(c.tenant.to_string());
    wire["deviceId"] = json!(principal.device());
    wire["sourceEpoch"] = json!(epoch);
    wire["issuedAt"] = json!(now - 10);
    wire["expiresAt"] = json!(now + 280);
    wire["maxResources"] = json!(64);
    wire["collector"]["mappings"] = json!(mappings);
    wire["binding"] = json!(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            c.tenant.to_string(),
            principal.device(),
            "agent.script",
            epoch,
            policy,
            version,
            &profile
        ))?)
    ));
    let configuration: wire::TelemetryConfiguration = serde_json::from_value(wire.clone())?;
    let script: rss_mdm_resource::ScriptDefinition = serde_json::from_value(json!({
        "profile":rss_mdm_resource::ScriptProfile::PowerShell7,"sql":null,"runAs":"system","encoding":"utf8",
        "parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},
        "output":wire["collector"]["outputSchema"],"purpose":{"kind":"collection","scope":{"kind":"device"},
        "applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},
        "mappings":mappings},"timeoutSeconds":1,"outputBytes":4096,"maxRows":1}))?;
    let frozen = json!({"resourceDigest":configuration.resource_digest,"source":"agent.script","profile":profile,
        "fields":fields,"collector":{"kind":"script","definition":script,"reference":"fixture.ps1","length":4,"digest":vec![7;32]}});
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    if page <= 16 {
        sqlx::query("SELECT mdm.append_field_version($1::uuid,f->>'key',1,f) FROM jsonb_array_elements($2::jsonb) f")
        .bind(c.tenant.to_string()).bind(json!(fields)).execute(&mut *tx).await?;
    }
    let definition = json!({"scope":Uuid::new_v4(),"action":{"kind":"telemetry_profile","resource":{"id":"profile","version":"v1","variant":"default","platform":"windows","architecture":"x86_64"}}});
    let author = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'archived',$4,$5,$6)")
        .bind(c.tenant.to_string()).bind(policy).bind(version).bind(definition).bind(serde_json::to_value(author)?).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'telemetry_profile','profile','v1',$4,$5)")
        .bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    let configuration = signing
        .sign_telemetry_on(&mut tx, principal, configuration)
        .await?;
    tx.commit().await?;
    let input = wire::TelemetryUpload {
        configuration,
        batch_id: Uuid::new_v4(),
        observations: vec![wire::TelemetryObservation {
            id: Uuid::new_v4(),
            sequence: page as u64 + 1,
            observed_at: now * 1_000_000,
            values,
        }],
    };
    input.validate()?;
    if page == 0 {
        let bytes = serde_json::to_vec(&input)?.len();
        super::uncertain_intake(c, "batches", input.batch_id, |request| async {
            service
                .receive(principal, &input, bytes, request)
                .await
                .map(|_| ())
        })
        .await?;
    }
    let receipt = service
        .receive(
            principal,
            &input,
            serde_json::to_vec(&input)?.len(),
            crate::authority_t2_support::telemetry_intake(principal.binding()),
        )
        .await?;
    anyhow::ensure!(receipt.batch_id == input.batch_id && (page == 0 || !receipt.replayed));
    Ok(input.batch_id)
}

// A read policy in the isolated PostgreSQL fixture pauses precisely the seventeenth
// publication. The normal verifier must finish its first page to reach this row.
async fn late_page_deadline(
    c: &Context,
    short: &http::Http,
    operation: &Value,
    publication: u128,
) -> Result<()> {
    let policy = format!("late_page_{}", Uuid::new_v4().simple());
    let key = Uuid::new_v4().as_u128() as i64;
    let last = Uuid::from_u128(publication);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE POLICY {policy} ON mdm_policy.versions AS RESTRICTIVE FOR SELECT
        USING (CASE WHEN tenant_id='{}'::uuid AND policy='{last}'::uuid THEN (SELECT true FROM pg_advisory_xact_lock({key}::bigint)) ELSE true END)",c.tenant))).execute(&c.operator).await?;
    let result = async {
        let mut tx = c.operator.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock($1)")
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
        let observed = std::sync::atomic::AtomicBool::new(false);
        let attempts = async {
            for _ in 0..16 {
                let response = short
                    .call("/telemetry/maintenance", operation.clone())
                    .await?;
                anyhow::ensure!(
                    response == (504, json!({"code":"request_deadline"})),
                    "qualification returned {response:?}"
                );
                if observed.load(std::sync::atomic::Ordering::SeqCst) {
                    return anyhow::Ok(());
                }
            }
            anyhow::bail!("request budget never reached gated publication")
        };
        let watch = async {
            c.wait_blocked(pid).await?;
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            anyhow::Ok(())
        };
        tokio::try_join!(watch, attempts)?;
        tx.rollback().await?;
        anyhow::Ok(())
    }
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP POLICY {policy} ON mdm_policy.versions"
    )))
    .execute(&c.operator)
    .await?;
    result
}

async fn verify_pool(
    c: &Context,
    f: &Fixture,
    prepared: &mut crate::command_runtime_t2_support::Prepared,
) -> Result<()> {
    let mut resource = f.config.clone();
    resource.connections = NonZeroU32::new(65).unwrap();
    resource.validate()?;
    let host = &mut prepared.config;
    host.telemetry = vec![resource.clone()];
    host.background.database_connection_budget = 65;
    anyhow::ensure!(host.background.compile(host).is_err());
    host.background.database_connection_budget = 4096;
    host.background.compile(host)?;
    // Use the physical factory used by PgStore, not the count of lazy connections at startup.
    let pool = resource.runtime_pool().await?;
    let mut held = Vec::new();
    for _ in 0..65 {
        held.push(pool.acquire().await?);
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1 AND usename=$2")
            .bind(&resource.database().name)
            .bind(&resource.database().user)
            .fetch_one(&c.operator)
            .await?;
    anyhow::ensure!(count >= 65 && pool.options().get_max_connections() == 65);
    drop(held);
    pool.close().await;
    Ok(())
}

pub(super) async fn exercise(c: &Context, f: &Fixture) -> Result<()> {
    use crate::command_runtime_t2_support::Prepared;
    let mut prepared = Prepared::open(c, |_| {}).await?;
    let result=async {
        verify_pool(c,f,&mut prepared).await?;
        fixture::persist_selection(c,&f.config).await?;
        let service=f.service(c,std::slice::from_ref(&f.config)).await?;
        let (registration,grant)=materials::seed_registration(c).await?;
        let principal=materials::authenticated_agent(c,grant,&registration,vec![
            wire::Capability::InventoryCollectionV1,wire::Capability::TelemetryCollectV1]).await?;
        let epoch=Uuid::new_v4();
        let trust=materials::seed_trust(c,&prepared.protection,&[rss_mdm_agent_wire::task_trust::KeyState::Active]).await?;
        materials::seed_ack(c,&trust,principal.device()).await?;
        let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
        anyhow::ensure!(rss_mdm_inventory_postgres::publish_retention_policy_in(&mut tx,c.tenant,&inv::RetentionPolicy{
            key:"standard".into(),revision:1,raw_seconds:86400,summary_seconds:86400,restore_seconds:0
        }).await?);
        sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,device,source,epoch,next_sequence,enabled) VALUES($1::uuid,$2,'agent.script',$3,0,true)")
            .bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(epoch).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut ids=Vec::new();
        for page in 0..49 { ids.push(upload(c,&service,&prepared.signing,&principal,epoch,page).await?); }
        let final_batch=ids[16];
        let first_batch=ids[0];
        let keys:i64=sqlx::query_scalar("SELECT count(DISTINCT field) FROM mdm_telemetry.batches CROSS JOIN LATERAL unnest(fields) field WHERE tenant_id=$1::uuid AND device=$2 AND epoch=$3")
            .bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(epoch).fetch_one(&c.operator).await?;
        anyhow::ensure!(keys==1025);
        let cancel=tokio_util::sync::CancellationToken::new();
        let worker=tokio::spawn(service.clone().run(prepared.storage.runtime.clone(),cancel.clone()));
        let delivery=tokio::time::timeout(std::time::Duration::from_secs(90), async {
            for id in ids { loop {
                if matches!(service.status(&principal,id).await?.delivery,wire::TelemetryDelivery::Published){ break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            } }
            anyhow::Ok(())
        }).await;
        cancel.cancel();
        worker.await??;
        delivery??;
        // Repeated historical admissions share an indexed field set. Only one earlier real batch is changed below.
        copy_batches(c,final_batch,8192,None,None).await?;
        let account=c.account(&[Permission::InventoryRead,Permission::TelemetryMaintain]).await?;
        let short=http::Http::with_timeout(c,service.clone(),&account,std::time::Duration::from_millis(750)).await?;
        let http=http::Http::open(c,service.clone(),&account).await?;
        let target=json!({"source":"agent.script","epoch":epoch});
        let request=|action:Value| json!({"id":Uuid::new_v4(),"device":principal.device(),
            "field":"custom.history_0000","resource":"device","startMicros":0,"endMicros":1,"action":action});
        let mut observer=f.provider_observer(c).await?;
        let generation=epoch.to_string();
        let (received,expired):(i64,bool)=sqlx::query_as("SELECT received_at,expired FROM rss_timeseries.batches WHERE tenant_id=$1::uuid AND generation=$2")
            .bind(c.tenant.to_string()).bind(&generation).fetch_one(&mut observer).await?;
        anyhow::ensure!(!expired);
        let expire=request(json!({"action":"expire_receipts","target":target,"before_micros":received+1}));
        let close=request(json!({"action":"close_stream","target":target}));
        let reclaim=request(json!({"action":"reclaim","target":target}));
        assert_eq!(http.call("/telemetry/maintenance",close.clone()).await?.0,403);
        for bad in [json!({"source":"agent.native","epoch":epoch}),json!({"source":"agent.script","epoch":Uuid::new_v4()})] {
            assert_eq!(http.call("/telemetry/maintenance",request(json!({"action":"expire_receipts","target":bad,"before_micros":1}))).await?.0,403);
        }
        let mut narrow=f.config.clone(); narrow.maintenance.authorization_bytes=NonZeroU32::new(1).unwrap();
        let limited_service=f.service(c,&[narrow]).await?;
        let limited=http::Http::open(c,limited_service,&account).await?;
        assert_eq!(limited.call("/telemetry/maintenance",expire.clone()).await?,(422,json!({"code":"capacity_exceeded"})));
        let other=Context::open("shared",&[]).await?;
        let account_other=other.account(&[Permission::InventoryRead,Permission::TelemetryMaintain]).await?;
        let foreign=http::Http::open(&other,service.clone(),&account_other).await?;
        assert_eq!(foreign.call("/telemetry/maintenance",expire.clone()).await?.0,403);
        drop(foreign); other.close().await;
        let probe_op=request(json!({"action":"expire_receipts","target":target,"before_micros":0}));
        fixed_budget(c,&short,&probe_op,first_batch).await?;
        late_page_deadline(c,&short,&expire,17).await?;
        checkpoints::boundaries(c,&short,&http,&expire,&account,first_batch).await?;
        let provider_expired:bool=sqlx::query_scalar("SELECT expired FROM rss_timeseries.batches WHERE tenant_id=$1::uuid AND generation=$2")
            .bind(c.tenant.to_string()).bind(&generation).fetch_one(&mut observer).await?;
        anyhow::ensure!(!provider_expired);
        let bad_page = "custom.history_1024";
        let mut lock = crate::command_runtime_t2_support::seed_transaction(c).await?;
        rss_mdm_registration_service::device::store::lock_channel(
            rss_mdm_install_support::StorageProfile::Mdm, &mut lock,&c.tenant.to_string(),principal.device(),inv::Channel::Agent
        ).await?;
        let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *lock).await?;
        let (status,error)=short.call("/telemetry/maintenance",expire.clone()).await?;
        anyhow::ensure!(status==504 && error["code"]=="request_deadline","undispatched stream step: {status} {error}");
        let delayed = http.call("/telemetry/maintenance",expire.clone());
        let change = async {
            c.wait_blocked(pid).await?;
            sqlx::query("UPDATE mdm.field_versions SET definition=jsonb_set(definition,'{sensitivity}',to_jsonb('secret'::text)) WHERE tenant_id=$1::uuid AND field=$2")
                .bind(c.tenant.to_string()).bind(bad_page).execute(&mut *lock).await?;
            lock.commit().await?;
            anyhow::Ok(())
        };
        let (rejected,modified) = tokio::join!(delayed, change);
        modified?;
        assert_eq!(rejected?.0,403);
        let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
        sqlx::query("UPDATE mdm.field_versions SET definition=jsonb_set(definition,'{sensitivity}',to_jsonb('standard'::text)) WHERE tenant_id=$1::uuid AND field=$2")
            .bind(c.tenant.to_string()).bind(bad_page).execute(&mut *tx).await?;
        tx.commit().await?;

        for replacement in [json!(["unknown.field"]),json!(["custom.history_0000"])] {
            let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
            sqlx::query("UPDATE mdm_telemetry.batches SET fields=ARRAY(SELECT jsonb_array_elements_text($3)) WHERE tenant_id=$1::uuid AND policy=$2 AND id=$4")
                .bind(c.tenant.to_string()).bind(Uuid::from_u128(17)).bind(replacement).bind(final_batch).execute(&mut *tx).await?;
            tx.commit().await?;
            assert_eq!(http.call("/telemetry/maintenance",expire.clone()).await?.0,403);
        }
        let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
        sqlx::query("UPDATE mdm_telemetry.batches SET fields=ARRAY[$3::text] WHERE tenant_id=$1::uuid AND policy=$2 AND id=$4")
            .bind(c.tenant.to_string()).bind(Uuid::from_u128(17)).bind(bad_page).bind(final_batch).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2 AND source='agent.script' AND epoch=$3")
            .bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(epoch).execute(&mut *tx).await?;
        tx.commit().await?;
        let id=Uuid::parse_str(expire["id"].as_str().unwrap())?;
        let intents:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
        anyhow::ensure!(intents==0);
        for command in [expire,close] {
            let (left,right)=tokio::join!(http.post("/telemetry/maintenance",command.clone()),http.post("/telemetry/maintenance",command.clone()));
            let progress=left?;
            assert_eq!(right?,progress);
            assert_eq!(progress["state"],"complete");
            assert_eq!(limited.post("/telemetry/maintenance",command.clone()).await?,progress);
            assert_eq!(http.post("/telemetry/maintenance",command).await?,progress);
        }
        let expired:bool=sqlx::query_scalar("SELECT expired FROM rss_timeseries.batches WHERE tenant_id=$1::uuid AND generation=$2")
            .bind(c.tenant.to_string()).bind(&generation).fetch_one(&mut observer).await?;
        anyhow::ensure!(expired);
        let blocked=http.post("/telemetry/maintenance",reclaim.clone()).await?;
        assert_eq!(blocked["state"],"blocked");
        // Raw retention has its own proof. Establish its exact terminal prerequisite for reclaim.
        anyhow::ensure!(sqlx::query("DELETE FROM rss_timeseries.samples WHERE tenant_id=$1::uuid AND generation=$2")
            .bind(c.tenant.to_string()).bind(&generation).execute(&mut observer).await?.rows_affected()==1);
        // RSS has committed Reclaim by the time product progress needs this row.
        let mut hold=crate::command_runtime_t2_support::seed_transaction(c).await?;
        let blocker:i32=sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_telemetry.retention_targets WHERE tenant_id=$1::uuid AND device=$2 AND field=$3 FOR UPDATE")
            .bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(bad_page).fetch_one(&mut *hold).await?;
        let uncertain=short.call("/telemetry/maintenance",reclaim.clone());
        let (observed,response)=tokio::join!(c.wait_blocked(blocker),uncertain);
        observed?;
        let (code,body)=response?;
        anyhow::ensure!(code==503 && body["code"]=="operation_unknown","post-provider settlement: {code} {body}");
        // Observe the committed provider effect while local progress is still fenced.
        let left:i64=sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.batches WHERE tenant_id=$1::uuid AND generation=$2")
            .bind(c.tenant.to_string()).bind(&generation).fetch_one(&mut observer).await?;
        anyhow::ensure!(left==0);
        hold.rollback().await?;
        let completed=http.post("/telemetry/maintenance",reclaim.clone()).await?;
        assert_eq!(completed,json!({"state":"complete","processed":0,"fence":reclaim["id"]}));
        assert_eq!(http.post("/telemetry/maintenance",reclaim).await?,completed);
        anyhow::Ok(())
    }.await;
    fixture::with_cleanup(result, prepared.close().await)
}
