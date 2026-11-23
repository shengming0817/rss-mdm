//! The union belongs to a stream incarnation, independently of the maximum fields per upload.
use super::*;
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
    for n in 0..if page == 16 { 1 } else { 64 } {
        let key = format!("custom.history_{:04}", page * 64 + n);
        let mut field = wire["fields"][0].clone();
        field["key"] = json!(key);
        field["platforms"] = json!(["windows"]);
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
        "parameters":{},"fields":references,"projection":"current","sampleMillis":5000,"uploadMillis":10000,
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
    sqlx::query("SELECT mdm.append_field_version($1::uuid,f->>'key',1,f) FROM jsonb_array_elements($2::jsonb) f")
        .bind(c.tenant.to_string()).bind(json!(fields)).execute(&mut *tx).await?;
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
    let receipt = service
        .receive(principal, &input, serde_json::to_vec(&input)?.len())
        .await?;
    anyhow::ensure!(!receipt.replayed);
    Ok(input.batch_id)
}

pub(super) async fn exercise(c: &Context, f: &Fixture) -> Result<()> {
    use crate::command_runtime_t2_support::Prepared;
    let prepared = Prepared::open(c, |_| {}).await?;
    let result=async {
        fixture::persist_selection(c,&f.config).await?;
        let service=f.service(c,std::slice::from_ref(&f.config)).await?;
        let (registration,grant)=materials::seed_registration(c).await?;
        let principal=materials::authenticated_agent(c,grant,&registration,vec![
            wire::Capability::InventoryCollectionV1,wire::Capability::TelemetryCollectV1]).await?;
        let epoch=Uuid::new_v4();
        let trust=materials::seed_trust(c,&prepared.protection,&[rss_mdm_agent_wire::task_trust::KeyState::Active]).await?;
        materials::seed_ack(c,&trust,principal.device()).await?;
        let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
        sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,device,source,epoch,next_sequence,enabled) VALUES($1::uuid,$2,'agent.script',$3,0,true)")
            .bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(epoch).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut ids=Vec::new();
        for page in 0..17 { ids.push(upload(c,&service,&prepared.signing,&principal,epoch,page).await?); }
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
        let account=c.account(&[Permission::InventoryRead,Permission::TelemetryMaintain]).await?;
        let http=http::Http::open(c,service,&account).await?;
        let target=json!({"source":"agent.script","epoch":epoch});
        let request=|action:Value| json!({"id":Uuid::new_v4(),"device":principal.device(),
            "field":"custom.history_0000","resource":"device","startMicros":0,"endMicros":1,"action":action});
        let expire=request(json!({"action":"expire_receipts","target":target,"before_micros":1}));
        let close=request(json!({"action":"close_stream","target":target}));
        let reclaim=request(json!({"action":"reclaim","target":target}));
        assert_eq!(http.call("/telemetry/maintenance",close.clone()).await?.0,403);
        for bad in [json!({"source":"agent.native","epoch":epoch}),json!({"source":"agent.script","epoch":Uuid::new_v4()})] {
            assert_eq!(http.call("/telemetry/maintenance",request(json!({"action":"expire_receipts","target":bad,"before_micros":1}))).await?.0,403);
        }
        let bad_page = "custom.history_1024";
        for replacement in [json!(["unknown.field"]),json!(["custom.history_0000"])] {
            let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
            sqlx::query("UPDATE mdm_telemetry.batches SET fields=ARRAY(SELECT jsonb_array_elements_text($3)) WHERE tenant_id=$1::uuid AND policy=$2")
                .bind(c.tenant.to_string()).bind(Uuid::from_u128(17)).bind(replacement).execute(&mut *tx).await?;
            tx.commit().await?;
            assert_eq!(http.call("/telemetry/maintenance",expire.clone()).await?.0,403);
        }
        let mut tx=crate::command_runtime_t2_support::seed_transaction(c).await?;
        sqlx::query("UPDATE mdm_telemetry.batches SET fields=ARRAY[$3::text] WHERE tenant_id=$1::uuid AND policy=$2")
            .bind(c.tenant.to_string()).bind(Uuid::from_u128(17)).bind(bad_page).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2 AND source='agent.script' AND epoch=$3")
            .bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(epoch).execute(&mut *tx).await?;
        tx.commit().await?;
        for command in [expire,close,reclaim] {
            let progress=http.post("/telemetry/maintenance",command.clone()).await?;
            assert_eq!(progress["state"],"complete");
            assert_eq!(http.post("/telemetry/maintenance",command).await?,progress);
        }
        anyhow::Ok(())
    }.await;
    fixture::with_cleanup(result, prepared.close().await)
}
