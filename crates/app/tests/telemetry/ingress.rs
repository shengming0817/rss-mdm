//! Product-only publication, mTLS admission, Outbox delivery and restart seams.
use crate::test_support::agent_execution::{
    Fixture, case_credential, case_device_id, claim_request, post, resource, upload,
};
use crate::test_support::*;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_resource as r;
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn run(expected: &str) -> Result<()> {
    let providers: Vec<crate::setup::providers::telemetry::Request> =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TELEMETRY_PROVIDERS")?)?)?;
    ensure!(providers.len() == 1);
    let installation = providers.into_iter().next().unwrap();
    ensure!(serde_json::to_value(&installation.configuration)?["backend"]["kind"] == expected);
    crate::setup::providers::telemetry::prepare(installation.clone()).await?;
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["telemetry"] = serde_json::to_value(&installation.configuration)?;
    let mut f = Fixture::from_config(base.clone()).await?;
    let resources = std::mem::take(&mut f.resources);
    let (body,query,receipt_path)=resources.finish(async {
        f.grants.push(crate::authorization::Grant {operation:crate::authorization::Permission::InventoryFieldsWrite,scope:crate::authorization::Scope::Tenant});
        for operation in [crate::authorization::Permission::InventoryCollect,crate::authorization::Permission::TelemetryMaintain,crate::authorization::Permission::TelemetryDelete] {
            f.grants.push(crate::authorization::Grant {operation,scope:crate::authorization::Scope::AllDevices});
        }
        identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        f.register_profile(json!(["inventory.collect.v1","task.execute.v1","telemetry.collect.v1"])).await?;
        ensure!(claim_request(&f.router,Uuid::new_v4()).await?.0==StatusCode::OK);
        let (template,_,_)=f.resource().await?;
        post(&mut f.author,&f.router,"/api/v1/asset-retention-policies",json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"key":"telemetry_test","revision":1,"rawSeconds":86400,"summarySeconds":172800,"restoreSeconds":3600}})).await?;
        let mut field=rss_mdm_inventory::builtin::fields().into_iter().find(|f|f.key.as_str()=="custom.corporate_agent.healthy").unwrap();
        field.version+=1;
        field.time_series=Some(rss_mdm_inventory::TimeSeriesBinding {kind:rss_mdm_inventory::TelemetryKind::State,value_path:vec![],interval_start_path:None,dimensions:Default::default(),aggregations:[rss_mdm_inventory::TelemetryAggregation::Timeline,rss_mdm_inventory::TelemetryAggregation::Coverage].into(),retention:rss_mdm_inventory::RetentionReference {key:"telemetry_test".into(),revision:1},max_resources:1});
        post(&mut f.author,&f.router,"/api/v1/asset-fields/custom.corporate_agent.healthy",json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","definition":field}})).await?;
        let profile=r::TelemetryProfile::new(r::TelemetryProfileSpec {
            template:r::TelemetryTemplate {resource:template.to_string(),version:"v1".into(),variant:"default".into(),platform:r::Platform::MacOS,architecture:r::Architecture::Aarch64},
            parameters:Default::default(),fields:vec![field.clone()],projection:r::TelemetryProjection::Both,
            sample_millis:5000,upload_millis:10000,budget:r::TelemetryBudget {points:64,bytes:65536,resources:1,execution_millis:1000,output_bytes:4096},boost:None,backfill_seconds:3600,metadata:Default::default(),
        })?;
        let profile_id=Uuid::new_v4();let bytes=profile.canonical();let digest:[u8;32]=Sha256::digest(&bytes).into();
        resource(&mut f.author,&f.router,profile_id,0,json!({"action":"create","kind":"telemetry_profile"})).await?;
        resource(&mut f.author,&f.router,profile_id,1,json!({"action":"version","version":"v1","kind":"telemetry_profile","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"telemetry_profile","artifact":{"reference":"profile","length":bytes.len(),"sha256":digest},"definition":profile}}]})).await?;
        ensure!(upload(&f.author,&f.router,profile_id,&bytes).await?==StatusCode::CREATED);
        resource(&mut f.author,&f.router,profile_id,2,json!({"action":"activate","version":"v1"})).await?;
        let scope=Uuid::new_v4();f.scope(scope,json!([{"kind":"device","id":case_device_id()}])).await?;
        let definition=json!({"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}});
        let preview=post(&mut f.author,&f.router,"/api/v1/policies/previews",json!({"definition":definition,"after":null,"scopeResult":null})).await?;
        ensure!(preview["items"].as_array().is_some_and(|v|v.len()==1) && preview["items"][0]["collectionSupported"]==true,"preview: {preview}");
        let policy=Uuid::new_v4();
        let policy=post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}}}})).await?;
        let config_path=format!("/api/v1/agent/runtime/telemetry/configurations/{}/{}",policy["id"].as_str().unwrap(),policy["versionId"].as_str().unwrap());
        let (status,configuration)=agent_call(&f.router,Method::GET,&config_path,Some(case_credential()),None).await?;
        ensure!(status==StatusCode::OK,"configuration: {status} {configuration}");
        let signed:wire::SignedTelemetryConfiguration=serde_json::from_value(configuration)?;
        use base64::Engine;
        use ring::signature::KeyPair;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519,f.key.public_key().as_ref()).verify(&signed.configuration.signing_bytes(&signed.key_id)?,&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signed.signature)?).map_err(|_|anyhow::anyhow!("configuration signature"))?;
        let configuration=signed.configuration;
        ensure!(configuration.device_id==case_device_id() && configuration.expires_at>configuration.issued_at);

        ensure!(matches!(configuration.collector,wire::TelemetryCollector::Script {..}));
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_micros() as i64;
        let id=Uuid::new_v4();let observation=Uuid::new_v4();
        let body=json!({"batchId":id,"policy":policy["id"],"policyVersion":policy["versionId"],"binding":configuration.binding,"observations":[{"id":observation,"sequence":1,"observedAt":now-1_000_000,"values":{"custom.corporate_agent.healthy":{"quality":"valid","value":{"kind":"boolean","value":true},"intervalStart":null}}}]});
        if expected=="postgres" {signing_gate(&mut f,scope,&config_path,&body).await?;}
        let path="/api/v1/agent/runtime/telemetry/batches";
        let (status,accepted)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(body.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED,"upload: {status} {accepted}");
        let (status,replayed)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(body.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED && replayed["replayed"]==true);
        let mut conflict=body.clone();conflict["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(conflict)).await?.0==StatusCode::CONFLICT);
        let mut observation_conflict=body.clone();observation_conflict["batchId"]=json!(Uuid::new_v4());
        observation_conflict["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(observation_conflict)).await?.0==StatusCode::CONFLICT);
        let receipt_path=format!("{path}/{id}");
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                let (status,receipt)=agent_call(&f.router,Method::GET,&receipt_path,Some(case_credential()),None).await?;
                ensure!(status==StatusCode::OK);
                if receipt["delivery"]=="published" {break;}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
        let regrouped_id=Uuid::new_v4();let mut regrouped=body.clone();regrouped["batchId"]=json!(regrouped_id);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(regrouped)).await?.0==StatusCode::ACCEPTED);
        published(&f.router,&format!("{path}/{regrouped_id}")).await?;
        observed(&f.router,&receipt_path,observation,"snapshot","applied").await?;
        let mut late=body.clone();let late_batch=Uuid::new_v4();let late_observation=Uuid::new_v4();
        late["batchId"]=json!(late_batch);late["observations"][0]["id"]=json!(late_observation);
        late["observations"][0]["sequence"]=json!(0);late["observations"][0]["observedAt"]=json!(now-1_500_000);
        late["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(late)).await?.0==StatusCode::ACCEPTED);
        observed(&f.router,&format!("{path}/{late_batch}"),late_observation,"stale","notApplicable").await?;
        let query=json!({"device":case_device_id(),"field":"custom.corporate_agent.healthy","resource":"device","startMicros":now-2_000_000,"endMicros":now+1_000_000,"maxPoints":64,"mode":"history","after":null});
        let history=post(&mut f.author,&f.router,"/api/v1/telemetry/history",query.clone()).await?;
        ensure!(history["rows"].as_array().is_some_and(|v|v.len()==2),"history: {history}");
        Ok((body,query,receipt_path))
    }).await?;
    if matches!(
        installation.configuration.backend,
        crate::telemetry::Storage::TimescaleDedicated { .. }
    ) {
        let result = crate::setup::providers::telemetry::maintain(
            crate::setup::providers::telemetry::PhysicalRequest {
                installation: installation.clone(),
                operation_id: Uuid::new_v4(),
                action: crate::setup::providers::telemetry::PhysicalAction::ConvertChunks {
                    start_micros: 0,
                    end_micros: 4_102_444_800_000_000,
                    max_chunks: std::num::NonZeroU32::new(32).unwrap(),
                    columnstore: true,
                },
            },
        )
        .await?;
        ensure!(
            result["state"] == "complete" && result["converted"].as_u64().is_some_and(|v| v > 0)
        );
    }
    crate::setup::backup::telemetry_fixture::roundtrip(base.clone(), installation.clone()).await?;
    let mut mismatch = base.clone();
    mismatch["telemetry"]["ingress"]["batchesPerMinute"] =
        json!(installation.configuration.ingress.batches_per_minute + 1);
    ensure!(
        app(&mismatch).await.is_err(),
        "a replica must not replace the tenant's fixed admission policy"
    );
    let (router, resources) = app(&base).await?;
    resources
        .finish(async {
            let history = post(
                &mut f.author,
                &router,
                "/api/v1/telemetry/history",
                query.clone(),
            )
            .await?;
            ensure!(history["rows"].as_array().is_some_and(|v| v.len() == 2));
            let receipt = agent_call(
                &router,
                Method::GET,
                &receipt_path,
                Some(case_credential()),
                None,
            )
            .await?;
            ensure!(receipt.0 == StatusCode::OK && receipt.1["delivery"] == "published");
            let replay = agent_call(
                &router,
                Method::POST,
                "/api/v1/agent/runtime/telemetry/batches",
                Some(case_credential()),
                Some(body.clone()),
            )
            .await?;
            ensure!(replay.0 == StatusCode::ACCEPTED && replay.1["replayed"] == true);
            use rss_mdm_telemetry_service::maintenance::{Action, Request as Maintenance};
            let start = query["startMicros"].as_i64().unwrap();
            let end = query["endMicros"].as_i64().unwrap();
            let maintenance = |action| Maintenance {
                id: Uuid::new_v4(),
                device: case_device_id().into(),
                field: "custom.corporate_agent.healthy".into(),
                resource: "device".into(),
                start_micros: start,
                end_micros: end,
                action,
            };
            let result = settle(
                &mut f.author,
                &router,
                &maintenance(Action::Delete {
                    restore_until_micros: end + 60_000_000,
                }),
            )
            .await?;
            let fence = result["fence"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("delete did not retain a restore fence"))?
                .to_owned();
            let deleted = post(
                &mut f.author,
                &router,
                "/api/v1/telemetry/history",
                query.clone(),
            )
            .await?;
            ensure!(
                deleted["rows"].as_array().is_some_and(Vec::is_empty)
                    && deleted["unavailable"]
                        .as_array()
                        .is_some_and(|v| v.iter().any(|v| v["reason"] == "deleted"))
            );
            settle(
                &mut f.author,
                &router,
                &maintenance(Action::Restore {
                    deletion_fence: fence,
                }),
            )
            .await?;
            let restored = post(
                &mut f.author,
                &router,
                "/api/v1/telemetry/history",
                query.clone(),
            )
            .await?;
            ensure!(restored["rows"].as_array().is_some_and(|v| v.len() == 2));
            let mut denied = query.clone();
            denied["device"] = json!("unassigned-device");
            let grants = identity::device_grants(Some(case_device_id()), &["inventory_read"])?;
            identity::set_grants(case_tenant(), &f.author_id, grants).await?;
            ensure!(
                f.author
                    .call(
                        &router,
                        Method::POST,
                        "/api/v1/telemetry/history",
                        Some(denied)
                    )
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            // A durable old receipt survives publisher revocation, but replay still needs current admission.
            ensure!(
                agent_call(
                    &router,
                    Method::POST,
                    "/api/v1/agent/runtime/telemetry/batches",
                    Some(case_credential()),
                    Some(body)
                )
                .await?
                .0 == StatusCode::FORBIDDEN
            );
            let receipt = agent_call(
                &router,
                Method::GET,
                &receipt_path,
                Some(case_credential()),
                None,
            )
            .await?;
            ensure!(receipt.0 == StatusCode::OK && receipt.1["delivery"] == "published");
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.postgres: real product publication, TLS admission, delivery and reopen"]
async fn postgres() -> Result<()> {
    run("postgres").await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.timescale_shared: real product publication, TLS admission, delivery and reopen"]
async fn timescale_shared() -> Result<()> {
    run("timescale_shared").await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.timescale_dedicated: real product publication, TLS admission, delivery and reopen"]
async fn timescale_dedicated() -> Result<()> {
    run("timescale_dedicated").await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.click_house: real product publication, TLS admission, delivery and reopen"]
async fn click_house() -> Result<()> {
    run("click_house").await
}

async fn observed(
    router: &Router,
    receipt: &str,
    id: Uuid,
    decision: &str,
    projection: &str,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = agent_call(
                router,
                Method::GET,
                &format!("{receipt}/observations/{id}"),
                Some(case_credential()),
                None,
            )
            .await?;
            ensure!(status.0 == StatusCode::OK);
            if status.1["state"]["observation"] == decision
                && status.1["state"]["projection"] == projection
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
async fn settle(
    author: &mut Browser,
    router: &Router,
    input: &rss_mdm_telemetry_service::maintenance::Request,
) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let result = post(
                author,
                router,
                "/api/v1/telemetry/maintenance",
                serde_json::to_value(input)?,
            )
            .await?;
            if result["state"] == "complete" {
                return Ok(result);
            }
            ensure!(
                result["state"] == "more",
                "unexpected maintenance state: {result}"
            );
        }
    })
    .await?
}

async fn published(router: &Router, receipt: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status =
                agent_call(router, Method::GET, receipt, Some(case_credential()), None).await?;
            ensure!(status.0 == StatusCode::OK);
            if status.1["delivery"] == "published" {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}

async fn signing_gate(
    f: &mut Fixture,
    scope: Uuid,
    configuration: &str,
    original: &Value,
) -> Result<()> {
    let mut authority = authority::Authority::from_config(f.base.clone()).await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let service=agent::service(&authority).await?;
        let label=case::name("telemetry-unacknowledged");let device=case::name("telemetry-new-device");
        let context=software_execution::context(software_execution::Platform::MacOs);
        let registration=agent::seed_unacknowledged(&service,label,device,json!({"capabilities":["inventory.collect.v1","task.execute.v1","telemetry.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":context})).await?;
        f.scope(scope,json!([{"kind":"device","id":case_device_id()},{"kind":"device","id":registration["deviceId"]}])).await?;
        let claim=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(label),Some(json!({"wireVersion":1,"executionContext":context,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
        ensure!(claim.0==StatusCode::OK,"capability announcement: {claim:?}");
        ensure!(agent_call(&f.router,Method::GET,configuration,Some(label),None).await?.0==StatusCode::FORBIDDEN);
        let peer=agent::evidence(label).unwrap();
        crate::test_support::task_signing::acknowledge(&service,&peer).await?;
        ensure!(agent_call(&f.router,Method::GET,configuration,Some(label),None).await?.0==StatusCode::OK);
        ensure!(agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/telemetry/batches",Some(label),Some(original.clone())).await?.0==StatusCode::FORBIDDEN);
        Ok(())
    }).await
}
