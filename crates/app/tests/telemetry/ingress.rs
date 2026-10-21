//! Product-only publication, mTLS admission, Outbox delivery and restart seams.
use crate::test_support::agent_execution::{
    Fixture, case_credential, case_device_id, claim_request, post, resource, upload,
};
use crate::test_support::*;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_resource as r;
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn run(expected: &str, projection: r::TelemetryProjection) -> Result<()> {
    let expected_rows = if projection == r::TelemetryProjection::Current {
        0
    } else {
        2
    };
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
    let (body,query,receipt_path,other_device,interrupted)=resources.finish(async {
        f.grants.push(crate::authorization::Grant {operation:crate::authorization::Permission::InventoryFieldsWrite,scope:crate::authorization::Scope::Tenant});
        for operation in [crate::authorization::Permission::InventoryCollect,crate::authorization::Permission::TelemetryMaintain,crate::authorization::Permission::TelemetryDelete] {
            f.grants.push(crate::authorization::Grant {operation,scope:crate::authorization::Scope::AllDevices});
        }
        identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        f.register_profile(json!(["inventory.collect.v1","task.execute.v1","telemetry.collect.v1"])).await?;
        ensure!(claim_request(&f.router,Uuid::new_v4()).await?.0==StatusCode::OK);
        let (template,_,_)=f.resource().await?;
        post(&mut f.author,&f.router,"/api/v1/asset-retention-policies",json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"key":"telemetry_test","revision":1,"rawSeconds":if expected=="postgres" {30} else {86400},"summarySeconds":if expected=="postgres" {60} else {172800},"restoreSeconds":if expected=="postgres" {30} else {3600}}})).await?;
        let mut field=rss_mdm_inventory::builtin::fields().into_iter().find(|f|f.key.as_str()=="custom.corporate_agent.healthy").unwrap();
        field.version+=1;
        field.time_series=Some(rss_mdm_inventory::TimeSeriesBinding {kind:rss_mdm_inventory::TelemetryKind::State,value_path:vec![],interval_start_path:None,dimensions:Default::default(),aggregations:[rss_mdm_inventory::TelemetryAggregation::Timeline,rss_mdm_inventory::TelemetryAggregation::Coverage].into(),retention:rss_mdm_inventory::RetentionReference {key:"telemetry_test".into(),revision:1},max_resources:1});
        put(&mut f.author,&f.router,"/api/v1/asset-fields/custom.corporate_agent.healthy",json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","definition":field}})).await?;
        let profile=r::TelemetryProfile::new(r::TelemetryProfileSpec {
            template:r::TelemetryTemplate {resource:template.to_string(),version:"v1".into(),variant:"default".into(),platform:r::Platform::MacOS,architecture:r::Architecture::Aarch64},
            parameters:Default::default(),fields:vec![r::TelemetryFieldReference {key:field.key.as_str().into(),version:field.version}],projection,
            sample_millis:5000,upload_millis:10000,budget:r::TelemetryBudget {points:64,bytes:65536,resources:1,execution_millis:1000,output_bytes:4096},boost:None,backfill_seconds:3600,
        })?;
        let profile_id=Uuid::new_v4();let bytes=profile.canonical();let digest:[u8;32]=Sha256::digest(&bytes).into();
        resource(&mut f.author,&f.router,profile_id,0,json!({"action":"create","kind":"telemetry_profile"})).await?;
        resource(&mut f.author,&f.router,profile_id,1,json!({"action":"version","version":"v1","kind":"telemetry_profile","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"telemetry_profile","artifact":{"reference":"profile","length":bytes.len(),"sha256":digest},"definition":profile}}]})).await?;
        ensure!(upload(&f.author,&f.router,profile_id,&bytes).await?==StatusCode::CREATED);
        let published_profile=resource(&mut f.author,&f.router,profile_id,2,json!({"action":"activate","version":"v1"})).await?;
        // The immutable Profile must remain publishable after a compatible catalog upgrade.
        let mut upgraded=field.clone();upgraded.version+=1;upgraded.sources.insert(rss_mdm_inventory::Source::AgentOsquery,1);
        put(&mut f.author,&f.router,"/api/v1/asset-fields/custom.corporate_agent.healthy",json!({"operationId":Uuid::new_v4(),"expectedRevision":field.version,"input":{"action":"put","definition":upgraded}})).await?;
        let scope=Uuid::new_v4();
        let secondary=if expected=="postgres" && projection==r::TelemetryProjection::Both {Some(secondary_peer(&f.base).await?)} else {None};
        let mut targets=vec![json!({"kind":"device","id":case_device_id()})];
        if let Some((_,device))=&secondary {targets.push(json!({"kind":"device","id":device}));}
        f.scope(scope,json!(targets)).await?;
        if secondary.is_some() {f.scope(Uuid::from_u128(case::id("telemetry-counter-scope")),json!([{"kind":"device","id":case_device_id()}])).await?;}

        let definition=json!({"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}});
        let preview=post(&mut f.author,&f.router,"/api/v1/policies/previews",json!({"definition":definition,"after":null,"scopeResult":null})).await?;
        ensure!(preview["items"].as_array().is_some_and(|v|v.len()==1+usize::from(secondary.is_some()) && v.iter().any(|item|item["target"]["device"]==case_device_id() && item["collectionSupported"]==true)),"preview: {preview}");
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
        if expected=="postgres" && projection==r::TelemetryProjection::Both {
            let presentation=json!({"name":"Telemetry display", "vendor":{"labels":["preserved", "nested"]}});
            let edited=resource(&mut f.author,&f.router,profile_id,3,json!({"action":"present","presentation":presentation})).await?;
            ensure!(edited["revision"]==4 && edited["presentation"]==presentation);
            ensure!(edited["versions"]==published_profile["versions"],"display edit changed executable version");
            let (status,after)=agent_call(&f.router,Method::GET,&config_path,Some(case_credential()),None).await?;
            ensure!(status==StatusCode::OK && after["configuration"]["binding"]==configuration.binding,"display edit changed upload binding");
        }
        ensure!(configuration.device_id==case_device_id() && configuration.expires_at>configuration.issued_at);

        ensure!(matches!(configuration.collector,wire::TelemetryCollector::Script {..}));
        let now=f.planning.clock.unix_seconds()? * 1_000_000;
        let id=Uuid::new_v4();let observation=Uuid::new_v4();
        let mut body=json!({"batchId":id,"policy":policy["id"],"policyVersion":policy["versionId"],"binding":configuration.binding,"observations":[{"id":observation,"sequence":10,"observedAt":now-1_000_000,"values":{"custom.corporate_agent.healthy":{"quality":"valid","value":{"kind":"boolean","value":true},"intervalStart":null}}}]});
        if expected=="postgres" && projection==r::TelemetryProjection::Both {
            body["observations"][0]["values"]["custom.vendor_extra"]=json!({"quality":"valid","value":{"kind":"string","value":"raw-vendor-evidence"},"intervalStart":null});
        }
        let other_device=if expected=="postgres" && projection==r::TelemetryProjection::Both {Some(signing_gate(&mut f,&config_path,&body,secondary.as_ref().unwrap()).await?)} else {None};
        if expected=="postgres" && projection==r::TelemetryProjection::Both { recovery::receive_commit_unknown(&mut f,&body).await?; }
        let path="/api/v1/agent/runtime/telemetry/batches";
        for (key,value) in [("tenantId",json!(case::peer())),("source",json!("manual")),("registrationId",json!(Uuid::new_v4()))] {
            let mut forged=body.clone();forged[key]=value;
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(forged)).await?.0==StatusCode::BAD_REQUEST);
        }
        let (status,accepted)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(body.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED,"upload: {status} {accepted}");
        let (status,replayed)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(body.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED && replayed["replayed"]==true);
        if expected=="postgres" && projection==r::TelemetryProjection::Both {
            let mut extension_conflict=body.clone();
            extension_conflict["observations"][0]["values"]["custom.vendor_extra"]["value"]["value"]=json!("changed-evidence");
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(extension_conflict.clone())).await?.0==StatusCode::CONFLICT);
            extension_conflict["batchId"]=json!(Uuid::new_v4());
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(extension_conflict)).await?.0==StatusCode::CONFLICT);
            let quality=pg(&format!("SELECT quality::text FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
            ensure!(!quality.contains("vendor_extra"),"unknown field entered quality: {quality}");
        }
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
        let before_late = if projection!=r::TelemetryProjection::History {
            observed(&f.router,&receipt_path,observation,"snapshot","applied").await?;
            let current=current_field(&mut f.author,&f.router).await?;
            if expected=="postgres" && projection==r::TelemetryProjection::Both {
                let (_,inventory)=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/inventory",case_device_id()),None).await?;
                ensure!(inventory["asset"]["device"]["fields"]["custom.vendor_extra"].is_null());
            }
            ensure!(current.state==rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::Boolean(true)));
            ensure!(current.sources.iter().any(|s|s.evidence.source==rss_mdm_inventory::Source::AgentScript && s.evidence.snapshot_id==observation.to_string()));
            Some(current)
        } else { None };
        let mut late=body.clone();let late_batch=Uuid::new_v4();let late_observation=Uuid::new_v4();
        late["batchId"]=json!(late_batch);late["observations"][0]["id"]=json!(late_observation);
        late["observations"][0]["sequence"]=json!(5);late["observations"][0]["observedAt"]=json!(now-1_500_000);
        late["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(late)).await?.0==StatusCode::ACCEPTED);
        if let Some(before_late)=before_late {
            observed(&f.router,&format!("{path}/{late_batch}"),late_observation,"stale","notApplicable").await?;
            ensure!(current_field(&mut f.author,&f.router).await?==before_late,"backfill changed current value or provenance");
        } else {
            published(&f.router,&format!("{path}/{late_batch}")).await?;
            let (status,current)=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/inventory",case_device_id()),None).await?;
            ensure!(status==StatusCode::OK);
            let field=&current["asset"]["device"]["fields"]["custom.corporate_agent.healthy"];
            ensure!(field.is_null() || field["state"]["kind"]=="missing", "history-only projected current: {field}");
        }
        let query=json!({"device":case_device_id(),"field":"custom.corporate_agent.healthy","resource":"device","startMicros":now-2_000_000,"endMicros":now+1_000_000,"maxPoints":64,"mode":"history","after":null});
        let history=post(&mut f.author,&f.router,"/api/v1/telemetry/history",query.clone()).await?;
        ensure!(history["rows"].as_array().is_some_and(|v|v.len()==expected_rows),"history: {history}");
        if expected=="postgres" { recovery::foreign_session_cannot_read(&mut f,&query).await?; }
        let interrupted=if expected=="postgres" && projection==r::TelemetryProjection::Both { Some(recovery::interrupt_after_backend_write(&mut f,&body).await?) } else { None };
        Ok((body,query,receipt_path,other_device,interrupted))
    }).await?;
    if interrupted.is_some() {
        recovery::release_interruption()?;
    }
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
    if projection == r::TelemetryProjection::Both {
        crate::setup::backup::telemetry_fixture::roundtrip(base.clone(), installation.clone())
            .await?;
    }
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
            if let Some(interrupted)=&interrupted {
                let receipt=format!("/api/v1/agent/runtime/telemetry/batches/{}",interrupted["batchId"].as_str().unwrap());
                published(&router,&receipt).await?;
                recovery::history_is_unique(&mut f.author,&router,interrupted).await?;
                observed(&router,&receipt,serde_json::from_value(interrupted["observations"][0]["id"].clone())?,"stale","notApplicable").await?;
            }
            let history = post(
                &mut f.author,
                &router,
                "/api/v1/telemetry/history",
                query.clone(),
            )
            .await?;
            ensure!(history["rows"].as_array().is_some_and(|v| v.len() == expected_rows));
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
            if projection!=r::TelemetryProjection::Both { return Ok(()); }
            if expected=="postgres" { f.router=router.clone(); counter::quality_and_sensitive_reads(&mut f).await?; }
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
            let mut page_query = query.clone();
            page_query["maxPoints"] = json!(1);
            let first = post(
                &mut f.author,
                &router,
                "/api/v1/telemetry/history",
                page_query.clone(),
            )
            .await?;
            ensure!(
                first["rows"].as_array().is_some_and(|v| v.len() == 1) && first["next"].is_string(),
                "real continuation: {first}"
            );
            page_query["after"] = first["next"].clone();
            let second = post(
                &mut f.author,
                &router,
                "/api/v1/telemetry/history",
                page_query.clone(),
            )
            .await?;
            ensure!(second["rows"].as_array().is_some_and(|v| v.len() == 1));
            if let Some(interrupted)=&interrupted {
                recovery::retention_finishes(&mut f.author,&router,interrupted,&query).await?;
            }
            identity::set_grants(case_tenant(), &f.author_id, vec![]).await?;
            ensure!(
                f.author
                    .call(
                        &router,
                        Method::POST,
                        "/api/v1/telemetry/history",
                        Some(page_query)
                    )
                    .await?
                    .0
                    == StatusCode::FORBIDDEN,
                "continuation must recheck revoked read permission"
            );
            identity::set_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
            // Query a genuine second device with durable samples, not a missing identifier.
            if let Some(other_device) = other_device {
                let mut denied = query.clone();
                denied["device"] = json!(other_device);
                let permitted = post(
                    &mut f.author,
                    &router,
                    "/api/v1/telemetry/history",
                    denied.clone(),
                )
                .await?;
                ensure!(permitted["rows"].as_array().is_some_and(|v| v.len() == 1));
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
            } else {
                identity::set_grants(
                    case_tenant(),
                    &f.author_id,
                    identity::device_grants(Some(case_device_id()), &["inventory_read"])?,
                )
                .await?;
            }
            // A durable old receipt survives publisher revocation, but replay still needs current admission.
            ensure!(
                agent_call(
                    &router,
                    Method::POST,
                    "/api/v1/agent/runtime/telemetry/batches",
                    Some(case_credential()),
                    Some(body.clone())
                )
                .await?
                .0 == StatusCode::UNAUTHORIZED
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
            let registration=pg(&format!("SELECT registration::text FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{}'",case_tenant(),body["batchId"].as_str().unwrap()))?;
            let registration:Uuid=registration.trim().parse()?;
            identity::set_grants(case_tenant(),&f.author_id,identity::device_grants(Some(case_device_id()), &["credentials","inventory_read"])?).await?;
            f.author.operation=Some(Uuid::new_v4());
            post(&mut f.author,&router,&format!("/api/v1/devices/{}/registrations/{registration}/revoke",case_device_id()),json!({})).await?;
            f.author.operation=None;
            for (method,path,payload) in [(Method::GET,receipt_path.as_str(),None),(Method::POST,"/api/v1/agent/runtime/telemetry/batches",Some(body))] {
                let (status,_)=agent_call(&router,method,path,Some(case_credential()),payload).await?;
                ensure!(matches!(status,StatusCode::UNAUTHORIZED|StatusCode::FORBIDDEN),"revoked credential accepted: {status}");
            }
            let mut latest_query=query.clone();latest_query["mode"]=json!("latest");
            let latest=post(&mut f.author,&router,"/api/v1/telemetry/history",latest_query).await?;
            ensure!(latest["rows"].as_array().is_some_and(Vec::is_empty),"retired registration remained current: {latest}");
            let historical=post(&mut f.author,&router,"/api/v1/telemetry/history",query).await?;
            ensure!(historical["rows"].as_array().is_some_and(|rows|rows.len()==2),"revocation removed history");
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.postgres: real product publication, TLS admission, delivery and reopen"]
async fn postgres() -> Result<()> {
    run("postgres", r::TelemetryProjection::Both).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.timescale_shared: real product publication, TLS admission, delivery and reopen"]
async fn timescale_shared() -> Result<()> {
    run("timescale_shared", r::TelemetryProjection::Both).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.timescale_dedicated: real product publication, TLS admission, delivery and reopen"]
async fn timescale_dedicated() -> Result<()> {
    run("timescale_dedicated", r::TelemetryProjection::Both).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.click_house: real product publication, TLS admission, delivery and reopen"]
async fn click_house() -> Result<()> {
    run("click_house", r::TelemetryProjection::Both).await
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
            let (status,result) = author.call(router,Method::POST,"/api/v1/telemetry/maintenance",Some(serde_json::to_value(input)?)).await?;
            if !status.is_success() {
                let receipt=pg(&format!("SELECT count(*)::text||':'||coalesce(max(result::text),'null') FROM mdm_telemetry.maintenance WHERE tenant_id='{}' AND id='{}'",case_tenant(),input.id))?;
                anyhow::bail!("maintenance {status} {result}; durable product receipt: {receipt}");
            }
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
    configuration: &str,
    original: &Value,
    secondary: &(String, String),
) -> Result<String> {
    let mut authority = authority::Authority::from_config(f.base.clone()).await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let service=agent::service(&authority).await?;
        let label=secondary.0.as_str();
        let context=software_execution::context(software_execution::Platform::MacOs);
        let claim=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(label),Some(json!({"wireVersion":1,"executionContext":context,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
        ensure!(claim.0==StatusCode::OK,"capability announcement: {claim:?}");
        ensure!(agent_call(&f.router,Method::GET,configuration,Some(label),None).await?.0==StatusCode::UNAUTHORIZED);
        let peer=agent::evidence(label).unwrap();
        crate::test_support::task_signing::acknowledge(&service,&peer).await?;
        let (status, signed)=agent_call(&f.router,Method::GET,configuration,Some(label),None).await?;
        ensure!(status==StatusCode::OK);
        ensure!(agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/telemetry/batches",Some(label),Some(original.clone())).await?.0==StatusCode::UNAUTHORIZED);
        let mut own=original.clone();
        let batch=Uuid::new_v4();
        own["binding"]=signed["configuration"]["binding"].clone();
        own["batchId"]=json!(batch);own["observations"][0]["id"]=json!(Uuid::new_v4());
        let (status,result)=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/telemetry/batches",Some(label),Some(own)).await?;
        ensure!(status==StatusCode::ACCEPTED,"second device: {status} {result}");
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                let (status,receipt)=agent_call(&f.router,Method::GET,&format!("/api/v1/agent/runtime/telemetry/batches/{batch}"),Some(label),None).await?;
                ensure!(status==StatusCode::OK);
                if receipt["delivery"]=="published" {break;}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
        Ok(secondary.1.clone())
    }).await
}

async fn current_field(
    browser: &mut Browser,
    router: &Router,
) -> Result<rss_mdm_inventory::ResolvedField> {
    let (status, value) = browser
        .call(
            router,
            Method::GET,
            &format!("/api/v1/devices/{}/inventory", case_device_id()),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "current inventory: {status} {value}"
    );
    Ok(serde_json::from_value(
        value["asset"]["device"]["fields"]["custom.corporate_agent.healthy"].clone(),
    )?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.postgres: current projection has no historical side effect"]
async fn postgres_current() -> Result<()> {
    run("postgres", r::TelemetryProjection::Current).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=telemetry.ingress.postgres: history projection has no current asset side effect"]
async fn postgres_history() -> Result<()> {
    run("postgres", r::TelemetryProjection::History).await
}

async fn put(browser: &mut Browser, router: &Router, path: &str, body: Value) -> Result<Value> {
    let (status, value) = browser.call(router, Method::PUT, path, Some(body)).await?;
    ensure!(status.is_success(), "{path}: {status} {value}");
    Ok(value)
}
#[path = "counter.rs"]
mod counter;

#[path = "recovery.rs"]
mod recovery;

async fn secondary_peer(base: &Value) -> Result<(String, String)> {
    let mut authority = authority::Authority::from_config(base.clone()).await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let service=agent::service(&authority).await?;
        let label=case::name("telemetry-unacknowledged");
        let registration=agent::seed_unacknowledged(&service,label,case::name("telemetry-new-device"),json!({"capabilities":["inventory.collect.v1","task.execute.v1","telemetry.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":software_execution::context(software_execution::Platform::MacOs)})).await?;
        Ok((label.into(),registration["deviceId"].as_str().unwrap().into()))
    }).await
}
