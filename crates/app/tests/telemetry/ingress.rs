//! Product-only publication, mTLS admission, Outbox delivery and restart seams.
use crate::test_support::agent_execution::{
    Fixture, case_credential, case_device_id, claim_request, post, resource, upload,
};
use crate::test_support::{agent::*, http::*, process::*, runtime::*, *};
use base64::Engine;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_resource as r;
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn fixture(base: Value) -> Result<Fixture> {
    let config: Config = serde_json::from_value(base.clone())?;
    let mut f = Fixture::from_config(base).await?;
    let (resources, mut f) = Resources::build(move |resources| {
        Box::pin(async move {
            resources.extend(std::mem::take(&mut f.resources));
            let tenant = f.planning.tenant;
            let inventory = crate::inventory_runtime::InventoryRuntime::fixture(
                config.runtime_database.options()?,
                Arc::new(rss_mdm_inventory_service::Store::from_pool(
                    f.authority.pool.clone(),
                )),
                tenant,
                monotonic(),
                f.authority.audit.clone(),
            )
            .await?;
            resources.resource(InventoryFixtureResource(inventory.clone()));
            let telemetry = config
                .telemetry
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("telemetry configuration missing"))?
                .open(f.planning.clone(), f.execution.clone())
                .await?;
            resources.resource(crate::telemetry::Resource(telemetry.clone()));
            resources.resource(crate::telemetry::fixture_task(
                telemetry.clone(),
                f.command_runtime.clone(),
                inventory.clone(),
                config.access_options()?,
                tenant,
            )?);
            let key = rss_mdm_flow_service::storage::cursor_key(&f.plan_runtime, tenant).await?;
            let audit_budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
            let audit = Arc::new(
                f.authority
                    .audit
                    .on_runtime(f.plan_runtime.clone(), tenant, &audit_budget.control())
                    .await?,
            );
            let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(
                inventory.clone(),
                audit,
                f.plan_runtime.clone(),
                tenant,
                Arc::new(crate::clock::SystemClock),
                &key,
                Arc::new(crate::automation::inventory_tasks::InventoryTasks),
            ));
            let routes = rss_mdm_management_http::telemetry::routes(Some(telemetry.clone()))
                .merge(rss_mdm_management_http::planning::policies::http::previews(
                    f.queries.clone(),
                    Some(telemetry.clone()),
                    rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor"),
                ))
                .merge(
                    rss_mdm_management_http::assets::routes().with_state(Arc::new(
                        rss_mdm_management_http::assets::http::HttpState { assets },
                    )),
                );
            let native = rss_mdm_agent_channel::router(
                Arc::new(crate::agent::HttpState {
                    content: f.content.clone(),
                    enrollment: f.enrollment.clone(),
                    audit_store: f.authority.audit.clone(),
                    access: Arc::new(rss_mdm_agent_channel::Store::from_pool(
                        f.authority.pool.clone(),
                    )),
                    inventory,
                    telemetry: Some(telemetry),
                }),
                rss_mdm_agent_channel::boundary::Envelope {
                    admission: Arc::new(tokio::sync::Semaphore::new(32)),
                    requests: Arc::new(tokio::sync::Semaphore::new(32)),
                    host: "mdm.example.test:9445".into(),
                    clock: monotonic(),
                    audit_store: f.authority.audit.clone(),
                    tenant: tenant.to_string(),
                },
            );
            f.router = f
                .router
                .clone()
                .merge(
                    f.authority
                        .protect(rss_mdm_http_contract::Router::new().nest("/api/v1", routes))?,
                )
                .merge(Router::new().nest("/api/v1/agent/runtime", native.into_axum()));
            f.router = resources.native_router(f.router);
            Ok(f)
        })
    })
    .await?;
    f.resources = resources;
    Ok(f)
}

async fn run(expected: &str, projection: r::TelemetryProjection) -> Result<()> {
    let anchor = expected == "postgres" && projection == r::TelemetryProjection::Both;
    let restore_seconds: i64 = if expected == "postgres" { 30 } else { 3600 };
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
    let mut f = fixture(base.clone()).await?;
    let resources = std::mem::take(&mut f.resources);
    let (body,query,receipt_path,other_device,interrupted,gap_evidence)=resources.finish(async {
        f.grants.push(crate::authorization::Grant {operation:crate::authorization::Permission::InventoryFieldsWrite,scope:crate::authorization::Scope::Tenant});
        for operation in [crate::authorization::Permission::InventoryCollect,crate::authorization::Permission::TelemetryMaintain,crate::authorization::Permission::TelemetryDelete] {
            f.grants.push(crate::authorization::Grant {operation,scope:crate::authorization::Scope::AllDevices});
        }
        identity::seed_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        f.register_profile(if anchor {json!(["inventory.collect.v1","task.execute.v1","inventory.native.v1","telemetry.collect.v1"])} else {json!(["inventory.collect.v1","task.execute.v1","telemetry.collect.v1"])}).await?;
        ensure!(claim_request(&f.router,Uuid::new_v4()).await?.0==StatusCode::OK);
        let (template,_,_)=f.resource().await?;
        post(&mut f.author,&f.router,"/api/v1/asset-retention-policies",json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"key":"telemetry_test","revision":1,"rawSeconds":if expected=="postgres" {30} else {86400},"summarySeconds":if expected=="postgres" {60} else {172800},"restoreSeconds":restore_seconds}})).await?;
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
        if anchor {
        resource(&mut f.author,&f.router,profile_id,0,json!({"action":"create","kind":"telemetry_profile"})).await?;
        resource(&mut f.author,&f.router,profile_id,1,json!({"action":"version","version":"v1","kind":"telemetry_profile","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"telemetry_profile","artifact":{"reference":"profile","length":bytes.len(),"sha256":digest},"definition":profile}}]})).await?;
        ensure!(upload(&f.author,&f.router,profile_id,&bytes).await?==StatusCode::CREATED);
        resource(&mut f.author,&f.router,profile_id,2,json!({"action":"activate","version":"v1"})).await?;
        let (status,directory)=f.author.call(&f.router,Method::GET,"/api/v1/resources?filter=kind==telemetry_profile;active==true",None).await?;
        ensure!(status==StatusCode::OK && directory["items"].as_array().is_some_and(|items| items.iter().any(|item| item["id"]==profile_id.to_string() && item["kind"]=="telemetry_profile" && item["activeVersion"]=="v1")),"telemetry resource directory: {status} {directory}");
        // The immutable Profile must remain publishable after a compatible catalog upgrade.
        let mut upgraded=field.clone();upgraded.version+=1;upgraded.sources.insert(rss_mdm_inventory::Source::AgentOsquery,1);
        put(&mut f.author,&f.router,"/api/v1/asset-fields/custom.corporate_agent.healthy",json!({"operationId":Uuid::new_v4(),"expectedRevision":field.version,"input":{"action":"put","definition":upgraded}})).await?;
        } else {
            let tenant = f.authority.identity.tenant;
            let version = r::Version::new(tenant, r::Id::new(profile_id.to_string())?, r::Id::new("v1")?, r::Kind::TelemetryProfile,
                vec![r::Variant::new(r::Platform::MacOS, r::Architecture::Aarch64, r::Id::new("default")?, r::Declaration::TelemetryProfile {
                    artifact: r::Artifact::new(r::Id::new("profile")?, bytes.len() as u64, r::Digest::from_bytes(digest))?, definition: profile.clone(),
                })])?;
            f.plan_runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
                rss_mdm_resource_postgres::fixture::active_version_in(tx, version, rss_contract::Timepoint::try_from(1_i64).expect("fixture time")).await
            })).await.fold(Ok, |e|Err(anyhow::anyhow!(e)), |e|Err(anyhow::anyhow!(e)), |_|Err(anyhow::anyhow!("seed rollback unconfirmed")), |_|Err(anyhow::anyhow!("seed commit unconfirmed")), |e|Err(anyhow::anyhow!(e)))?;
            let artifact = r::Artifact::new(r::Id::new("profile")?, bytes.len() as u64, r::Digest::from_bytes(digest))?;
            rss_mdm_content_service::fixture::artifact(f.content.as_deref().ok_or_else(|| anyhow::anyhow!("telemetry content"))?, &artifact, bytes.clone(), crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400).await?;
        }
        let scope=Uuid::new_v4();
        let secondary=if anchor {Some(secondary_peer(&f.base).await?)} else {None};
        let mut targets=vec![json!({"kind":"device","id":case_device_id()})];
        if let Some((_,device,_))=&secondary {targets.push(json!({"kind":"device","id":device}));}
        f.scope(scope,json!(targets)).await?;
        if secondary.is_some() {f.scope(Uuid::from_u128(case::id("telemetry-counter-scope")),json!([{"kind":"device","id":case_device_id()}])).await?;}

        let definition=json!({"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}});
        if anchor {
        let preview=post(&mut f.author,&f.router,"/api/v1/policies/previews",json!({"definition":definition,"scopeResult":null})).await?;
        ensure!(preview["items"].as_array().is_some_and(|v|v.len()==1+usize::from(secondary.is_some()) && v.iter().any(|item|item["target"]["device"]==case_device_id() && item["collectionSupported"]==true)),"preview: {preview}");
        }
        let policy=Uuid::new_v4();
        let policy=post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}}}})).await?;
        let config_path=format!("/api/v1/agent/runtime/telemetry/configurations/{}/{}",policy["id"].as_str().unwrap(),policy["versionId"].as_str().unwrap());
        let (status,configuration)=agent_call(&f.router,Method::GET,&config_path,Some(case_credential()),None).await?;
        ensure!(status==StatusCode::OK,"configuration: {status} {configuration}");
        let signed:wire::SignedTelemetryConfiguration=serde_json::from_value(configuration)?;
        use ring::signature::KeyPair;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519,f.key.public_key().as_ref()).verify(&signed.configuration.signing_bytes(&signed.key_id)?,&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signed.signature)?).map_err(|_|anyhow::anyhow!("configuration signature"))?;
        let configuration=signed.configuration.clone();
        if anchor {performance::published_cpu(&mut f).await?;}
        let gap_evidence=if anchor {Some(gaps::receive(&mut f,&configuration,secondary.as_ref().unwrap()).await?)} else {None};
        if anchor {
            let resource_path=format!("/api/v1/resources/{profile_id}");
            let (status,before)=f.author.call(&f.router,Method::GET,&resource_path,None).await?;
            ensure!(status==StatusCode::OK && before["versions"].as_array().is_some_and(|v|v.len()==1),"resource before edit: {status} {before}");
            let presentation=json!({"name":"Telemetry display", "vendor":{"labels":["preserved", "nested"]}});
            resource(&mut f.author,&f.router,profile_id,3,json!({"action":"present","presentation":presentation})).await?;
            let (status,edited)=f.author.call(&f.router,Method::GET,&resource_path,None).await?;
            ensure!(status==StatusCode::OK && edited["revision"]==4 && edited["presentation"]==presentation,"resource after edit: {status} {edited}");
            ensure!(edited["versions"]==before["versions"],"display edit changed executable version");
            let (status,after)=agent_call(&f.router,Method::GET,&config_path,Some(case_credential()),None).await?;
            ensure!(status==StatusCode::OK && after["configuration"]["binding"]==configuration.binding,"display edit changed upload binding");
        }
        ensure!(configuration.device_id==case_device_id() && configuration.expires_at>configuration.issued_at);

        ensure!(matches!(configuration.collector,wire::TelemetryCollector::Script {..}));
        if anchor { recovery::cross_dataset_sequence(&f,&field).await?; }
        let now=f.planning.clock.unix_seconds()? * 1_000_000;
        let id=Uuid::new_v4();let observation=Uuid::new_v4();
        let mut body=json!({"batchId":id,"configuration":signed,"observations":[{"id":observation,"sequence":10,"observedAt":now,"values":{"custom.corporate_agent.healthy":{"quality":"valid","value":{"kind":"boolean","value":true},"intervalStart":null}}}]});
        if anchor {
            body["observations"][0]["values"]["custom.vendor_extra"]=json!({"quality":"valid","value":{"kind":"string","value":"raw-vendor-evidence"},"intervalStart":null});
        }
        let other_device=if anchor {Some(signing_gate(&mut f,&config_path,&body,secondary.as_ref().unwrap()).await?)} else {None};
        // A failed transport may precede admission. The Agent queries the original ID
        // before resubmitting its persisted body; absence must not revoke its identity.
        let receipt_path=format!("/api/v1/agent/runtime/telemetry/batches/{id}");
        ensure!(agent_call(&f.router,Method::GET,&receipt_path,Some(case_credential()),None).await?.0==StatusCode::NOT_FOUND);
        if anchor { recovery::receive_commit_unknown(&mut f,&body).await?; }
        let path="/api/v1/agent/runtime/telemetry/batches";
        if anchor {
        for (key,value) in [("tenantId",json!(case::peer())),("source",json!("manual")),("registrationId",json!(Uuid::new_v4()))] {
            let mut forged=body.clone();forged[key]=value;
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(forged)).await?.0==StatusCode::BAD_REQUEST);
        }
        }
        let (status,accepted)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(body.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED,"upload: {status} {accepted}");
        if anchor {
        let (status,replayed)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(body.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED && replayed["replayed"]==true);
        if anchor {
            let mut extension_conflict=body.clone();
            extension_conflict["observations"][0]["values"]["custom.vendor_extra"]["value"]["value"]=json!("changed-evidence");
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(extension_conflict.clone())).await?.0==StatusCode::CONFLICT);
            extension_conflict["batchId"]=json!(Uuid::new_v4());
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(extension_conflict)).await?.0==StatusCode::CONFLICT);
            let quality=pg(&format!("SELECT quality::text FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
            ensure!(!quality.contains("vendor_extra"),"unknown field entered quality: {quality}");
        }
        let mut tampered=body.clone();let tampered_id=Uuid::new_v4();tampered["batchId"]=json!(tampered_id);tampered["configuration"]["configuration"]["expiresAt"]=json!(configuration.expires_at+1);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(tampered)).await?.0==StatusCode::UNAUTHORIZED);
        ensure!(pg(&format!("SELECT count(*) FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{tampered_id}'",case_tenant()))?.trim()=="0");
        let mut conflict=body.clone();conflict["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(conflict)).await?.0==StatusCode::CONFLICT);
        let mut observation_conflict=body.clone();observation_conflict["batchId"]=json!(Uuid::new_v4());
        observation_conflict["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(observation_conflict)).await?.0==StatusCode::CONFLICT);
        }
        let receipt_path=format!("{path}/{id}");
        if let Some((credential,_,_))=&secondary {
            ensure!(agent_call(&f.router,Method::GET,&receipt_path,Some(credential),None).await?.0==StatusCode::NOT_FOUND,"another registration must not discover a batch receipt");
        }
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                let (status,receipt)=agent_call(&f.router,Method::GET,&receipt_path,Some(case_credential()),None).await?;
                ensure!(status==StatusCode::OK);
                if receipt["delivery"]=="published" {break;}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
        if anchor {
        let regrouped_id=Uuid::new_v4();let mut regrouped=body.clone();regrouped["batchId"]=json!(regrouped_id);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(regrouped)).await?.0==StatusCode::ACCEPTED);
        published(&f.router,&format!("{path}/{regrouped_id}")).await?;
        }
        let before_late = if projection!=r::TelemetryProjection::History {
            observed(&f.router,&receipt_path,observation,"snapshot","applied").await?;
            let current=current_field(&mut f.author,&f.router).await?;
            if anchor {
                let (_,inventory)=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/inventory",case_device_id()),None).await?;
                ensure!(inventory["asset"]["device"]["fields"]["custom.vendor_extra"].is_null());
            }
            ensure!(current.state==rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::Boolean(true)));
            ensure!(current.sources.iter().any(|s|s.evidence.source==rss_mdm_inventory::Source::AgentScript && s.evidence.snapshot_id==observation.to_string()));
            Some(current)
        } else { None };
        let mut late=body.clone();let late_batch=Uuid::new_v4();let late_observation=Uuid::new_v4();
        late["batchId"]=json!(late_batch);late["observations"][0]["id"]=json!(late_observation);
        late["observations"][0]["sequence"]=json!(5);late["observations"][0]["observedAt"]=json!(now);
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
        let interrupted=if anchor { Some(recovery::interrupt_after_backend_write(&mut f,&body).await?) } else { None };
        Ok((body,query,receipt_path,other_device,interrupted,gap_evidence))
    }).await?;
    if projection != r::TelemetryProjection::Both {
        return Ok(());
    }
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
    crate::setup::backup::telemetry_fixture::roundtrip(base.clone(), installation.clone()).await?;
    let grants = f.grants;
    let author = f.author;
    f = fixture(base.clone()).await?;
    f.grants = grants;
    f.author = author;
    let router = f.router.clone();
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
    if expected == "postgres" {
        let mut mismatch = base.clone();
        mismatch["telemetry"]["ingress"]["batchesPerMinute"] =
            json!(installation.configuration.ingress.batches_per_minute + 1);
        let config: Config = serde_json::from_value(mismatch)?;
        let binding = config
            .telemetry
            .as_ref()
            .unwrap()
            .configuration_binding()
            .await?;
        ensure!(
            matches!(rss_mdm_telemetry_service::admit_configuration(
                &f.planning.runtime,
                f.planning.tenant,
                binding
            )
            .await, Err(rss_mdm_telemetry_service::Error::Conflict)),
            "a replica must not replace the tenant's fixed admission policy"
        );
    }
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
            if anchor {
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
            }
            if projection!=r::TelemetryProjection::Both { return Ok(()); }
            if expected=="postgres" { counter::quality_and_sensitive_reads(&mut f).await?; }
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
            // Restoration lifetime starts at deletion, independently of sample age and restart time.
            let delete_now: i64 = pg("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")?.trim().parse()?;
            let result = settle(
                &mut f.author,
                &router,
                &maintenance(Action::Delete {
                    restore_until_micros: delete_now + restore_seconds.min(60) * 1_000_000,
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
            if expected != "postgres" { return Ok(()); }
            identity::change_grants(case_tenant(), &f.author_id, vec![]).await?;
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
            identity::change_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
            // Query a genuine second device with durable samples, not a missing identifier.
            if let Some(other_device) = other_device {
                let mut denied = query.clone();
                denied["device"] = json!(other_device);
                denied["endMicros"]=json!(f.planning.clock.unix_seconds()?*1_000_000+1);
                let permitted = post(
                    &mut f.author,
                    &router,
                    "/api/v1/telemetry/history",
                    denied.clone(),
                )
                .await?;
                ensure!(permitted["rows"].as_array().is_some_and(|v| v.len() == 1));
                let grants = identity::device_grants(Some(case_device_id()), &["inventory_read"])?;
                identity::change_grants(case_tenant(), &f.author_id, grants).await?;
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
                identity::change_grants(
                    case_tenant(),
                    &f.author_id,
                    identity::device_grants(Some(case_device_id()), &["inventory_read"])?,
                )
                .await?;
            }
            // Accepted batches recover their original receipt after the publisher loses permissions.
            ensure!(
                agent_call(
                    &router,
                    Method::POST,
                    "/api/v1/agent/runtime/telemetry/batches",
                    Some(case_credential()),
                    Some(body.clone())
                )
                .await?
                .0 == StatusCode::ACCEPTED
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
            if let Some(evidence)=&gap_evidence { gaps::reopened(&mut f,&router,evidence).await?; }
            // The same backend intake accepts a first batch for an older issued Profile.
            identity::change_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
            let owner=body["configuration"]["configuration"]["policy"].as_str().unwrap();
            let (status,current)=f.author.call(&router,Method::GET,&format!("/api/v1/policies/{owner}"),None).await?;ensure!(status==StatusCode::OK);
            let new_scope=Uuid::new_v4();f.scope(new_scope,json!([{"kind":"device","id":case_device_id()}])).await?;
            let frozen: rss_mdm_policy_service::telemetry::FrozenProfile=serde_json::from_str(&pg(&format!("SELECT frozen::text FROM mdm_policy.versions WHERE tenant_id='{}' AND id='{}'",case_tenant(),body["configuration"]["configuration"]["policyVersion"].as_str().unwrap()))?)?;
            let mut spec=frozen.profile.spec().clone();spec.sample_millis=10000;spec.upload_millis=20000;
            let revised=r::TelemetryProfile::new(spec)?;let revised_resource=Uuid::new_v4();
            performance::publish(&mut f,revised_resource,"telemetry_profile",json!(revised),&revised.canonical()).await?;
            let mut replacement=current["definition"].clone();replacement["scope"]=json!(new_scope);replacement["action"]["resource"]["id"]=json!(revised_resource);
            let updated=post(&mut f.author,&router,&format!("/api/v1/policies/{owner}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":current["revision"],"input":{"action":"put","enabled":true,"definition":replacement}})).await?;
            ensure!(updated["versionId"]!=body["configuration"]["configuration"]["policyVersion"]);
            let before_current=current_field(&mut f.author,&router).await?;
            let mut old=body.clone();let old_batch=Uuid::new_v4();old["batchId"]=json!(old_batch);
            let mut original:wire::SignedTelemetryConfiguration=serde_json::from_value(old["configuration"].clone())?;
            let received=f.planning.clock.unix_seconds()?;
            original.configuration.issued_at=received-301;original.configuration.expires_at=received-1;
            original.signature=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(f.key.sign(&original.configuration.signing_bytes(&original.key_id)?).as_ref());
            let observed_at=(received-2)*1_000_000;
            old["configuration"]=json!(original);old["observations"][0]["id"]=json!(Uuid::new_v4());old["observations"][0]["sequence"]=json!(3);old["observations"][0]["observedAt"]=json!(observed_at);old["observations"][0]["values"]["custom.corporate_agent.healthy"]["value"]["value"]=json!(false);
            let (status,result)=agent_call(&router,Method::POST,"/api/v1/agent/runtime/telemetry/batches",Some(case_credential()),Some(old)).await?;
            ensure!(status==StatusCode::ACCEPTED,"old issued profile: {status} {result}");
            published(&router,&format!("/api/v1/agent/runtime/telemetry/batches/{old_batch}")).await?;
            ensure!(pg(&format!("SELECT current_assets FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{old_batch}'",case_tenant()))?.trim()=="f","old profile became current projection");
            let mut historical=query.clone();historical["startMicros"]=json!(observed_at);historical["endMicros"]=json!(observed_at+1);historical["after"]=Value::Null;
            let retained=post(&mut f.author,&router,"/api/v1/telemetry/history",historical).await?;
            ensure!(retained["rows"].as_array().is_some_and(|r|r.len()==1),"new historical observation missing: {retained}");
            ensure!(current_field(&mut f.author,&router).await?==before_current,"old issued profile overwrote current projection");
            if let Some(evidence)=&gap_evidence { gaps::withdrawn(&mut f,&router,evidence,&body["configuration"]["configuration"]["policy"]).await?; }
            let registration=pg(&format!("SELECT registration::text FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{}'",case_tenant(),body["batchId"].as_str().unwrap()))?;
            let registration:Uuid=registration.trim().parse()?;
            identity::change_grants(case_tenant(),&f.author_id,identity::device_grants(Some(case_device_id()), &["credentials","inventory_read"])?).await?;
            f.author.operation=Some(Uuid::new_v4());
            post(&mut f.author,&router,&format!("/api/v1/devices/{}/registrations/{registration}/revoke",case_device_id()),json!({})).await?;
            f.author.operation=None;
            if let Some(evidence)=&gap_evidence { gaps::revoked(&router,evidence).await?; }
            let mut reader_grants = identity::device_grants(Some(case_device_id()), &["inventory_read"])?;
            for operation in [crate::authorization::Permission::PolicyRead, crate::authorization::Permission::ResourceRead] {
                reader_grants.push(crate::authorization::Grant { operation, scope:crate::authorization::Scope::Tenant });
            }
            identity::change_grants(case_tenant(), &f.author_id, reader_grants).await?;
            let (status, summary) = f.author.call(&router, Method::GET,
                &format!("/api/v1/devices/{}/telemetry-configurations", case_device_id()), None).await?;
            ensure!(status == StatusCode::OK && summary["registration"].is_null()
                && summary["configurations"].as_array().is_some_and(Vec::is_empty),
                "revoked registration retained current configuration: {status} {summary}");
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
                anyhow::bail!("maintenance action={} {status} {result}; durable product receipt: {receipt}",serde_json::to_value(&input.action)?);
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
    secondary: &(String, String, wire::BindingProfile),
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
        own["configuration"]=signed.clone();
        own["observations"][0]["observedAt"]=json!(signed["configuration"]["issuedAt"].as_i64().unwrap()*1_000_000);
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

async fn secondary_peer(base: &Value) -> Result<(String, String, wire::BindingProfile)> {
    let mut authority = authority::Authority::from_config(base.clone()).await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let service=agent::service(&authority).await?;
        let label=case::name("telemetry-unacknowledged");
        let registration=agent::seed_unacknowledged(&service,label,case::name("telemetry-new-device"),json!({"capabilities":["inventory.collect.v1","task.execute.v1","telemetry.collect.v1","telemetry.counter.local.v1"],"platform":"macos","architecture":"aarch64","executionContext":software_execution::context(software_execution::Platform::MacOs)})).await?;
        let profile: wire::BindingProfile=serde_json::from_value(registration)?;
        ensure!(profile.capabilities.contains(&wire::Capability::TelemetryCounterLocalV1), "new counter capability must survive registration and activation");
        Ok((label.into(),profile.device_id.clone(),profile))
    }).await
}

#[path = "gaps.rs"]
mod gaps;

#[path = "performance.rs"]
mod performance;

#[tokio::test]
#[ignore = "MODULE=telemetry.ingress.postgres: tenant baseline uses real publication, content and authorization owners"]
async fn postgres_baseline_recovers_original_receipts_without_overwriting_edits() -> Result<()> {
    use sqlx::Connection;
    let requests: Vec<crate::setup::providers::telemetry::Request> =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TELEMETRY_PROVIDERS")?)?)?;
    ensure!(requests.len() == 1);
    let installation = &requests[0];
    crate::setup::providers::telemetry::prepare(installation.clone()).await?;
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["telemetry"] = serde_json::to_value(&installation.configuration)?;
    // Ordinary installation completes its baseline before the administrator sets up signing.
    base["task_signing"] = Value::Null;
    base["agent_pki"] = json!({"mode":"disabled"});
    let (initial, execution, runtime, _, resources) = baseline_application(&base).await?;
    let mut author = crate::test_support::authority::Authority::prepared_browser("admin")?;
    identity::seed_grants(
        case_tenant(),
        &prepared_subject(&author)?,
        vec![crate::authorization::Grant {
            operation: crate::authorization::Permission::ResourceWrite,
            scope: crate::authorization::Scope::Tenant,
        }],
    )
    .await?;
    resources
        .finish(partial_initialization_content(
            &base,
            &initial.browser,
            &mut author,
            &runtime,
            &execution.content,
        ))
        .await?;
    let manifest = crate::baseline::manifest::build(Uuid::parse_str(case_tenant())?)?;
    // This tenant's real provisioned administrator creates the grant and App intent
    // in the same transaction, exactly as target account provisioning does.
    let database: crate::config::Database =
        serde_json::from_value(base["access_database"].clone())?;
    let mut c = sqlx::PgConnection::connect_with(&database.options()?).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let (_, authority) = crate::authorization::baseline::grant_administrator_on(
        &mut tx,
        identity::user(case_tenant(), case_admin()),
        Uuid::new_v4(),
        manifest.targets(),
    )
    .await?;
    crate::baseline::reserve_on(&mut tx, &authority).await?;
    tx.commit().await?;
    c.close().await?;
    let (app, _, _, _, resources) = baseline_application(&base).await?;
    let router = app.browser;
    let (policy,completed)=resources.finish(async {
        resume_baseline(app.baseline).await?;
        let phase=pg(&format!("SELECT phase||':'||coalesce(blocked,'') FROM mdm_initialization.baselines WHERE tenant_id='{}'",case_tenant()))?;
        ensure!(phase.trim()=="configured:","baseline incomplete: {phase}");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_group.groups WHERE tenant_id='{}' AND kind='system'",case_tenant()))?.trim()=="3");
        let completed=pg(&format!("SELECT (SELECT count(*) FROM jsonb_object_keys(completed)) FROM mdm_initialization.baselines WHERE tenant_id='{}'",case_tenant()))?;
        ensure!(completed.trim().parse::<usize>()?==manifest.steps.len());
        let expected_policies=manifest.steps.iter().filter(|s|matches!(s.action,crate::baseline::manifest::Action::Policy{..})).count();
        let persisted=pg(&format!("SELECT count(*) FROM mdm_policy.policies p JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(p.tenant_id,p.current_version) JOIN mdm_policy.requests r ON r.tenant_id=p.tenant_id AND r.receipt->>'id'=p.id::text WHERE p.tenant_id='{}'",case_tenant()))?;
        ensure!(expected_policies>0 && persisted.trim().parse::<usize>()?==expected_policies,"baseline policies or original receipts missing");
        // A normal client cannot create system selectors.
        let (status,_)=author.call(&router,Method::POST,&format!("/api/v1/groups/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create_system","selector":"all_active","presentation":{"name":"client","description":""}}}))).await?;
        ensure!(status.is_client_error());
        let last=manifest.steps.last().unwrap();
        let policy=Uuid::parse_str(&last.target)?;
        let crate::baseline::manifest::Action::Policy {definition}=&last.action else {anyhow::bail!("last policy");};
        let mut administrator = crate::test_support::authority::Authority::prepared_browser("admin")?;
        let agent=manifest.steps.iter().find_map(|s|match &s.action {crate::baseline::manifest::Action::Policy{definition} if matches!(definition.action,rss_mdm_policy::Action::AgentCollection{..})=>Some(definition),_=>None}).unwrap();
        let (status,_)=administrator.call(&router,Method::POST,"/api/v1/policies/previews",Some(json!({"definition":agent,"scopeResult":null}))).await?;
        ensure!(status==StatusCode::CONFLICT,"unsigned baseline preview claimed execution readiness");
        let changed=post(&mut administrator,&router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","enabled":false,"definition":definition}})).await?;
        ensure!(changed["revision"]==2);
        // Lost App checkpoint after owner COMMIT; recovery must use the original
        // operation's receipt even when the user has since disabled this Policy.
        pg(&format!("UPDATE mdm_initialization.baselines SET phase='pending',completed=completed-'{key}' WHERE tenant_id='{tenant}'",key=last.key,tenant=case_tenant()))?;
        Ok((policy,completed))
    }).await?;
    let (restarted, _, _, _, resources) = baseline_application(&base).await?;
    resources.finish(async {
        resume_baseline(restarted.baseline).await?;
        ensure!(pg(&format!("SELECT phase FROM mdm_initialization.baselines WHERE tenant_id='{}'",case_tenant()))?.trim()=="configured");
        ensure!(pg(&format!("SELECT (SELECT count(*) FROM jsonb_object_keys(completed)) FROM mdm_initialization.baselines WHERE tenant_id='{}'",case_tenant()))?==completed);
        ensure!(pg(&format!("SELECT state||':'||revision FROM mdm_policy.policies WHERE tenant_id='{}' AND id='{policy}'",case_tenant()))?.trim()=="disabled:2");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_group.groups WHERE tenant_id='{}' AND kind='system'",case_tenant()))?.trim()=="3");
        Ok(())
    }).await
}

async fn partial_initialization_content(
    base: &Value,
    router: &Router,
    author: &mut Browser,
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
    content: &Option<Arc<rss_mdm_content_service::Store>>,
) -> Result<()> {
    use rss_mdm_content_service::service as content;
    use sqlx::Connection;
    let target = Uuid::new_v4();
    let blueprint = r::blueprints::catalog()
        .into_iter()
        .find(|b| {
            matches!(
                b.definition,
                r::blueprints::Definition::NativeCollection { .. }
            )
        })
        .unwrap();
    resource(
        author,
        router,
        target,
        0,
        json!({"action":"instantiate","blueprint":blueprint.id,"version":blueprint.version}),
    )
    .await?;
    let mut identity = crate::test_support::authority::Authority::from_config(base.clone()).await?;
    let resources = std::mem::take(&mut identity.resources);
    resources
        .finish(async {
            let mut c = sqlx::PgConnection::connect_with(
                &serde_json::from_value::<Config>(base.clone())?.access_options()?,
            )
            .await?;
            let mut tx = c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(case_tenant())
                .execute(&mut *tx)
                .await?;
            let (_, authority) = crate::authorization::baseline::grant_administrator_on(
                &mut tx,
                identity::user(case_tenant(), case_admin()),
                Uuid::new_v4(),
                [target.to_string()].into(),
            )
            .await?;
            tx.commit().await?;
            c.close().await?;
            let proof = authority.principal(&identity.authorization.clone()).await?;
            let audit = rss_mdm_audit_integration::RequestAudit::new(
                case_tenant().into(),
                "baseline_initialize",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            proof.bind_audit(&audit)?;
            let store = content.as_ref().unwrap();
            let budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
            let content_audit = Arc::new(
                identity
                    .audit
                    .on_runtime(runtime.clone(), identity.identity.tenant, &budget.control())
                    .await?,
            );
            let app = content::Access {
                sessions: crate::authorization::session::SessionAuthority::new(
                    identity.identity.authority.clone(),
                    identity.identity.tenant,
                ),
                authorization: identity.authorization.clone(),
                runtime: runtime.clone(),
                audit_store: content_audit,
                tenant: identity.identity.tenant,
                content: content.clone(),
                clock: Arc::new(crate::clock::ContentClock(Arc::new(
                    crate::clock::SystemClock,
                ))),
                catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(
                    identity.identity.tenant,
                )),
            };
            let operation = Uuid::new_v4();
            let selection = content::Selection {
                version: blueprint.label(),
                variant: "x86_64".into(),
                platform: blueprint.platform,
                architecture: r::Architecture::X86_64,
                artifact: Some(blueprint.definition.reference().into()),
                operation: Some(operation),
            };
            let bytes = blueprint.definition.canonical();
            let staged = content::begin_upload(
                &app,
                &proof,
                &audit,
                &target.to_string(),
                operation,
                &selection,
                store.upload_budget()?,
            )
            .await?;
            let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
            ensure!(
                store
                    .append(
                        &staged.binding.actor,
                        operation,
                        0,
                        now,
                        &bytes[..3],
                        store.upload_budget()?
                    )
                    .await?
                    .offset
                    == 3
            );
            content::upload(
                &app,
                content::UploadAuthority::initialization(&proof)?,
                &audit,
                &target.to_string(),
                &selection,
                bytes.as_slice(),
            )
            .await?;
            let done = store.status(&staged.binding.actor, operation, now).await?;
            ensure!(
                done.complete
                    && done.offset == bytes.len() as u64
                    && done.binding.sha256 == staged.binding.sha256
            );
            audit.finalize(None);
            Ok(())
        })
        .await
}

async fn baseline_application(
    base: &Value,
) -> Result<(
    crate::native::Routers,
    crate::execution_assembly::Assembly,
    Arc<rss_transactional_messaging_postgres::PgRuntime>,
    Arc<rss_mdm_flow_service::planning::Planning>,
    Resources,
)> {
    let config: Config = serde_json::from_value(base.clone())?;
    let access = database(base).await?;
    let audit = access.audit_store_fixture(&config.audit).await?;
    let (mut app, execution, runtime, planning, resources) = crate::api::application_fixture(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit,
    )
    .await?;
    app.browser = app
        .browser
        .layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
    Ok((app, execution, runtime, planning, resources))
}

async fn resume_baseline(registration: rss_runtime::ManagedTaskRegistration) -> Result<()> {
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    owner.startup()?.stage_task_with_token(registration);
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let phase = pg(&format!("SELECT phase||':'||coalesce(blocked,'') FROM mdm_initialization.baselines WHERE tenant_id='{}'", case_tenant()))?;
            if phase.trim() == "configured:" { return Ok::<_, anyhow::Error>(()); }
            ensure!(!phase.starts_with("blocked:"), "baseline blocked: {phase}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await;
    let cleanup = owner.shutdown().join().await?;
    result??;
    ensure!(cleanup.is_clean());
    Ok(())
}
