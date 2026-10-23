//! Product HTTP -> durable fanout -> real HTTPS, with response loss and restart-safe identities.
use crate::test_support::{http::*, process::*, runtime::*, *};
use rss_mdm_webhook_service::{events, model::*};
use sqlx::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

async fn receiver(
    listener: tokio::net::TcpListener,
    tls: tokio_rustls::TlsAcceptor,
) -> Result<Vec<(String, String, Vec<u8>)>> {
    let mut received = Vec::new();
    let mut lost = false;
    while received.len() < rss_mdm_webhook_service::PAGE as usize + 2 {
        let (socket, _) = listener.accept().await?;
        let mut socket = tls.accept(socket).await?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            ensure!(head.len() < 32768);
            head.push(socket.read_u8().await?);
        }
        let headers = String::from_utf8(head)?;
        let header = |name: &str| {
            headers.lines().find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.trim().to_owned())
            })
        };
        let length: usize = header("content-length")
            .ok_or_else(|| anyhow::anyhow!("missing body length"))?
            .parse()?;
        ensure!(length <= 64 * 1024);
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await?;
        let id = header("webhook-id").ok_or_else(|| anyhow::anyhow!("missing delivery id"))?;
        let time =
            header("webhook-timestamp").ok_or_else(|| anyhow::anyhow!("missing signature time"))?;
        let mut signed = format!("{id}.{time}.").into_bytes();
        signed.extend_from_slice(&body);
        use base64::Engine as _;
        let signature = base64::engine::general_purpose::STANDARD.encode(
            ring::hmac::sign(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[7; 32]),
                &signed,
            )
            .as_ref(),
        );
        ensure!(header("webhook-signature").as_deref() == Some(format!("v1,{signature}").as_str()));
        let path = headers
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_owned();
        received.push((path.clone(), id, body));
        if path == "/first" && !lost {
            lost = true;
            drop(socket);
        } else {
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
        }
    }
    Ok(received)
}
async fn call(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: i64,
    change: Value,
) -> Result<Value> {
    let (status, value) = browser
        .call(
            router,
            Method::PUT,
            path,
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"change":change})),
        )
        .await?;
    ensure!(status == StatusCode::OK, "{path}: {status} {value}");
    Ok(value)
}
// Hold authorization and prove a material request has not taken its later source partition.
async fn authorization_before_partition<T>(
    c: &mut sqlx::PgConnection,
    partition: &rss_transactional_messaging::message::PartitionIdentity,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    use anyhow::Context;
    let mut hold = c.begin().await?;
    rss_mdm_authorization_service::lock_on(&mut hold, case_tenant(), INSTANCE).await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_command_runtime' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%2363%')").fetch_one(&mut *hold).await?;
                if waiting { break; }
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::task::yield_now().await;
            }
            let row: Option<i32> = sqlx::query_scalar("SELECT 1 FROM rss_transactional_messaging.outbox_partitions WHERE tenant_id=$1::uuid AND domain=$2 AND partition_key=$3 FOR UPDATE NOWAIT")
                .bind(case_tenant()).bind(partition.domain().as_str()).bind(partition.key().as_str()).fetch_optional(&mut *hold).await?;
            ensure!(row == Some(1), "material request partition must exist and remain unlocked");
            Ok::<_, anyhow::Error>(())
        }).await;
        hold.rollback().await?;
        observed.context("material request must actually wait for authorization")??;
        Ok::<_, anyhow::Error>(())
    };
    let (result, released) = tokio::join!(operation, release);
    released?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=webhooks.product: real PG, management authorization, signed HTTPS and response-loss recovery"]
async fn subscription_versions_atomic_fanout_and_same_id_https_retry() -> Result<()> {
    use tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    };
    let root = std::path::PathBuf::from(std::env::var("SOURCE_T2_TLS")?);
    let address: std::net::IpAddr = std::env::var("SOURCE_T2_ADDRESS")?.parse()?;
    let listener = tokio::net::TcpListener::bind((address, 0)).await?;
    let port = listener.local_addr()?.port();
    let tls = ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_file(root.join("server.pem"))?],
        PrivateKeyDer::from_pem_file(root.join("server.key"))?,
    )?;
    let mut server = tokio::spawn(receiver(
        listener,
        tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
    ));
    let material = tempfile::tempdir()?;
    let key = material.path().join("webhook.key");
    use base64::Engine as _;
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(
        &key,
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode([7; 32])
        ),
    )?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["identity"]["tenant_id"] = json!(case_tenant());
    base["webhooks"]["networks"] = json!([{"tenant":case_tenant(),"reference":"receiver","hostname":"source.invalid","port":port,"addresses":[format!("{address}:{port}")],"cidrs":[format!("{address}/32")],"ca_files":[root.join("ca.pem")]}]);
    let config: Config = serde_json::from_value(base.clone())?;
    {
        let options = std::env::var("MDM_OWNER_URL")?
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?);
        let mut c = sqlx::PgConnection::connect_with(&options).await?;
        let mut tx = c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *tx)
            .await?;
        let protection = config.native_protector()?;
        let tenant = Uuid::parse_str(case_tenant())?;
        rss_mdm_webhook_service::materials::prepare(
            &mut tx,
            tenant,
            Uuid::new_v4(),
            &rss_mdm_webhook_service::materials::Prepare {
                reference: "receiver".into(),
                expected_revision: 0,
                configuration_sha256: config.webhooks.material_configuration()?,
                endpoint: format!("https://source.invalid:{port}/"),
                network_reference: "receiver".into(),
                source: rss_mdm_webhook_service::materials::Source::Import {
                    secret: std::fs::read_to_string(&key)?.into(),
                },
            },
            &protection,
        )
        .await?;
        // This case observes delivery, not material confirmation. Seed the legal confirmed state.
        sqlx::query("UPDATE mdm_webhook.key_materials SET confirmed=true,attempted_at=1,confirmed_at=1 WHERE tenant_id=$1 AND reference='receiver' AND revision=1")
            .bind(tenant).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_webhook.key_heads SET active_revision=1 WHERE tenant_id=$1 AND reference='receiver'")
            .bind(tenant).execute(&mut *tx).await?;
        tx.commit().await?;
        c.close().await?;
    }

    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let fence = format!(
        "SET LOCAL rss.storage_target='{}'; SET LOCAL rss.storage_lineage='{}'; SET LOCAL rss.execution_epoch='{}';",
        hex(&config.flow.storage.target),
        hex(&config.flow.storage.lineage),
        config.flow.storage.epoch
    );
    let access = database(&base).await?;
    let audit = access.audit_store_fixture(&config.audit).await?;
    let material_configuration = config.webhooks.material_configuration()?;
    let (router, execution, _, _, resources) = crate::api::application_fixture(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit,
    )
    .await?;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let backend = execution
        .webhooks
        .get()
        .ok_or_else(|| anyhow::anyhow!("missing product webhook assembly"))?
        .clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let mut worker = None;
    let result=async {
        use crate::authorization::{Grant, Permission, Scope};
        let grants = vec![Grant {operation:Permission::WebhookWrite,scope:Scope::Tenant}, Grant {operation:Permission::WebhookRead,scope:Scope::Tenant}, Grant {operation:Permission::WebhookReplay,scope:Scope::Tenant}, Grant {operation:Permission::InventoryRead,scope:Scope::AllDevices}];
        identity::set_grants(case_tenant(),case::admin(),grants.clone()).await?;
        let mut browser=Browser::default();ensure!(browser.login(&router,"admin").await?==StatusCode::OK);
        let partition = rss_mdm_audit_integration::source_partition(rss_request_context::TenantId::parse(case_tenant())?, "mdm", "request")?;
        let declared = partition.clone();
        execution.runtime.local_tx(rss_request_context::TenantId::parse(case_tenant())?, crate::webhooks::deadline(), move |tx| Box::pin(async move { tx.prepare_outbox_partitions(&[declared]).await })).await.fold(Ok, Err, Err, Err, Err, Err)?;
        let mut observer = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let material = json!({"reference":"lock-order", "expectedRevision":0, "configurationSha256":material_configuration, "endpoint":format!("https://source.invalid:{port}/"), "networkReference":"receiver", "source":{"kind":"generate"}});
        browser.operation = Some(Uuid::new_v4());
        let (status, prepared) = authorization_before_partition(&mut observer, &partition, browser.call(&router, Method::POST, "/api/v1/webhooks/materials", Some(material))).await?;
        ensure!(status == StatusCode::OK && prepared["revision"] == 1);
        pg(&format!("UPDATE mdm_webhook.key_materials SET confirmed=true,attempted_at=1,confirmed_at=1 WHERE tenant_id='{}' AND reference='lock-order' AND revision=1", case_tenant()))?;
        let activation = json!({"reference":"lock-order", "expectedRevision":1, "action":{"kind":"activate","materialRevision":1}});
        browser.operation = Some(Uuid::new_v4());
        let (status, active) = authorization_before_partition(&mut observer, &partition, browser.call(&router, Method::POST, "/api/v1/webhooks/materials/transitions", Some(activation))).await?;
        ensure!(status == StatusCode::OK && active["revision"] == 2 && active["activeRevision"] == 1);
        observer.close().await?;
        browser.operation = None;
        let device=case::name("webhook-device");pg(&format!("INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{}','{}')",case_tenant(),device))?;
        let tenant=Uuid::parse_str(case_tenant())?;
        let event=Event{event_id:Uuid::new_v4(),event_type:EventType::Registered,version:1,occurred_at:crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,tenant_id:tenant,device_id:device.to_owned(),data:EventData::Registration {registration_id:Uuid::new_v4(),generation:1,channel:"agent".into(),state:"active".into()}};
        let mut subscriptions=Vec::new();
        for index in 0..rss_mdm_webhook_service::PAGE + 1 {
            let name = match index { 0 => "first".to_owned(), 1 => "second".to_owned(), _ => format!("receiver-{index}") };
            let id=Uuid::new_v4();let path=format!("/api/v1/webhooks/subscriptions/{id}");
            let settings=json!({"presentation":{"name":name},"endpoint":format!("https://source.invalid:{port}/{name}"),"eventTypes":["device.registered"],"selection":{"kind":"allDevices"},"keyReference":"receiver","networkReference":"receiver"});
            if index == 0 {
                let request=json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"change":{"kind":"put","value":settings}});
                identity::set_grants(case_tenant(),case::admin(),vec![Grant {operation:Permission::WebhookWrite,scope:Scope::Tenant}]).await?;
                ensure!(browser.call(&router,Method::PUT,&path,Some(request.clone())).await?.0==StatusCode::FORBIDDEN);
                identity::set_grants(case_tenant(),case::admin(),vec![Grant {operation:Permission::WebhookWrite,scope:Scope::Tenant},Grant {operation:Permission::InventoryRead,scope:Scope::Device{id:device.to_owned()}}]).await?;
                ensure!(browser.call(&router,Method::PUT,&path,Some(request)).await?.0==StatusCode::FORBIDDEN,"one-device grant expanded to all devices");
                ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.subscriptions WHERE tenant_id='{tenant}' AND id='{id}'"))?.trim()=="0","denied create left a subscription");
                identity::set_grants(case_tenant(),case::admin(),grants.clone()).await?;
            }
            let created=call(&mut browser,&router,&path,0,json!({"kind":"put","value":settings})).await?;ensure!(created["enabled"]==false);
            let enabled=call(&mut browser,&router,&path,1,json!({"kind":"enabled","value":true})).await?;
            let mut rename=settings;rename["presentation"]["name"]=json!(format!("renamed-{name}"));
            let renamed=call(&mut browser,&router,&path,2,json!({"kind":"put","value":rename})).await?;ensure!(renamed["targetVersion"]==enabled["targetVersion"]);
            subscriptions.push((path,renamed));
        }
        let rollback_event=Event{event_id:Uuid::new_v4(),..event.clone()};let copied=rollback_event.clone();
        let rolled=execution.runtime.local_tx(rss_request_context::TenantId::parse(case_tenant())?,crate::webhooks::deadline(),move|tx|Box::pin(async move {events::emit_in(tx,copied).await.map_err(rss_transactional_messaging_postgres::PgError::from)?;Err::<(),_>(sqlx::Error::Protocol("deliberate business rollback".into()).into())})).await;
        ensure!(rolled.fold(|_|false,|_|false,|_|true,|_|false,|_|false,|_|false));
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.events WHERE id='{}'",rollback_event.event_id))?.trim()=="0");
        let copied=event.clone();execution.runtime.local_tx(rss_request_context::TenantId::parse(case_tenant())?,crate::webhooks::deadline(),move|tx|Box::pin(async move {events::emit_in(tx,copied).await.map_err(rss_transactional_messaging_postgres::PgError::from)})).await.fold(Ok,Err,Err,Err,Err,Err)?;
        // The integration belongs to the tenant even after its creator loses all business grants.
        identity::set_grants(case_tenant(),case::admin(),vec![]).await?;
        worker=Some(tokio::spawn(backend.clone().work(stop.clone())));
        let requests=match tokio::time::timeout(Duration::from_secs(30),&mut server).await {
            Ok(result)=>result??,
            Err(error)=>{
                let diagnostic=pg(&format!("SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT last_stage,last_reason,last_outcome,count(*) AS count FROM mdm_webhook.deliveries WHERE tenant_id='{tenant}' GROUP BY last_stage,last_reason,last_outcome) s"))?;
                anyhow::bail!("webhook receiver deadline: {error}; delivery stages: {diagnostic}");
            }
        };
        let first:Vec<_>=requests.iter().filter(|r|r.0=="/first").collect();ensure!(first.len()==2 && first[0].1==first[1].1 && first[0].2==first[1].2);
        ensure!(requests.iter().all(|r|serde_json::from_slice::<Value>(&r.2).ok().is_some_and(|v|v["eventId"]==event.event_id.to_string())));
        tokio::time::timeout(Duration::from_secs(10),async {loop {if pg(&format!("SELECT count(*) FROM mdm_webhook.deliveries d JOIN rss_transactional_messaging.outbox o ON(o.tenant_id,o.message_id)=(d.tenant_id,d.id::text) WHERE d.event_id='{}' AND o.status='published'",event.event_id))?.trim()==(rss_mdm_webhook_service::PAGE+1).to_string(){return Ok::<_,anyhow::Error>(())}tokio::time::sleep(Duration::from_millis(100)).await;}}).await??;
        stop.cancel();
        if let Some(mut task)=worker.take() {
            match tokio::time::timeout(Duration::from_secs(20),&mut task).await {
                Ok(result) => { result??; }
                Err(_) => {task.abort();let _=task.await;return Err(anyhow::anyhow!("webhook relay shutdown timed out"));}
            }
        }
        identity::set_grants(case_tenant(),case::admin(),grants.clone()).await?;
        let test_path=format!("{}/test",subscriptions[0].0);
        let test_request=json!({"operationId":Uuid::new_v4(),"deviceId":device});
        let (status,test_receipt)=browser.call(&router,Method::POST,&test_path,Some(test_request.clone())).await?;
        ensure!(status==StatusCode::OK);
        let (status,list)=browser.call(&router,Method::GET,"/api/v1/webhooks/deliveries",None).await?;ensure!(status==StatusCode::OK && list["items"].as_array().is_some_and(|i|i.len()==rss_mdm_webhook_service::PAGE as usize));
        let next=list["nextCursor"].as_str().ok_or_else(||anyhow::anyhow!("missing delivery cursor"))?;
        let page=browser.call(&router,Method::GET,&format!("/api/v1/webhooks/deliveries?after={next}"),None).await?;
        ensure!(page.0==StatusCode::OK && page.1["items"].as_array().is_some_and(|items|items.len()==2));
        let disabled=call(&mut browser,&router,&subscriptions[0].0,3,json!({"kind":"enabled","value":false})).await?;
        ensure!(disabled["targetVersion"]!=subscriptions[0].1["targetVersion"]);
        let retried=browser.call(&router,Method::POST,&test_path,Some(test_request)).await?;
        ensure!(retried.0==StatusCode::OK && retried.1==test_receipt, "committed test receipt must survive disable");
        let stale_id:Uuid=serde_json::from_value(test_receipt["id"].clone())?;
        let denied=execution.runtime.local_tx(rss_request_context::TenantId::parse(case_tenant())?,crate::webhooks::deadline(),move|tx|Box::pin(async move {tx.with_connection(move|c|Box::pin(async move {Ok(matches!(rss_mdm_webhook_service::storage::binding(c,tenant,stale_id).await,Err(rss_mdm_webhook_service::Error::Denied)))})).await})).await.fold(Ok,Err,Err,Err,Err,Err)?;
        ensure!(denied,"disabled target remained eligible for sending");
        // Exercise the real RSS recovery role and request audit after its separate intent transaction.
        let source=events::identity(event.event_id,&format!("{}:{}:automatic",subscriptions[1].0.rsplit('/').next().unwrap(),subscriptions[1].1["targetVersion"].as_i64().unwrap()));
        pg(&format!("{fence} UPDATE rss_transactional_messaging.outbox SET status='dead_letter',automatic_retry_deadline=clock_timestamp()+interval '1 hour',lease_token=NULL,lease_until=NULL WHERE tenant_id='{tenant}' AND message_id='{source}'"))?;
        let replay_path=format!("/api/v1/webhooks/deliveries/{source}/replay");
        let replay_request=json!({"operationId":Uuid::new_v4()});
        let replayed=browser.call(&router,Method::POST,&replay_path,Some(replay_request.clone())).await?;
        ensure!(replayed.0==StatusCode::OK && replayed.1["id"]!=source.to_string() && replayed.1["eventId"]==event.event_id.to_string() && replayed.1["sourceDelivery"]==source.to_string());
        ensure!(browser.call(&router,Method::POST,&replay_path,Some(replay_request.clone())).await?==replayed);
        let recovery_path=format!("/api/v1/webhooks/deliveries/{source}/redrive");
        let recovery_request=json!({"operationId":Uuid::new_v4(),"expectedVersion":1});
        let recovered=browser.call(&router,Method::POST,&recovery_path,Some(recovery_request.clone())).await?;
        ensure!(recovered.0==StatusCode::OK && recovered.1["recoveryVersion"]==2, "redrive failed: {recovered:?}");
        ensure!(browser.call(&router,Method::POST,&recovery_path,Some(recovery_request)).await?==recovered);
        let stale=browser.call(&router,Method::POST,&recovery_path,Some(json!({"operationId":Uuid::new_v4(),"expectedVersion":1}))).await?;
        ensure!(stale.0==StatusCode::CONFLICT);

        call(&mut browser,&router,&subscriptions[1].0,3,json!({"kind":"enabled","value":false})).await?;
        let delivery_count=pg("SELECT count(*) FROM mdm_webhook.deliveries WHERE tenant_id=current_setting('rss.tenant_id')::uuid")?;
        ensure!(browser.call(&router,Method::POST,&replay_path,Some(replay_request.clone())).await?==replayed,"committed replay receipt must survive disable");
        let changed_path=format!("/api/v1/webhooks/deliveries/{stale_id}/replay");
        ensure!(browser.call(&router,Method::POST,&changed_path,Some(replay_request.clone())).await?.0==StatusCode::CONFLICT);
        ensure!(browser.call(&router,Method::POST,&replay_path,Some(json!({"operationId":Uuid::new_v4()}))).await?.0==StatusCode::FORBIDDEN,"new replay ignored retired target");
        let another=case::name("another-device");
        pg(&format!("INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{tenant}','{another}')"))?;
        let limited=vec![Grant {operation:Permission::WebhookRead,scope:Scope::Tenant},Grant {operation:Permission::WebhookReplay,scope:Scope::Tenant},Grant {operation:Permission::InventoryRead,scope:Scope::Device{id:another.to_owned()}}];
        identity::set_grants(case_tenant(),case::admin(),limited).await?;
        ensure!(browser.call(&router,Method::GET,&format!("/api/v1/webhooks/deliveries/{source}"),None).await?.0==StatusCode::NOT_FOUND);
        ensure!(browser.call(&router,Method::POST,&replay_path,Some(replay_request)).await?.0==StatusCode::FORBIDDEN,"receipt bypassed current event read permission");
        ensure!(pg("SELECT count(*) FROM mdm_webhook.deliveries WHERE tenant_id=current_setting('rss.tenant_id')::uuid")?==delivery_count,"denied/repeated replay created delivery");
        identity::set_grants(case_tenant(),case::admin(),identity::device_grants(None,&["inventory_read"])?).await?;
        ensure!(browser.call(&router,Method::GET,"/api/v1/webhooks/subscriptions",None).await?.0==StatusCode::FORBIDDEN);
        identity::set_grants(case_tenant(),case::admin(),grants).await?;
        let foreign=Uuid::new_v4();
        pg(&format!("INSERT INTO mdm_webhook.subscriptions(tenant_id,id,revision,target_version,enabled,deleted,settings) SELECT (SELECT management_tenant_id FROM public.mdm_installation),'{foreign}',1,1,false,false,settings FROM mdm_webhook.subscriptions WHERE tenant_id='{tenant}' AND id='{}'",subscriptions[0].0.rsplit('/').next().unwrap()))?;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.subscriptions WHERE tenant_id<>'{tenant}' AND id='{foreign}' AND revision=1"))?.trim()=="1","missing real foreign subscription");
        let foreign_path=format!("/api/v1/webhooks/subscriptions/{foreign}");
        ensure!(browser.call(&router,Method::GET,&foreign_path,None).await?.0==StatusCode::NOT_FOUND);
        ensure!(browser.call(&router,Method::PUT,&foreign_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"change":{"kind":"enabled","value":false}}))).await?.0==StatusCode::CONFLICT);
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.subscriptions WHERE tenant_id='{tenant}' AND id='{foreign}'"))?.trim()=="0");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_webhook.subscriptions WHERE tenant_id<>'{tenant}' AND id='{foreign}' AND revision=1"))?.trim()=="1","cross-tenant request mutated foreign subscription");
        let (status,_)=Browser::default().call(&router,Method::GET,"/api/v1/webhooks/subscriptions",None).await?;ensure!(status==StatusCode::UNAUTHORIZED);
        Ok::<_,anyhow::Error>(())
    }.await;
    stop.cancel();
    if let Some(mut task) = worker
        && tokio::time::timeout(Duration::from_secs(20), &mut task)
            .await
            .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    if !server.is_finished() {
        server.abort();
        let _ = server.await;
    }
    resources.finish(async { result }).await
}
