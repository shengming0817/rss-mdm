//! Lost commit acknowledgements are injected after a real durable PostgreSQL commit.
use super::*;

pub(super) async fn receive_commit_unknown(f: &mut Fixture, body: &Value) -> Result<()> {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    use rss_transactional_messaging_postgres::{
        PgConfig, PgPassword, PgPrivateCa, PgRuntime, PgTransactionFault,
    };
    let input: wire::TelemetryUpload = serde_json::from_value(body.clone())?;
    let mut authority = authority::Authority::from_config(f.base.clone()).await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let agent=agent::service(&authority).await?;
        let principal=agent.authenticate(&agent::evidence(case_credential()).unwrap()).await?;
        let config:crate::flow::Config=serde_json::from_value(f.base["flow"].clone())?;
        let database=&config.storage.database;
        let binding=ExecutionBinding::new(StorageIdentity::new(config.storage.target,config.storage.lineage)?,vec![(f.planning.tenant,Epoch::new(config.storage.epoch)?)])?;
        let pg_config=PgConfig::new(&database.host,database.port,&database.name,&database.user,
            PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
            PgPrivateCa::from_pem(crate::config::read(&database.ca_file,1024*1024,false)?.to_vec())?);
        // This runtime has no relay or maintenance tasks: the injection belongs only
        // to the receiving transaction, rather than racing a shared background pool.
        let runtime=Arc::new(PgRuntime::connect_producer(pg_config,crate::lifecycle::RuntimeTimer,binding).await?);
        let planning=Arc::new(rss_mdm_flow_service::planning::Planning::new(f.planning.audit_store.clone(),runtime.clone(),f.planning.tenant,
            f.planning.clock.clone(),&[9;32],f.planning.objects.clone()).await?);
        let config:crate::telemetry::Config=serde_json::from_value(f.base["telemetry"].clone())?;
        let service=Arc::new(rss_mdm_telemetry_service::Service::new(f.planning.tenant,runtime.clone(),planning,config.open_backend(f.planning.tenant).await?,f.execution.clone(),config.ingress.clone(),
            rss_mdm_telemetry_service::StorageBudget {points:config.limits.max_points,series:config.limits.max_series,bytes:config.limits.max_bytes})?);
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
        let result=async {
            ensure!(matches!(service.receive(&principal,&input,serde_json::to_vec(&input)?.len()).await,Err(rss_mdm_telemetry_service::Error::Unknown)));
            ensure!(pg(&format!("SELECT count(*) FROM mdm_telemetry.batches WHERE tenant_id='{}' AND id='{}'",case_tenant(),input.batch_id))?.trim()=="1","lost commit acknowledgement must leave original durable receipt");
            let receipt=service.status(&principal,input.batch_id).await?;
            ensure!(serde_json::to_value(receipt)?["batchId"]==input.batch_id.to_string());
            let replay=service.receive(&principal,&input,serde_json::to_vec(&input)?.len()).await?;
            ensure!(serde_json::to_value(replay)?["replayed"]==true);
            Ok(())
        }.await;
        let closed=service.close(rss_request_context::Deadline::from_timeout(&rss_mdm_telemetry_service::backend::SystemClock,Duration::from_secs(10))?).await;
        runtime.close().await;
        closed?;
        result
    }).await
}

/// Force a real local transaction rollback only after the other database accepted its batch.
/// The host is then closed by the caller while RSS retains the unconfirmed delivery.
pub(super) async fn interrupt_after_backend_write(
    f: &mut Fixture,
    original: &Value,
) -> Result<Value> {
    let mut body = original.clone();
    let id = Uuid::new_v4();
    let observation = Uuid::new_v4();
    body["batchId"] = json!(id);
    body["observations"][0]["id"] = json!(observation);
    body["observations"][0]["sequence"] = json!(0);
    body["observations"][0]["observedAt"] =
        json!(original["observations"][0]["observedAt"].as_i64().unwrap() - 10_000_000);
    pg(&format!(
        "CREATE FUNCTION public.interrupt_telemetry_delivery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='{id}'::uuid AND NEW.delivery='published' THEN RAISE EXCEPTION 'fixture interruption after destination write' USING ERRCODE='40001'; END IF; RETURN NEW; END $$; CREATE TRIGGER interrupt_telemetry_delivery BEFORE UPDATE ON mdm_telemetry.batches FOR EACH ROW EXECUTE FUNCTION public.interrupt_telemetry_delivery();"
    ))?;
    ensure!(
        agent_call(
            &f.router,
            Method::POST,
            "/api/v1/agent/runtime/telemetry/batches",
            Some(case_credential()),
            Some(body.clone())
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = agent_call(
                &f.router,
                Method::GET,
                &format!("/api/v1/agent/runtime/telemetry/batches/{id}"),
                Some(case_credential()),
                None,
            )
            .await?;
            ensure!(status.0 == StatusCode::OK);
            if status.1["delivery"] == "unknown" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    history_is_unique(&mut f.author, &f.router, &body).await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{observation}'",case_tenant()))?.trim()=="0","current effect committed despite local interruption");
    Ok(body)
}
pub(super) fn release_interruption() -> Result<()> {
    pg(
        "DROP TRIGGER interrupt_telemetry_delivery ON mdm_telemetry.batches; DROP FUNCTION public.interrupt_telemetry_delivery();",
    )?;
    Ok(())
}
pub(super) async fn history_is_unique(
    author: &mut Browser,
    router: &Router,
    body: &Value,
) -> Result<()> {
    let time = body["observations"][0]["observedAt"].as_i64().unwrap();
    let history=post(author,router,"/api/v1/telemetry/history",json!({"device":case_device_id(),"field":"custom.corporate_agent.healthy","resource":"device","startMicros":time,"endMicros":time+1,"maxPoints":64,"mode":"history","after":null})).await?;
    ensure!(
        history["rows"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1),
        "recovery duplicated or lost durable destination: {history}"
    );
    Ok(())
}

pub(super) async fn foreign_session_cannot_read(f: &mut Fixture, query: &Value) -> Result<()> {
    let mut base = f.base.clone();
    base["identity"]["tenant_id"] = json!(case::peer());
    let authority = authority::Authority::from_config(base).await?;
    let mut browser = authority.browser("admin")?;
    let own_router = authority.router(authority.authorization())?;
    authority
        .resources
        .finish(async {
            // The foreign session is live and valid in its own tenant.
            ensure!(!browser_subject(&browser, &own_router).await?.is_empty());
            let response = browser
                .call(
                    &f.router,
                    Method::POST,
                    "/api/v1/telemetry/history",
                    Some(query.clone()),
                )
                .await?;
            ensure!(
                matches!(response.0, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
                "foreign tenant read real history: {response:?}"
            );
            Ok(())
        })
        .await
}
