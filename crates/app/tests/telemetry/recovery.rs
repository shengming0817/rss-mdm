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
        let budget=rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit=Arc::new(f.planning.audit_store.on_runtime(runtime.clone(),f.planning.tenant,&budget.control()).await?);
        let planning=Arc::new(rss_mdm_flow_service::planning::Planning::new(audit,runtime.clone(),f.planning.tenant,
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
    body["observations"][0]["sequence"] = json!(3);
    body["observations"][0]["observedAt"] =
        json!(original["observations"][0]["observedAt"].as_i64().unwrap());
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
    // Make this series genuinely due while its accepted batch is still unsettled.
    let due = original["observations"][0]["observedAt"].as_i64().unwrap() + 26_000_000;
    // Intake must occur inside the raw window. Only then does elapsed wall time
    // make the older sample expire, while the two recent samples remain inside
    // the cutoff fixed by this due time.
    tokio::time::timeout(Duration::from_secs(40), async {
        while f.planning.clock.unix_seconds()? * 1_000_000 < due {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let target = retention_target();
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_telemetry.retention_targets WHERE {target}"
        ))?
        .trim()
            == "1"
    );
    pg(&format!(
        "UPDATE mdm_telemetry.retention_targets SET due_at={due},next_check=0 WHERE {target}"
    ))?;
    wait_retention("result->>'reason'='accepted_batches_pending' AND phase=0").await?;
    history_is_unique(&mut f.author, &f.router, &body).await?;
    // Keep the frozen due time but hold the next attempt until restart assertions finish.
    pg(&format!(
        "UPDATE mdm_telemetry.retention_targets SET next_check=9223372036854775807 WHERE {target}"
    ))?;
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
    let foreign_identity = authority.identity.clone();
    authority
        .resources
        .finish(async {
            // The foreign session is live and valid in its own tenant.
            foreign_identity
                .authority
                .inspect_session(
                    foreign_identity.tenant,
                    identity::credential(&foreign_identity, "admin")?,
                    crate::identity::deadline(),
                )
                .await?;
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

fn retention_target() -> String {
    format!(
        "tenant_id='{}' AND device='{}' AND field='custom.corporate_agent.healthy' AND resource='device'",
        case_tenant(),
        case_device_id()
    )
}
async fn wait_retention(condition: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if pg(&format!(
                "SELECT count(*) FROM mdm_telemetry.retention_targets WHERE {} AND ({condition})",
                retention_target()
            ))?
            .trim()
                == "1"
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await??;
    Ok(())
}
/// Drive the real background scheduler through cutoff and prune after the pending batch settles.
pub(super) async fn retention_finishes(
    author: &mut Browser,
    router: &Router,
    old: &Value,
    recent: &Value,
) -> Result<()> {
    let target = retention_target();
    let due = pg(&format!(
        "SELECT due_at FROM mdm_telemetry.retention_targets WHERE {target}"
    ))?;
    let due: i64 = due.trim().parse()?;
    for phase in [1, 0] {
        pg(&format!(
            "UPDATE mdm_telemetry.retention_targets SET next_check=0 WHERE {target}"
        ))?;
        let condition = if phase == 1 {
            format!("phase=1 AND due_at={due} AND result->>'state'='complete'")
        } else {
            format!(
                "phase=0 AND due_at>{due} AND next_check=due_at AND result->>'state'='complete'"
            )
        };
        wait_retention(&condition).await?;
    }
    let time = old["observations"][0]["observedAt"].as_i64().unwrap();
    let expired=post(author,router,"/api/v1/telemetry/history",json!({"device":case_device_id(),"field":"custom.corporate_agent.healthy","resource":"device","startMicros":time,"endMicros":time+1,"maxPoints":64,"mode":"history","after":null})).await?;
    ensure!(
        expired["rows"].as_array().is_some_and(Vec::is_empty),
        "expired sample survived automatic retention: {expired}"
    );
    let retained = post(author, router, "/api/v1/telemetry/history", recent.clone()).await?;
    ensure!(
        retained["rows"]
            .as_array()
            .is_some_and(|rows| rows.len() == 2),
        "automatic retention removed unexpired samples: {retained}"
    );
    Ok(())
}

/// Both actual collection producers share source ordering but own different datasets.
pub(super) async fn cross_dataset_sequence(
    f: &Fixture,
    field: &rss_mdm_inventory::FieldDefinition,
) -> Result<()> {
    use rss_mdm_inventory::{CollectionDefinition, CollectionField, CollectionScope, Source};
    use rss_observation::{Batch, Body, Change, Id};
    use sqlx::{Connection, Row};
    let mut authority = authority::Authority::from_config(f.base.clone()).await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let service=agent::service(&authority).await?;
        let principal=service.authenticate(&agent::evidence(case_credential()).unwrap()).await?;
        let tenant=principal.tenant();let registration=principal.registration();
        let mut inspect=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let (epoch,sequence):(Uuid,i64)=sqlx::query_as("SELECT epoch,next_sequence FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='agent.script'")
            .bind(tenant.to_string()).bind(registration).fetch_one(&mut inspect).await?;
        inspect.close().await?;
        let fields=vec![CollectionField{definition:field.clone(),scope:CollectionScope::Device}];
        let enterprise=CollectionDefinition::new("inventory",format!("collision-{}",Uuid::new_v4()),Source::AgentScript,fields.clone())?;
        let periodic=CollectionDefinition::new(&format!("telemetry.{}",Uuid::new_v4()),"v1",Source::AgentScript,fields)?;
        let scope=crate::device::scope_dataset(tenant,registration,"agent.script",epoch,periodic.dataset())?;
        let now=f.planning.clock.unix_seconds()?;
        let batch=Batch::new(Id::new(Uuid::new_v4().to_string())?,sequence as u64,rss_contract::Timepoint::try_from(now)?,periodic.coverage()?,
            Body::Snapshot(vec![Change::upsert(Id::new(field.key.as_str())?,rss_mdm_inventory::CollectedValue::Value(rss_mdm_inventory::Scalar::Boolean(true)).encode(field)?)]))?;
        let attempt=Uuid::new_v4();
        let barrier=Arc::new(tokio::sync::Barrier::new(2));
        let mut a=sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?).await?;
        let mut b=sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?).await?;
        let reserve=async {
            let mut tx=a.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
            barrier.wait().await;
            crate::collection::enterprise::start_in(&mut tx,tenant,registration,Uuid::new_v4(),attempt,enterprise,now).await?;
            tx.commit().await?;anyhow::Ok(())
        };
        let receive=async {
            let mut tx=b.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
            barrier.wait().await;
            crate::collection::telemetry::accept_on(&mut tx,&scope,&periodic,&batch,now).await?;
            tx.commit().await?;anyhow::Ok(())
        };
        let (reserved,received)=tokio::join!(reserve,receive);reserved?;received?;
        let mut tx=b.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
        let rows=sqlx::query("SELECT sequence,scope::jsonb->>'dataset' AS dataset FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND (id=$2 OR id=$3)")
            .bind(tenant.to_string()).bind(attempt).bind(Uuid::parse_str(batch.id().as_str())?).fetch_all(&mut *tx).await?;
        ensure!(rows.len()==2 && rows.iter().all(|r|r.get::<i64,_>("sequence")==sequence));
        ensure!(rows[0].get::<String,_>("dataset")!=rows[1].get::<String,_>("dataset"));
        crate::collection::telemetry::accept_on(&mut tx,&scope,&periodic,&batch,now).await?;
        tx.commit().await?;
        let conflicting=Batch::new(Id::new(Uuid::new_v4().to_string())?,batch.sequence(),rss_contract::Timepoint::try_from(batch.observed_at_seconds())?,periodic.coverage()?,batch.body().clone())?;
        let mut tx=b.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
        ensure!(crate::collection::telemetry::accept_on(&mut tx,&scope,&periodic,&conflicting,now).await.is_err(),"same full stream accepted a duplicate sequence");
        tx.rollback().await?;a.close().await?;b.close().await?;
        Ok(())
    }).await
}
