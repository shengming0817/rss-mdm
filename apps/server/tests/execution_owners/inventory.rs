use super::*;
use rss_mdm_inventory::*;
use rss_mdm_inventory_service::collection::enterprise;
#[tokio::test]
#[ignore = "T2: Inventory reserves original attempts, rejects owner mismatch, and seals once before asset projection"]
async fn original_attempt_reservation_and_report_are_atomic_and_independent_of_projection()
-> anyhow::Result<()> {
    let h = Harness::open().await?;
    let field = FieldDefinition {
        time_series: None,
        key: FieldKey::parse("custom.script.healthy")?,
        version: 1,
        value_type: ValueType::Boolean,
        nullable: false,
        manual: false,
        sources: [(Source::AgentScript, 0)].into(),
        platforms: [Platform::Windows].into(),
        sensitivity: Sensitivity::Standard,
        unit: None,
        searchable: true,
        item_key: None,
    };
    let key = field.key;
    let definition = CollectionDefinition::new(
        "script-health",
        1,
        Source::AgentScript,
        vec![CollectionField {
            definition: field,
            scope: CollectionScope::Device,
        }],
    )?;
    let task = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let sentinel = Uuid::new_v4();
    let tenant = h.c.tenant;
    let registration = h.p.device().to_owned();
    let at = now();
    let mut tx = command::seed_transaction(&h.c).await?;
    anyhow::ensure!(
        rss_mdm_inventory_postgres::publish_field_in(
            &mut tx,
            tenant,
            0,
            definition.fields().next().unwrap()
        )
        .await?,
        "custom field seed"
    );
    sqlx::query("INSERT INTO mdm_access.report_sources (tenant_id, device, source, epoch, enabled) VALUES (CAST($1 AS uuid), $2, 'agent.script', $3, TRUE)").bind(tenant.to_string()).bind(&registration).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;

    let start_device = registration.clone();
    script::transaction::run(
        &h.audit,
        &h.a.resources.storage.runtime,
        tenant,
        &request(&h.c),
        definition.clone(),
        move |definition, tx| {
            Box::pin(async move {
                let definition = definition.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        enterprise::start_in(
                            c,
                            tenant,
                            start_device.clone(),
                            task,
                            attempt,
                            definition.clone(),
                            at,
                        )
                        .await?;
                        enterprise::start_in(
                            c,
                            tenant,
                            start_device.clone(),
                            task,
                            sentinel,
                            definition,
                            at,
                        )
                        .await
                    })
                })
                .await?;
                Ok(())
            })
        },
    )
    .await?;
    let progress = CollectionProgress::native(
        definition,
        [(
            key,
            NativeValue::Value(CollectedValue::Value(Scalar::Boolean(true))),
        )]
        .into(),
        at,
    )?;
    let accept = |task| {
        let registration = registration.clone();
        let progress = progress.clone();
        let audit = request(&h.c);
        let h = &h;
        async move {
            script::transaction::run(
                &h.audit,
                &h.a.resources.storage.runtime,
                tenant,
                &audit,
                progress,
                move |progress, tx| {
                    Box::pin(async move {
                        let progress = progress.clone();
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                enterprise::accept_in(
                                    c,
                                    tenant,
                                    enterprise::Report {
                                        device: registration.to_string(),
                                        task,
                                        attempt,
                                        progress,
                                        now: now(),
                                        observed_at: at,
                                        project: true,
                                        trusted: true,
                                    },
                                )
                                .await
                            })
                        })
                        .await?;
                        Ok(())
                    })
                },
            )
            .await
        }
    };
    assert!(accept(Uuid::new_v4()).await.is_err());
    let row = |attempt| {
        sqlx::query_as::<_,(Option<i64>,Option<Vec<u8>>,bool)>("SELECT sealed_at,batch,delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(attempt).fetch_one(&h.c.operator)
    };
    assert_eq!(row(attempt).await?, (None, None, false));
    accept(task).await?;
    let sealed = row(attempt).await?;
    assert!(sealed.0.is_some() && sealed.1.is_some() && sealed.2);
    assert_eq!(row(sentinel).await?, (None, None, false));
    accept(task).await?;
    assert_eq!(row(attempt).await?, sealed);
    h.close().await
}

#[tokio::test]
#[ignore = "T2: native cleanup derives sent task certainty from Inventory reports without a second terminal state"]
async fn native_cleanup_distinguishes_complete_failure_from_unconfirmed_report()
-> anyhow::Result<()> {
    let h = Harness::open().await?;
    for reason in ["complete", "timeout", "revoked"] {
        let (_, task, object) = super::retirement::native(&h, Some(reason)).await?;
        let registrations = object
            .members
            .iter()
            .map(|m| m.device.clone())
            .collect::<Vec<_>>();
        let mut tx = command::seed_transaction(&h.c).await?;
        let progress = rss_mdm_inventory_service::collection::execution::retirement::progress_on(
            &mut tx,
            &h.c.tenant.to_string(),
            &registrations,
        )
        .await?;
        tx.rollback().await?;
        assert_eq!(
            progress,
            if reason == "complete" {
                (false, None)
            } else {
                (true, Some(task))
            }
        );
    }
    h.close().await
}
#[tokio::test]
#[ignore = "T2: native metadata detail needs InventoryRead while Agent raw detail retains sensitive authorization"]
async fn native_detail_does_not_require_raw_evidence_permission() -> anyhow::Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::Reads;
    let h = Harness::open().await?;
    let (policy, task, _) = super::retirement::native(&h, Some("complete")).await?;
    let account =
        h.c.account(&[
            Permission::PolicyRead,
            Permission::OperationRead,
            Permission::InventoryRead,
        ])
        .await?;
    let proof = std::sync::Arc::new(h.c.authenticate(&account).await?);
    let detail = Reads::run(
        h.a.task_reads.as_ref(),
        &h.c.read_auth(proof.clone()),
        &h.c.request(&proof)?,
        policy,
        task,
    )
    .await?;
    let detail = serde_json::to_value(detail)?;
    assert_eq!(detail["channel"], "mdm");
    assert_eq!(detail["report"]["reason"], "complete");
    assert!(detail.get("native").is_none());
    let (d, f, _) = super::mixed::agent(&h)?;
    let policy = Uuid::new_v4();
    let v = super::mixed::publish(&h, policy, 1, d, f).await?;
    let task = super::mixed::run(&h, v, now()).await?;
    assert!(matches!(
        Reads::run(
            h.a.task_reads.as_ref(),
            &h.c.read_auth(proof.clone()),
            &h.c.request(&proof)?,
            policy,
            task
        )
        .await,
        Err(rss_mdm_management_http::Error::Forbidden)
    ));
    h.close().await
}

#[tokio::test]
#[ignore = "T2: Collection assignment interval follows actual starts and new versions without writing or reusing historical success"]
async fn periodic_assignment_uses_actual_start_and_exact_current_version() -> anyhow::Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::Reads;
    let h = Harness::open().await?;
    let result=async {
        let (definition,frozen,template)=super::mixed::agent(&h)?;
        let announcement=w::TaskClaimRequest::new(Uuid::new_v4(),vec![w::ExecutorProfile::PowerShell7],context())?
            .with_environment(rss_mdm_agent_wire::CollectionEnvironment{edition:None,tools:Default::default(),native_engines:template.spec().plan.requirements()})?;
        assert!(h.delivery.claim(&h.p,&announcement,&request(&h.c)).await?.task().is_none());
        let mut tx=command::seed_transaction(&h.c).await?;
        sqlx::query("INSERT INTO mdm_access.report_sources (tenant_id, device, source, epoch, enabled) VALUES (CAST($1 AS uuid), $2, 'agent.native', $3, TRUE) ON CONFLICT (tenant_id, device, source) DO UPDATE SET enabled = TRUE").bind(h.c.tenant.to_string()).bind(h.p.device()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
        tx.commit().await?;
        let policy=Uuid::new_v4();
        let version=super::mixed::publish(&h,policy,1,definition.clone(),frozen.clone()).await?;
        let account=h.c.account(&[Permission::PolicyRead,Permission::InventoryRead,Permission::OperationRead]).await?;
        let proof=std::sync::Arc::new(h.c.authenticate(&account).await?);
        let query=rss_mdm_policy::pages::ASSIGNMENTS_SCHEMA.page(Some(10),None,4096)?;
        let codec=rss_mdm_query::cursor::CursorCodec::new(&[9;32])?;
        let read=||async {Ok::<Value,anyhow::Error>(serde_json::to_value(Reads::assignments(h.a.task_reads.as_ref(),&h.c.read_auth(proof.clone()),&h.c.request(&proof)?,policy,&query,&codec).await?)?)};
        let first=read().await?;
        assert_eq!(first["items"][0]["taskAdmission"]["state"],"waiting_check_in");
        assert!(first["items"][0]["execution"]["latestRun"].is_null());
        assert_eq!(first["items"][0]["execution"]["currentRecord"]["state"],"absent");
        let created=now()-180;
        let triggered=now()-90;
        let started=now()-30;
        let task=super::mixed::run(&h,version,created).await?;
        let mut state=rss_mdm_task_state::RunState::new(created+300,created)?;
        state.started_at=Some(started);
        state.execution=rss_mdm_task_state::Execution::Succeeded;
        let mut tx=command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE mdm_inventory.collection_tasks SET agent_state=$3,triggered_at=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(task).bind(serde_json::to_value(state)?).bind(triggered).execute(&mut *tx).await?;
        tx.commit().await?;
        let waiting=read().await?;
        assert_eq!(waiting["items"][0]["taskAdmission"]["state"],"interval_not_elapsed");
        assert_eq!(waiting["items"][0]["taskAdmission"]["nextAllowedStartAt"],started+3600);
        assert_eq!(waiting["items"][0]["execution"]["latestRun"]["taskId"],task.to_string());
        assert_eq!(waiting["items"][0]["execution"]["latestRun"]["state"]["execution"],"succeeded");
        // Move the minimal historical fixture to a legal completed run whose interval is now due.
        let created=created-3600;
        let triggered=triggered-3600;
        let started=started-3600;
        let mut completed=rss_mdm_task_state::RunState::new(created+300,created)?;
        completed.started_at=Some(started);
        completed.execution=rss_mdm_task_state::Execution::Succeeded;
        let mut tx=command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE mdm_inventory.collection_tasks SET created_at=$3,available_at=$3,deadline=$4,triggered_at=$5,agent_state=$6 WHERE tenant_id=$1::uuid AND id=$2")
            .bind(h.c.tenant.to_string()).bind(task).bind(created).bind(created+300).bind(triggered).bind(serde_json::to_value(completed)?).execute(&mut *tx).await?;
        tx.commit().await?;
        let due=read().await?;
        assert_eq!(due["items"][0]["taskAdmission"]["state"],"waiting_check_in");
        assert!(due["items"][0]["taskAdmission"].get("nextAllowedStartAt").is_none());
        assert_eq!(due["items"][0]["execution"]["currentRecord"]["state"],"unknown");
        assert_eq!(due["items"][0]["execution"]["latestRun"]["taskId"],task.to_string());
        super::mixed::publish(&h,policy,2,definition,frozen).await?;
        let next=read().await?;
        assert_eq!(next["items"][0]["taskAdmission"]["state"],"waiting_check_in");
        assert_eq!(next["items"][0]["execution"]["latestRun"]["versionId"],version.to_string());
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid").bind(h.c.tenant.to_string()).fetch_one(&h.c.operator).await?;
        assert_eq!(count,1);
        let mut tx=command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE mdm_policy.policies SET state='disabled' WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(policy).execute(&mut *tx).await?;
        tx.commit().await?;
        assert_eq!(read().await?["items"][0]["taskAdmission"]["state"],"paused");
        Ok(())
    }.await;
    h.close().await?;
    result
}
