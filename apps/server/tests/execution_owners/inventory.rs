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
    let registration = h.p.registration();
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
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,'agent.script',$3,true)").bind(tenant.to_string()).bind(registration).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;

    script::transaction::run(
        &h.audit,
        &h.a.runtime,
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
                            registration,
                            task,
                            attempt,
                            definition.clone(),
                            at,
                        )
                        .await?;
                        enterprise::start_in(
                            c,
                            tenant,
                            registration,
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
        let progress = progress.clone();
        let audit = request(&h.c);
        let h = &h;
        async move {
            script::transaction::run(
                &h.audit,
                &h.a.runtime,
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
                                        registration,
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
            .map(|m| m.registration_id)
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
    let proof = h.c.authenticate(&account).await?;
    let detail = Reads::run(
        h.a.task_reads.as_ref(),
        &proof,
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
            &proof,
            &h.c.request(&proof)?,
            policy,
            task
        )
        .await,
        Err(rss_mdm_management_http::Error::Forbidden)
    ));
    h.close().await
}
