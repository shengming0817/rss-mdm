//! Product seams for the current complete report: authenticated intake, durable replay and projection.
use super::*;
use rss_mdm_agent_channel as agent;
use rss_mdm_inventory_service::{collection, inventory_runtime as rt};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "T2: 4096-field escaped report crosses Agent HTTP, authoritative definitions, Observation and Projection without truncation"]
#[expect(
    clippy::disallowed_methods,
    reason = "real host HTTP clock and bounded integration polling"
)]
async fn complete_large_report_survives_authenticated_intake_replay_and_projection()
-> anyhow::Result<()> {
    let h = Harness::open().await?;
    let vocabulary = (0..1024)
        .map(|i| format!("state{i:04}{}", "s".repeat(128)))
        .collect::<std::collections::BTreeSet<_>>();
    let fields = (0..4096)
        .map(|i| {
            Ok(FieldDefinition {
                key: FieldKey::parse(&format!("custom.capacity.f{i:04}_{}", "x".repeat(96)))?,
                version: 1,
                value_type: match i {
                    0 => ValueType::Array {
                        items: Box::new(ValueType::String {
                            max_length: 65536,
                            allow_empty: false,
                        }),
                        max_items: 128,
                    },
                    1 => ValueType::Enum {
                        values: vocabulary.clone(),
                    },
                    _ => ValueType::Boolean,
                },
                nullable: false,
                manual: false,
                sources: [(Source::AgentBuiltin, 0)].into(),
                platforms: [Platform::Windows].into(),
                sensitivity: Sensitivity::Standard,
                unit: None,
                searchable: false,
                item_key: None,
                time_series: None,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    assert!(serde_json::to_vec(&fields[1])?.len() > 65536);
    let definition = CollectionDefinition::new(
        "capacity",
        1,
        Source::AgentBuiltin,
        fields
            .iter()
            .cloned()
            .map(|definition| CollectionField {
                definition,
                scope: CollectionScope::Device,
            })
            .collect(),
    )?;
    assert!(serde_json::to_vec(&definition)?.len() > 1024 * 1024);
    let mut tx = command::seed_transaction(&h.c).await?;
    // Exercise the actual publication boundary for the large definition. The remaining independent
    // authoritative history is one minimal seed, avoiding thousands of repeated catalog reads.
    assert!(
        rss_mdm_inventory_postgres::publish_field_in(&mut tx, h.c.tenant, 0, &fields[1]).await?
    );
    let others = fields
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, f)| f)
        .collect::<Vec<_>>();
    sqlx::query("SELECT mdm.append_field_version($1::uuid,f->>'key',1,f) FROM jsonb_array_elements($2::jsonb) f")
        .bind(h.c.tenant.to_string()).bind(serde_json::to_value(others)?).execute(&mut *tx).await?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, h.c.tenant, &definition).await?;
    tx.commit().await?;
    let wire = collection::wire::to_wire(&definition)?;
    let values = wire
        .fields()
        .iter()
        .enumerate()
        .map(|(i, f)| w::FieldValue {
            field: f.key,
            value: w::CollectedValue::Value(match i {
                0 => w::Scalar::Array(vec![w::Scalar::String("\\\"".repeat(1024)); 128]),
                1 => w::Scalar::String(vocabulary.first().unwrap().clone()),
                _ => w::Scalar::Boolean(true),
            }),
        })
        .collect::<Vec<_>>();
    assert!(serde_json::to_vec(&values[0])?.len() > 65536);
    let id = Uuid::new_v4();
    let report = w::ReportRequest::new(
        id,
        1,
        now(),
        wire.clone(),
        w::ReportBody::Snapshot(values.clone()),
    )?;
    let body = report.canonical()?;
    assert!(body.len() > 2 * 1024 * 1024 && body.len() <= w::MAX_REPORT_BYTES);
    let batch = agent::report_batch(&report)?;
    assert!(batch.encode().len() <= 4 * 1024 * 1024);

    let resources = &h.a.resources;
    let n = crate::native_identity_t2_support::seed(&h.c, "windows").await?;
    let materials = crate::assembly::registration_installation_t2::support::materials(
        &h.c,
        &n,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let native = Arc::new(
        rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
            tenant: h.c.tenant,
            instance: resources.config.identity.instance_id.clone(),
            source: Arc::new(crate::assembly::software_sources::Source(
                resources.source.clone(),
            )),
            inventory: Arc::new(crate::assembly::software_sources::Inventory),
            lifecycle: Arc::new(crate::assembly::software_sources::Lifecycle),
            protection: resources.protection.clone(),
            software_distribution: resources.config.software_distribution,
        },
    );
    let enrollment = Arc::new(
        crate::assembly::registration_installation_t2::support::service(
            &h.c,
            &n,
            native,
            resources.protection.clone(),
            &materials,
        )?,
    );
    let clock = rt::Clock::new(
        crate::clock::monotonic(),
        resources.config.inventory_runtime.compile()?,
    );
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_projection::Control::new(&clock, clock.startup_cutoff(), &cancel);
    let observation =
        rt::ObservationResource::open(h.c.inputs.options("shared", "mdm_runtime")?, clock.clone())
            .await?;
    let projection = rt::ProjectionResource::open(
        h.c.inputs.options("shared", "mdm_runtime")?,
        clock.clone(),
        &control,
    )
    .await?;
    let inventory = Arc::new(rt::InventoryRuntime::new(
        observation.store.clone(),
        projection.store.clone(),
        h.c.database.inventory(),
        h.c.audit.clone(),
        h.c.tenant,
        clock,
        Arc::new(rt::Readiness::default()),
    ));
    let state = Arc::new(agent::HttpState {
        content: None,
        telemetry: None,
        enrollment,
        audit_store: h.c.audit.clone(),
        access: Arc::new(h.c.database.agent_store()),
        inventory: inventory.clone(),
    });
    let envelope = agent::boundary::Envelope {
        profile: rss_mdm_install_support::StorageProfile::Mdm,
        admission: Arc::new(tokio::sync::Semaphore::new(8)),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
        host: "mdm.example.test".into(),
        clock: Arc::new(crate::Monotonic(std::time::Instant::now)),
        audit_store: h.c.audit.clone(),
        tenant: h.c.tenant.to_string(),
        request_budget: rss_axum::RequestBudget::new(std::time::Duration::from_secs(30))?,
    };
    let mut lifecycle = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(std::time::Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let launch = lifecycle.startup()?.commit();
    let (admission, gate) =
        launch.finish_with_admission("report-capacity", std::time::Duration::from_secs(10));
    admission.open()?;
    let router = agent::router(state, envelope)
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Agent)
        .layer(axum::Extension(gate));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let _client = tokio::net::TcpStream::connect(socket.local_addr()?).await?;
    let (stream, _) = socket.accept().await?;
    let gateway =
        rss_mdm_certificate::GatewayConnection::from_stream(&stream, "127.0.0.1".parse()?)?;
    let certificate: String = sqlx::query_scalar("SELECT certificate_chain->>0 FROM mdm_access.certificate_issuances WHERE tenant_id=$1::uuid AND credential=$2")
        .bind(h.c.tenant.to_string()).bind(h.p.credential()).fetch_one(&h.c.operator).await?;
    let evidence = gateway.client_certificate(&format!(
        "-----BEGIN CERTIFICATE-----\n{certificate}\n-----END CERTIFICATE-----\n"
    ))?;
    let send = |bytes: Vec<u8>, authenticated: bool| {
        let router = router.clone();
        let evidence = evidence.clone();
        async move {
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/reports")
                .header("host", "mdm.example.test")
                .header("content-type", "application/json");
            if authenticated {
                request = request.extension(evidence);
            }
            let response = router
                .oneshot(request.body(axum::body::Body::from(bytes))?)
                .await?;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
            Ok::<_, anyhow::Error>((status, bytes))
        }
    };
    assert_eq!(send(body.clone(), false).await?.0, 401);
    let first = send(body.clone(), true).await?;
    assert_eq!(first.0, 202, "{}", String::from_utf8_lossy(&first.1));
    let replay = send(body.clone(), true).await?;
    assert_eq!(replay, first);
    let mut changed = values;
    changed[2].value = w::CollectedValue::Value(w::Scalar::Boolean(false));
    let conflict = w::ReportRequest::new(
        id,
        1,
        report.observed_at(),
        wire.clone(),
        w::ReportBody::Snapshot(changed),
    )?;
    assert_eq!(send(conflict.canonical()?, true).await?.0, 409);
    let mut tx = command::seed_transaction(&h.c).await?;
    let stored = collection::store::read_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &h.c.tenant.to_string(),
        id,
    )
    .await?;
    let canonical: String = sqlx::query_scalar("SELECT evidence->>'agentReport' FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string()).bind(id).fetch_one(&mut *tx).await?;
    assert_eq!(canonical.as_bytes(), body);
    assert_eq!(stored.attempts.fields().len(), 4096);
    assert_eq!(stored.attempts.body()?.as_ref(), Some(batch.body()));
    tx.rollback().await?;
    let second = w::ReportRequest::new(
        Uuid::new_v4(),
        2,
        report.observed_at(),
        wire,
        w::ReportBody::Snapshot(report.values().to_vec()),
    )?;
    assert_eq!(send(second.canonical()?, true).await?.0, 202);
    let charge: i64 = sqlx::query_scalar("SELECT octet_length(attempts::text)::bigint+octet_length(batch)+octet_length(scope)+1024 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string()).bind(id).fetch_one(&h.c.operator).await?;
    let delivery = collection::store::Delivery::new(h.c.database.inventory(), h.c.audit.clone());
    let prefix = delivery
        .pending_reports(
            &h.c.tenant.to_string(),
            rss_projection::BatchLimit::new(1024)?,
            charge,
        )
        .await?;
    assert_eq!(prefix.len(), 1);
    assert_eq!(prefix[0].batch().id().as_str(), id.to_string());
    assert_eq!(
        delivery
            .pending_reports(
                &h.c.tenant.to_string(),
                rss_projection::BatchLimit::new(1024)?,
                charge * 2
            )
            .await?
            .len(),
        2
    );
    assert!(matches!(
        delivery
            .pending_reports(
                &h.c.tenant.to_string(),
                rss_projection::BatchLimit::new(1024)?,
                charge - 1
            )
            .await,
        Err(rss_mdm_inventory_service::Error::Unavailable(
            rss_mdm_inventory_service::Failure::Capacity
        ))
    ));

    // One tenant/object row is enough to exhaust a pass without blocking unrelated T2 consumers.
    sqlx::query("INSERT INTO rss_observation.objects(tenant_id,object_id,revision) VALUES($1::uuid,$2,0) ON CONFLICT DO NOTHING")
        .bind(h.c.tenant.to_string()).bind(stored.scope.object().as_str()).execute(&h.c.operator).await?;
    let mut locked = h.c.operator.begin().await?;
    sqlx::query("SELECT revision FROM rss_observation.objects WHERE tenant_id=$1::uuid AND object_id=$2 FOR UPDATE")
        .bind(h.c.tenant.to_string()).bind(stored.scope.object().as_str()).fetch_one(&mut *locked).await?;
    let mut worker_lifecycle = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(std::time::Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = worker_lifecycle.startup()?.commit();
    launch.stage_resource(rss_runtime::DynManagedResource::new_box(observation));
    launch.stage_resource(rss_runtime::DynManagedResource::new_box(projection));
    let notify = Arc::new(tokio::sync::Notify::new());
    let status = launch.stage_task_with_token(inventory.clone().registration(notify.clone()));
    launch.finish();
    tokio::time::sleep(std::time::Duration::from_secs(
        resources.config.inventory_runtime.pass_seconds + 1,
    ))
    .await;
    assert_eq!(status.current(), rss_runtime::TaskState::Running);
    locked.rollback().await?;
    notify.notify_one();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(30));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let status = inventory
                .inspect_report(
                    &stored.scope,
                    stored.batch().unwrap(),
                    budget.deadline(),
                    rss_request_context::Cancellation::observe(&budget),
                )
                .await?;
            if status.projection == rt::ProjectionStatus::Projected
                && delivery.pending_count(&h.c.tenant.to_string()).await? == 0
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await??;
    let mut tx = command::seed_transaction(&h.c).await?;
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as("SELECT field,state,value FROM mdm.inventory WHERE tenant_id=$1::uuid AND scope=$2 ORDER BY field")
        .bind(h.c.tenant.to_string()).bind(stored.scope.encode()?).fetch_all(&mut *tx).await?;
    assert_eq!(rows.len(), 4096);
    assert_eq!(
        rows.iter()
            .map(|r| r.0.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4096
    );
    for (field, state, value) in &rows {
        assert_eq!(state, "known");
        if field != fields[0].key.as_str() && field != fields[1].key.as_str() {
            assert_eq!(
                serde_json::from_str::<Scalar>(value.as_ref().unwrap())?,
                Scalar::Boolean(true)
            );
        }
    }
    let projected = rss_mdm_inventory_postgres::read_in(
        &mut tx,
        h.c.tenant,
        std::slice::from_ref(&stored.scope),
        &[fields[0].key, fields[1].key],
    )
    .await?;
    assert_eq!(projected.scalars.len(), 1);
    assert_eq!(
        projected.scalars[0].fact.state,
        State::Known(Scalar::String(vocabulary.first().unwrap().clone()))
    );
    assert_eq!(projected.arrays.len(), 1);
    let rss_mdm_inventory::ArrayState::Known(array) = &projected.arrays[0].fact.state else {
        anyhow::bail!("known complete array")
    };
    assert_eq!(array.count, 128);
    let page = rss_mdm_inventory_postgres::arrays::page(
        &mut tx,
        h.c.tenant,
        &array.version,
        0,
        1024,
        4 * 1024 * 1024,
    )
    .await?;
    assert_eq!(page.items, vec![Scalar::String("\\\"".repeat(1024)); 128]);
    assert!(page.next.is_none());
    tx.rollback().await?;
    assert!(worker_lifecycle.shutdown().join().await?.is_clean());
    assert!(lifecycle.shutdown().join().await?.is_clean());
    h.close().await
}
