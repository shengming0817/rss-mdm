//! The real Agent HTTP handler authenticates the current certificate before bounded qualification.
use super::*;
use rss_mdm_agent_channel as agent;
use tower::ServiceExt;
#[tokio::test]
#[ignore = "T2: authenticated Agent HTTP directory derives the real public row and preserves eligibility/paging"]
#[expect(
    clippy::disallowed_methods,
    reason = "The real Agent HTTP boundary receives its host monotonic clock"
)]
async fn authenticated_self_service_filters_typed_fields_and_business_search() -> Result<()> {
    let h = Harness::open().await?;
    let (policy, _) = h.policy("directory-self-service").await?;
    let (sentinel, _) = h.policy("directory-sentinel").await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    for (id, name) in [(policy, "Directory Install"), (sentinel, "Sentinel")] {
        sqlx::query("UPDATE mdm_policy.policies SET definition=jsonb_set(definition,'{selfService}',$3) WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(id)
            .bind(json!({"access":{"kind":"device"},"published":true,"allowAi":false,"riskLevel":2,"presentation":{"displayName":name,"category":"Tools","description":"","prerequisites":"","sideEffects":"","keywords":[]}})).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let announcement = w::TaskClaimRequest::new(
        Uuid::new_v4(),
        vec![w::ExecutorProfile::PowerShell7],
        context(),
    )?;
    assert!(
        h.delivery
            .claim(&h.p, &announcement, &request(&h.c))
            .await?
            .task()
            .is_none()
    );
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
    let tasks = Arc::new(crate::assembly::agent_tasks::AgentTasks {
        access: h.a.access_execution.service.clone(),
        credentials: vec![],
        software: h.a.software.service.clone(),
        registration: h.a.registration.enrollment.clone(),
        content: None,
        requests: h.a.self_service.clone(),
        execution: h.a.service.clone(),
        scripts: h.a.scripts.clone(),
        collections: h.a.collections.clone(),
    });
    let delivery = Arc::new(agent::delivery::Delivery {
        runtime: resources.storage.runtime.clone(),
        tenant: h.c.tenant,
        audit: h.audit.clone(),
        signing: resources.signing.clone(),
        tasks: tasks.clone(),
        content: None,
    });
    let state = Arc::new(agent::TaskState {
        access: Arc::new(h.c.database.agent_store()),
        enrollment,
        delivery,
        self_service: tasks.clone(),
        installation: tasks,
        task_trust: Arc::new(material::service(&h.c, resources.protection.clone())?),
        identity: resources.sessions.clone(),
        authorization: h.c.access(),
    });
    let envelope = agent::boundary::Envelope {
        profile: rss_mdm_install_support::StorageProfile::Mdm,
        admission: Arc::new(tokio::sync::Semaphore::new(8)),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
        host: "mdm.example.test".into(),
        clock: Arc::new(crate::Monotonic(std::time::Instant::now)),
        audit_store: h.audit.clone(),
        tenant: h.c.tenant.to_string(),
    };
    let mut lifecycle = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(std::time::Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let (control, gate) = lifecycle
        .startup()?
        .commit()
        .finish_with_admission("self-service-directory", std::time::Duration::from_secs(10));
    control.open()?;
    let router =
        agent::task_router::<crate::assembly::agent_tasks::SelfServiceQuery>(state, envelope)
            .into_checked_axum(rss_mdm_http_contract::module::Listener::Agent)
            .layer(axum::Extension(gate));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let _client = tokio::net::TcpStream::connect(socket.local_addr()?).await?;
    let (stream, _) = socket.accept().await?;
    let gateway =
        rss_mdm_certificate::GatewayConnection::from_stream(&stream, "127.0.0.1".parse()?)?;
    let certificate: String = sqlx::query_scalar("SELECT certificate_chain->>0 FROM mdm_access.certificate_issuances WHERE tenant_id=$1::uuid AND credential=$2")
        .bind(h.c.tenant.to_string()).bind(h.p.credential()).fetch_one(&h.c.operator).await?;
    let pem = format!("-----BEGIN CERTIFICATE-----\n{certificate}\n-----END CERTIFICATE-----\n");
    let evidence = gateway.client_certificate(&pem)?;
    for fields in [None, Some("policyId,capability")] {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("source", "human").append_pair(
            "filter",
            &format!(
                "policyId=={policy};displayName=='Directory Install';capability.objectType==policy"
            ),
        );
        if let Some(fields) = fields {
            q.append_pair("fields", fields);
        }
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/self-service?{}", q.finish()))
                    .header("host", "mdm.example.test")
                    .extension(evidence.clone())
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        let page: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(status, 200, "{page}");
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["items"][0]["policyId"], policy.to_string());
        if fields.is_some() {
            assert!(page["items"][0].get("task").is_none());
        }
    }
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/self-service?source=human")
                .header("host", "mdm.example.test")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), 401);
    assert!(lifecycle.shutdown().join().await?.is_clean());
    h.close().await
}
