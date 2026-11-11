//! The real Agent HTTP handler authenticates the current certificate before bounded qualification.
use super::*;
use rss_mdm_agent_channel as agent;
use tower::ServiceExt;
#[tokio::test]
#[ignore = "T2: authenticated Agent HTTP directory derives the real public row and preserves eligibility/paging"]
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
    let resources = &h.a.resources;
    let n = crate::native_identity_t2_support::seed(&h.c, "windows").await?;
    let materials = super::super::registration_installation_t2::support::materials(
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
            source: Arc::new(super::super::software_sources::Source(
                resources.source.clone(),
            )),
            inventory: Arc::new(super::super::software_sources::Inventory),
            lifecycle: Arc::new(super::super::software_sources::Lifecycle),
            protection: resources.protection.clone(),
            software_distribution: resources.config.software_distribution,
        },
    );
    let enrollment = Arc::new(
        super::super::registration_installation_t2::support::service(
            &h.c,
            &n,
            native,
            resources.protection.clone(),
            &materials,
        )?,
    );
    let tasks = Arc::new(super::super::agent_tasks::AgentTasks {
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
    let router = agent::task_router::<super::super::agent_tasks::SelfServiceQuery>(state, envelope)
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Agent);
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let _client = tokio::net::TcpStream::connect(socket.local_addr()?).await?;
    let (stream, _) = socket.accept().await?;
    let gateway =
        rss_mdm_certificate::GatewayConnection::from_stream(&stream, "127.0.0.1".parse()?)?;
    let leaf =
        h.c.inputs
            .directory
            .join(format!("task-trust-agent-{}/leaf.pem", h.c.tenant));
    let evidence = gateway.client_certificate(&std::fs::read_to_string(leaf)?)?;
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
    h.close().await
}
