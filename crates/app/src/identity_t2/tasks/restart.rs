//! Restart actual command workers between persisted fanout and recovery pages.
use super::*;
pub(super) async fn worker(base: &Value) -> Result<rss_runtime::ShutdownStack> {
    let config: Config = serde_json::from_value(base.clone())?;
    let service = crate::flow::execution::open(
        &config,
        crate::identity_fixture::audit_store(&config).await?,
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::execution::Resource(service.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(service.registration().critical());
    launch.finish();
    Ok(owner)
}
pub(super) async fn targets(author: &mut Browser, router: &Router) -> Result<Vec<String>> {
    let mut devices = vec![DEVICE_ID.to_owned()];
    for n in 0..129 {
        let device = format!("restart-agent-{n:03}");
        let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        author.operation = Some(Uuid::new_v4());
        let enrollment = post(
            author,
            router,
            "/api/v3/enrollments",
            json!({"deviceId":device,"password":password,"source":"agent.builtin"}),
        )
        .await?;
        author.operation = None;
        let credential = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(device.as_bytes()));
        let registration=agent_call(router,Method::POST,"/api/agent/v3/registrations",None,Some(json!({"wireVersion":3,"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":credential,"platform":"macos","architecture":"aarch64","capabilities":["inventory.basic.v3","task.execute.v3"]}))).await?;
        ensure!(
            registration.0 == StatusCode::CREATED,
            "restart target registration: {registration:?}"
        );
        devices.push(device);
    }
    devices.extend((0..171).map(|n| format!("unregistered-{n:04}")));
    Ok(devices)
}
pub(super) async fn checkpoint(operation: Uuid, recovery: bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60),async {loop {
        let progress:Value=serde_json::from_str(pg(&format!("SELECT jsonb_build_object('cursor',cursor,'runAfter',run_after,'staged',staged) FROM mdm_planning.remote_operations WHERE id='{operation}'"))?.trim())?;
        let key=if recovery {"runAfter"}else{"cursor"};
        if !progress[key].is_null() {
            ensure!(recovery || progress["staged"]==false,"worker skipped the checkpoint boundary: {progress}");return Ok::<_,anyhow::Error>(());
        }
        ensure!(recovery || progress["staged"]==false,"all pages finished before restart: {progress}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await?
}
pub(super) async fn cancelled(author: &mut Browser, router: &Router, id: Uuid) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let reply = author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v2/remote-operations/{id}"),
                    None,
                )
                .await?;
            if reply.0 == StatusCode::SERVICE_UNAVAILABLE {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            ensure!(reply.0 == StatusCode::OK, "remote progress: {reply:?}");
            if reply.1["phase"] == "completed" {
                ensure!(reply.1["cancellationRequested"] == true);
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(
                reply.1["phase"] == "cancelling",
                "premature or unexpected terminal phase: {reply:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
