//! Native consumers begin with an actual signed Agent task and its start authorization.
use super::{agent::*, runtime::*, *};
use rss_mdm_resource::Platform;
pub(crate) struct Handoff {
    pub fixture: agent_execution::Fixture,
    pub receipt: Value,
    pub password: String,
    pub source: Value,
    worker: Option<rss_runtime::ShutdownStack>,
    automation: Option<rss_runtime::ShutdownStack>,
}
impl Handoff {
    pub(crate) async fn new(platform: Platform) -> Result<Self> {
        let mut base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        base["native_protocols"] = json!({});
        base["enrollment_entries"] =
            json!({"windows":"https://mdm.example.test","macos":"https://mdm.example.test/"});
        let mut f = agent_execution::Fixture::from_config(base).await?;
        f.grants
            .extend(identity::device_grants(None, &["enrollment"])?);
        identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
        let windows = platform == Platform::Windows;
        let context = software_execution::context(if windows {
            software_execution::Platform::Windows
        } else {
            software_execution::Platform::MacOs
        });
        let source=agent::seed_profile(&f.base,f.execution.clone(),agent_execution::case_credential(),agent_execution::case_device_id(),json!({"capabilities":["inventory.collect.v1","mdm.enrollment.v1"],"platform":if windows{"windows"}else{"macos"},"architecture":if windows{"x86_64"}else{"aarch64"},"executionContext":context})).await?;
        let scope = Uuid::new_v4();
        f.scope(scope, json!([{"kind":"device","id":source["deviceId"]}]))
            .await?;
        let policy = Uuid::new_v4();
        planning_http::call(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"request_mdm_enrollment","organization":case_tenant(),"runLifetimeSeconds":600}}})).await?;
        let automation = start_automation(&f.base).await?;
        let worker = agent_execution::worker(&f.base).await?;
        let collection = source["collections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                c["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["key"] == "channel.mdm.enrollment")
            })
            .unwrap();
        let report = Uuid::new_v4();
        let accepted=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/reports",Some(agent_execution::case_credential()),Some(json!({"wireVersion":1,"collection":collection,"reportId":report,"sequence":0,"observedAt":1,"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":"unenrolled"}}}]}}))).await?;
        ensure!(
            accepted.0 == StatusCode::ACCEPTED,
            "handoff source: {accepted:?}"
        );
        wait_agent_status(
            &f.router,
            agent_execution::case_credential(),
            report,
            "snapshot",
            "applied",
        )
        .await?;
        planning_http::await_ingress().await?;
        let task=tokio::time::timeout(Duration::from_secs(30),async {loop{
            let result=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(agent_execution::case_credential()),Some(json!({"wireVersion":1,"executionContext":context,"environment":{"edition":if windows {Some("professional")}else{None},"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()}))).await?;
            ensure!(result.0==StatusCode::OK,"handoff claim: {result:?}");
            if !result.1["task"].is_null(){break Ok::<_,anyhow::Error>(result.1["task"].clone());}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }}).await??;
        let task_id = task["payload"]["task"]["taskId"].as_str().unwrap();
        for kind in ["received", "start"] {
            let result=agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{task_id}/events"),Some(agent_execution::case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"executionContext":context,"event":{"kind":kind}}))).await?;
            ensure!(result.0 == StatusCode::OK, "handoff {kind}: {result:?}");
        }
        let password = credential("native-protocol-handoff");
        let result=agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{task_id}/enrollment"),Some(agent_execution::case_credential()),Some(json!({"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"password":password}))).await?;
        ensure!(result.0 == StatusCode::OK, "native handoff: {result:?}");
        Ok(Self {
            fixture: f,
            receipt: result.1,
            password,
            source,
            worker,
            automation,
        })
    }
    pub(crate) async fn close(mut self) -> Result<()> {
        stop_worker(self.worker.take()).await?;
        stop_worker(self.automation.take()).await?;
        std::mem::take(&mut self.fixture.resources)
            .finish(async { Ok(()) })
            .await
    }
}
