//! Real authenticated product authoring -> frozen plan -> native Replace -> independent Get.
use super::*;
mod admission;
mod boundaries;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
impl Client {
    async fn product(&mut self, path: &str, body: Value) -> anyhow::Result<Value> {
        let mut reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!(
                    "/api/v{}/{path}",
                    if path.ends_with("/execute") || path.starts_with("resources/") {
                        1
                    } else {
                        2
                    }
                ),
                Some(body),
            )
            .await?;
        ensure!(reply.0.is_success(), "{path}: {reply:?}");
        if let Some(status) = reply.1["statusUrl"].as_str() {
            return self.wait_preview(status).await;
        }
        if path.starts_with("policies/")
            && !path.contains("/plans")
            && let Some(task) = reply.1["task"].as_str()
        {
            self.wait_preview(&format!("/api/v2/plan-previews/{task}"))
                .await?;
            let current = self
                .browser
                .call(&self.router, Method::GET, &format!("/api/v2/{path}"), None)
                .await?;
            ensure!(current.0 == StatusCode::OK);
            reply.1["storageRevision"] = current.1["storageRevision"].clone();
        }
        Ok(reply.1)
    }
    async fn wait_preview(&mut self, path: &str) -> anyhow::Result<Value> {
        let mut last = Value::Null;
        let result = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let reply = self
                    .browser
                    .call(&self.router, Method::GET, path, None)
                    .await?;
                ensure!(reply.0 == StatusCode::OK, "task read: {reply:?}");
                last = reply.1.clone();
                if matches!(
                    reply.1["status"].as_str(),
                    Some("completed" | "failed" | "superseded")
                ) {
                    return Ok(reply.1);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        result.map_err(|_| {
            anyhow::anyhow!(
                "task {path} timed out: {last}; worker {:?}",
                self.app
                    .management
                    .automation_task
                    .get()
                    .map(|t| t.is_running())
            )
        })?
    }
    pub(super) async fn firewall_cycle(
        &mut self,
        peer: &reqwest::Client,
        url: &str,
        initial: &s::Message,
        ack: &s::Message,
    ) -> anyhow::Result<()> {
        // Earlier command tests intentionally corrupt shared runtime privileges.
        // Start this real worker only once that adversarial matrix has restored them.
        let mut automation_owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let automation = crate::management::automation::Automation::connect(
            self.app.management.clone(),
            crate::device::tests::options("mdm_management_runtime")?.password("runtime-fixture"),
        )
        .await?;
        let mut startup = automation_owner.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            crate::management::automation::Resource(automation.clone()),
        ));
        let mut launch = startup.commit();
        launch.stage_deferred_task_with_token(automation.registration().critical());
        launch.finish();
        let cap = native::begin(peer, url, initial, ack, 950, None).await?;
        let message = native::report(&cap.first, &cap.gets, "10.0.19045.0", 200);
        peer_reply(peer, url, &message).await?;
        let rule = Uuid::new_v4();
        let mut grants: Vec<Value> = [
            "resource_read",
            "resource_write",
            "policy_read",
            "policy_write",
            "scope_write",
            "plan_preview",
            "plan_save",
            "plan_execute",
        ]
        .iter()
        .map(|p| json!({"operation":p,"scope":{"kind":"tenant"}}))
        .collect();
        let subject = json!({"kind":"user","user":crate::identity_fixture::user(TENANT,crate::identity_fixture::ADMIN)});
        let reply=self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{rule}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":subject,"grants":grants}}))).await?;
        ensure!(reply.0 == StatusCode::OK);
        let resource = format!("firewall-{}", Uuid::new_v4());
        let policy = format!("policy-{}", Uuid::new_v4());
        let scope = Uuid::new_v4();
        let op = |revision, input| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
        let r = self
            .product(
                &format!("resources/{resource}"),
                op(0, json!({"action":"create","kind":"configuration"})),
            )
            .await?;
        self.product(
            &format!("resources/{resource}"),
            op(
                r["storageRevision"].as_u64().unwrap(),
                json!({"action":"firewall_version","version":"v1","enabled":true}),
            ),
        )
        .await?;
        let p = self
            .product(
                &format!("policies/{policy}"),
                op(0, json!({"action":"create"})),
            )
            .await?;
        let p=self.product(&format!("policies/{policy}"),op(p["storageRevision"].as_u64().unwrap(),json!({"action":"activate","version":1,"resource":resource,"resourceVersion":"v1"}))).await?;
        let revision = p["storageRevision"].as_u64().unwrap();
        self.product(&format!("scopes/{scope}"),op(0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":DEVICE}],"limitations":null,"exclusions":[]}}))).await?;
        let preview = Uuid::new_v4();
        let pre = json!({"operationId":preview,"expectedRevision":revision,"input":{"scope":scope,"expectedRevision":revision}});
        let frozen = self
            .product(&format!("policies/{policy}/previews"), pre)
            .await?;
        ensure!(
            frozen["execution"]["configuration"]["enabled"] == true
                && frozen["execution"]["configuration"]["ddf"] == "DDFv2Feb2026"
        );
        let saved = self
            .product(
                &format!("policies/{policy}/plans"),
                op(
                    frozen["policyRevision"].as_u64().unwrap(),
                    json!({"preview":preview}),
                ),
            )
            .await?;
        let request = json!({"operationId":Uuid::new_v4(),"expectedRevision":saved["receipt"]["storageRevision"],"deadline":self.app.clock.unix_seconds()?+300});
        let path = format!("/api/v1/policies/{policy}/plans/{preview}/execute");
        let denied = self
            .browser
            .call(&self.router, Method::POST, &path, Some(request.clone()))
            .await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN,
            "StateVerify authorized write: {denied:?}"
        );
        grants.push(json!({"operation":"firewall_write","scope":{"kind":"device","id":DEVICE}}));
        ensure!(self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{rule}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":{"subject":subject,"grants":grants}}))).await?.0==StatusCode::OK);
        #[cfg(feature = "integration")]
        {
            self.app.commands.inject_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(
                self.browser
                    .call(&self.router, Method::POST, &path, Some(request.clone()))
                    .await?
                    .0
                    == StatusCode::SERVICE_UNAVAILABLE
            );
        }
        let accepted = self
            .browser
            .call(&self.router, Method::POST, &path, Some(request.clone()))
            .await?;
        ensure!(
            accepted.0 == StatusCode::ACCEPTED,
            "plan dispatch: {accepted:?}"
        );
        ensure!(
            self.browser
                .call(&self.router, Method::POST, &path, Some(request.clone()))
                .await?
                == accepted
        );
        let operation =
            Uuid::parse_str(accepted.1["operations"][0]["operationId"].as_str().unwrap())?;
        self.publish_operation(operation).await?;
        let write = native::begin(peer, url, initial, ack, 951, None).await?;
        let response = peer_reply(
            peer,
            url,
            &native::report(&write.first, &write.gets, "10.0.19045.0", 200),
        )
        .await?;
        assert_work(
            &response,
            &[("replace", rss_mdm_windows_mdm::configuration::FIREWALL_URI)],
        )?;
        let replace = response
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Replace { id, configuration } => Some((*id, configuration.enabled())),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("response has no real Replace: {response:?}"))?;
        ensure!(replace.1);
        let status = |id, reference, command| {
            s::Command::Status(s::Status {
                id,
                message_ref: 3,
                command_ref: reference,
                command,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            })
        };
        let received = s::Message {
            header: s::Header {
                message_id: 4,
                credential: None,
                ..write.first.header.clone()
            },
            commands: vec![
                status(1, 0, s::CommandName::SyncHdr),
                status(2, replace.0, s::CommandName::Replace),
            ],
            final_message: true,
        };
        let observation = peer_reply(peer, url, &received).await?;
        assert_work(
            &observation,
            &[("get", rss_mdm_windows_mdm::configuration::STATUS_URI)],
        )?;
        let (get, uri) = observation
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Get { id, items, .. }
                    if items[0].target.as_deref()
                        == Some(rss_mdm_windows_mdm::configuration::STATUS_URI) =>
                {
                    Some((*id, items[0].target.clone().unwrap()))
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("no independent Get"))?;
        let before = self
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
        ensure!(
            before.1["commandStatus"] == "received"
                && before.1["observation"]["effect"] == "unknown"
        );
        let mut result = received.clone();
        result.header.message_id = 5;
        result.commands = vec![
            s::Command::Status(s::Status {
                id: 1,
                message_ref: 4,
                command_ref: 0,
                command: s::CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
            s::Command::Status(s::Status {
                id: 2,
                message_ref: 4,
                command_ref: get,
                command: s::CommandName::Get,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
            s::Command::Results(s::Results {
                id: 3,
                message_ref: Some(4),
                command_ref: Some(get),
                command: Some(s::CommandName::Get),
                meta: None,
                items: vec![s::Item {
                    source: Some(uri),
                    target: None,
                    meta: None,
                    data: Some(Secret("0".into())),
                }],
            }),
        ];
        let end = peer_reply(peer, url, &result).await?;
        ensure!(
            !end.commands
                .iter()
                .any(|c| matches!(c, s::Command::Replace { .. } | s::Command::Get { .. }))
        );
        let after = self
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
        ensure!(
            after.1["commandStatus"] == "received"
                && after.1["observation"]["value"] == "0"
                && after.1["observation"]["effect"] == "unknown"
                && after.1["observation"]["cleanup"] == "unsupported",
            "coarse observation became configuration success: {after:?}"
        );
        // A new frozen version cancels the old command, without claiming cleanup.
        let next = self
            .next_firewall_plan(&resource, &policy, scope, false, 2, None)
            .await?;
        let old = self
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
        ensure!(
            old.1["commandStatus"] == "cancelled" && old.1["observation"]["effect"] == "unknown"
        );
        let before = self.call(Method::GET, &format!("/{next}"), None).await?;
        peer_reply(peer, url, &result).await?;
        ensure!(
            self.call(Method::GET, &format!("/{next}"), None).await? == before,
            "late v1 observation changed v2"
        );
        self.publish_operation(next).await?;
        let second = native::begin(peer, url, initial, ack, 952, None).await?;
        let response = peer_reply(
            peer,
            url,
            &native::report(&second.first, &second.gets, "10.0.19045.0", 200),
        )
        .await?;
        assert_work(
            &response,
            &[("replace", rss_mdm_windows_mdm::configuration::FIREWALL_URI)],
        )?;
        let replace = response
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Replace { id, configuration } => Some((*id, configuration.enabled())),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("v2 Replace missing"))?;
        ensure!(!replace.1);
        let mut receipt = received.clone();
        receipt.header.session_id = 952;
        if let s::Command::Status(s) = &mut receipt.commands[1] {
            s.command_ref = replace.0;
        }
        let observation = peer_reply(peer, url, &receipt).await?;
        assert_work(
            &observation,
            &[("get", rss_mdm_windows_mdm::configuration::STATUS_URI)],
        )?;
        let get = observation
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Get { id, .. } => Some(*id),
                _ => None,
            })
            .unwrap();
        ensure!(
            self.call(
                Method::POST,
                &format!("/{next}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::OK
        );
        let mut late = result.clone();
        late.header.session_id = 952;
        if let s::Command::Status(s) = &mut late.commands[1] {
            s.command_ref = get;
        }
        if let s::Command::Results(r) = &mut late.commands[2] {
            r.command_ref = Some(get);
        }
        let cancelled = peer_reply(peer, url, &late).await?;
        ensure!(
            !cancelled
                .commands
                .iter()
                .any(|c| matches!(c, s::Command::Replace { .. } | s::Command::Get { .. }))
        );
        let state = self.call(Method::GET, &format!("/{next}"), None).await?;
        ensure!(
            state.1["commandStatus"] == "cancelled"
                && state.1["observation"]["effect"] == "unknown"
        );
        Box::pin(self.boundary_tests(boundaries::Fixture {
            peer,
            url,
            initial,
            ack,
            resource: &resource,
            policy: &policy,
            scope,
        }))
        .await?;
        ensure!(automation_owner.shutdown().join().await?.is_clean());
        Ok(())
    }
    async fn next_firewall_plan(
        &mut self,
        resource: &str,
        policy: &str,
        scope: Uuid,
        enabled: bool,
        version: u64,
        lifetime: Option<i64>,
    ) -> anyhow::Result<Uuid> {
        let op = |revision, input| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
        let r = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v1/resources/{resource}"),
                None,
            )
            .await?;
        ensure!(r.0 == StatusCode::OK);
        self.product(
            &format!("resources/{resource}"),
            op(
                r.1["revision"].as_u64().unwrap(),
                json!({"action":"firewall_version","version":format!("v{version}"),"enabled":enabled}),
            ),
        )
        .await?;
        let p = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v2/policies/{policy}"),
                None,
            )
            .await?;
        ensure!(p.0 == StatusCode::OK);
        let p=self.product(&format!("policies/{policy}"),op(p.1["storageRevision"].as_u64().unwrap(),json!({"action":"activate","version":version,"resource":resource,"resourceVersion":format!("v{version}")}))).await?;
        let revision = p["storageRevision"].as_u64().unwrap();
        let preview = Uuid::new_v4();
        let frozen = self.product(&format!("policies/{policy}/previews"),json!({"operationId":preview,"expectedRevision":revision,"input":{"scope":scope,"expectedRevision":revision}})).await?;
        let saved = self
            .product(
                &format!("policies/{policy}/plans"),
                op(
                    frozen["policyRevision"].as_u64().unwrap(),
                    json!({"preview":preview}),
                ),
            )
            .await?;
        let result=self.product(&format!("policies/{policy}/plans/{preview}/execute"),json!({"operationId":Uuid::new_v4(),"expectedRevision":saved["receipt"]["storageRevision"],"deadline":self.app.clock.unix_seconds()? + lifetime.unwrap_or(300)})).await?;
        Ok(Uuid::parse_str(
            result["operations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["accepted"] == true)
                .unwrap()["operationId"]
                .as_str()
                .unwrap(),
        )?)
    }
}
async fn peer_reply(
    peer: &reqwest::Client,
    url: &str,
    message: &s::Message,
) -> anyhow::Result<s::Message> {
    // Respect the production per-peer admission rate across the expanded exchanges.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let response = peer
        .post(url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(s::encode(message, &CodecLimits::default())?)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status == StatusCode::OK,
        "native status {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(s::decode(&bytes, &CodecLimits::default())?)
}

fn assert_work(message: &s::Message, expected: &[(&str, &str)]) -> anyhow::Result<()> {
    ensure!(
        message
            .commands
            .iter()
            .map(s::Command::id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == message.commands.len()
    );
    let work = message
        .commands
        .iter()
        .filter_map(|c| match c {
            s::Command::Get { items, .. } => Some(("get", items[0].target.as_deref().unwrap())),
            s::Command::Replace { .. } => {
                Some(("replace", rss_mdm_windows_mdm::configuration::FIREWALL_URI))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        work == expected,
        "session {} message {}: expected {expected:?}, actual {work:?}",
        message.header.session_id,
        message.header.message_id
    );
    Ok(())
}
