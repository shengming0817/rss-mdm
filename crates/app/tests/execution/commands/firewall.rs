#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
//! Real configuration Policy -> automatic native Replace -> independent Get.
use crate::execution::test_support::native;
use crate::execution::test_support::*;
use crate::execution::*;
use anyhow::{Context, ensure};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::Connection;

use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
impl Client {
    async fn submit_product(&mut self, path: &str, body: Value) -> anyhow::Result<Value> {
        let route = format!(
            "/api/v{}/{path}",
            if path.starts_with("resources/") { 3 } else { 2 }
        );
        let mut reply = self
            .browser
            .call(&self.router, Method::POST, &route, Some(body.clone()))
            .await?;
        for _ in 0..20 {
            if reply.0 != StatusCode::SERVICE_UNAVAILABLE {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Retain the original operation identity and body on uncertain settlement.
            reply = self
                .browser
                .call(&self.router, Method::POST, &route, Some(body.clone()))
                .await?;
        }
        ensure!(reply.0.is_success(), "{path}: {reply:?}");
        Ok(reply.1)
    }
    async fn product(&mut self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.submit_product(path, body).await
    }
    async fn wait_preview(&mut self, path: &str) -> anyhow::Result<Value> {
        let mut last = Value::Null;
        let result = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let reply = self
                    .browser
                    .call(&self.router, Method::GET, path, None)
                    .await?;
                if reply.0 == StatusCode::SERVICE_UNAVAILABLE {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
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
                    .flow
                    .planning
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
        let mut automation_owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let automation = crate::automation::Automation::connect(
            self.app.flow.planning.clone(),
            self.app.flow.assets.clone(),
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?;
        let mut startup = automation_owner.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            crate::automation::Resource(automation.clone()),
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
            "scope_read",
            "group_read",
            "group_write",
            "group_recompute",
        ]
        .iter()
        .map(|p| json!({"operation":p,"scope":{"kind":"tenant"}}))
        .collect();
        grants.extend(
            ["operation_read", "operation_cancel"].into_iter().map(
                |operation| json!({"operation":operation,"scope":{"kind":"device","id":DEVICE}}),
            ),
        );
        let subject = json!({"kind":"user","user":crate::test_support::identity::user(TENANT,crate::test_support::identity::ADMIN)});
        let reply=self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{rule}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":subject,"grants":grants}}))).await?;
        ensure!(reply.0 == StatusCode::OK);
        let resource = format!("firewall-{}", Uuid::new_v4());
        let policy = Uuid::new_v4().to_string();
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
        let current = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v3/resources/{resource}"),
                None,
            )
            .await?;
        self.product(
            &format!("resources/{resource}"),
            op(
                current.1["revision"].as_u64().unwrap(),
                json!({"action":"activate","version":"v1"}),
            ),
        )
        .await?;
        let created=self.product(&format!("scopes/{scope}"),op(0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":DEVICE}],"limitations":null,"exclusions":[]}}))).await?;
        self.wait_preview(&format!(
            "/api/v2/scopes/{scope}/tasks/{}",
            created["task"].as_str().unwrap()
        ))
        .await?;
        let path = format!("/api/v2/policies/{policy}");
        let request = op(0, configuration_definition(&resource, "v1", scope));
        ensure!(
            self.browser
                .call(&self.router, Method::POST, &path, Some(request.clone()))
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
        grants.push(json!({"operation":"firewall_write","scope":{"kind":"all_devices"}}));
        grants.push(json!({"operation":"inventory_read","scope":{"kind":"all_devices"}}));
        ensure!(self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{rule}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":{"subject":subject,"grants":grants}}))).await?.0==StatusCode::OK);
        // A stable Unknown exclusion retains a pending owner. An independent
        // fresh Scope requiring the identical effect must still be able to apply.
        let unknown_group = Uuid::new_v4();
        let g=self.product(&format!("groups/{unknown_group}"),op(0,json!({"action":"create","name":"unknown exclusion","description":"","criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":true}}}))).await?;
        self.wait_preview(&format!(
            "/api/v2/groups/{unknown_group}/tasks/{}",
            g["task"].as_str().unwrap()
        ))
        .await?;
        let uncertain_scope = Uuid::new_v4();
        let s=self.product(&format!("scopes/{uncertain_scope}"),op(0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":DEVICE}],"limitations":null,"exclusions":[{"kind":"group","id":unknown_group}]}}))).await?;
        self.wait_preview(&format!(
            "/api/v2/scopes/{uncertain_scope}/tasks/{}",
            s["task"].as_str().unwrap()
        ))
        .await?;
        let pending_policy = Uuid::new_v4().to_string();
        self.product(
            &format!("policies/{pending_policy}"),
            op(
                0,
                configuration_definition(&resource, "v1", uncertain_scope),
            ),
        )
        .await?;
        self.pending_configuration_input()
            .await
            .context("pending configuration input")?;
        let mut command_owner = self.command_worker()?;
        self.settled_configuration(&pending_policy)
            .await
            .context("pending policy settlement")?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let diagnosis:Option<String>=sqlx::query_scalar("SELECT diagnosis FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2").bind(TENANT).bind(DEVICE).fetch_one(&mut db).await?;
        ensure!(
            diagnosis.as_deref() == Some("waiting_scope"),
            "Unknown exclusion did not retain pending claim: {diagnosis:?}"
        );
        let accepted = self
            .product(&format!("policies/{policy}"), request.clone())
            .await?;
        ensure!(accepted == self.product(&format!("policies/{policy}"), request).await?);
        let operation = self
            .wait_configuration(&policy, None)
            .await
            .context("first configuration dispatch")?;
        // The native command has been published but no device ACK exists yet.
        ensure!(command_owner.shutdown().join().await?.is_clean());
        command_owner = self.command_worker()?;
        ensure!(self.wait_configuration(&policy, None).await? == operation);
        self.product(
            &format!("policies/{pending_policy}"),
            op(1, json!({"action":"disable"})),
        )
        .await?;
        self.settled_configuration(&pending_policy)
            .await
            .context("pending policy settlement")?;
        let write = native::begin(peer, url, initial, ack, 951, None).await?;
        let response = peer_reply(
            peer,
            url,
            &native::report(&write.first, &write.gets, "10.0.19045.0", 200),
        )
        .await?;
        if !response
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Replace { .. }))
        {
            let mut pg = sqlx::PgConnection::connect_with(&crate::device::test_support::options(
                "postgres",
            )?)
            .await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
                .bind(TENANT)
                .execute(&mut pg)
                .await?;
            let diagnostic:Value=sqlx::query_scalar("SELECT jsonb_build_object('command',d.status,'scope',mdm_planning.scope_admission($2::uuid,$3),'task',o.request,'capabilities',(SELECT to_jsonb(c) FROM mdm_commands.capabilities c WHERE c.registration=o.registration),'assignment',(SELECT to_jsonb(x) FROM mdm_planning.configuration_devices x WHERE x.device=$3)) FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.command_id=o.id::text WHERE o.id=$1").bind(operation).bind(scope).bind(DEVICE).fetch_one(&mut pg).await?;
            anyhow::bail!("missing automatic native configuration: {diagnostic}");
        }
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
        // Identical assignments share one native effect and one necessary command.
        let shared = Uuid::new_v4().to_string();
        self.product(
            &format!("policies/{shared}"),
            op(0, configuration_definition(&resource, "v1", scope)),
        )
        .await?;
        ensure!(
            self.wait_configuration(&shared, None).await? == operation,
            "same configuration duplicated native work"
        );
        // The original authoring assignment may exit while another still needs
        // the same effect; the accepted command remains valid without duplication.
        ensure!(command_owner.shutdown().join().await?.is_clean());
        self.product(
            &format!("policies/{policy}"),
            op(1, json!({"action":"disable"})),
        )
        .await?;
        self.pending_configuration_input()
            .await
            .context("pending configuration input")?;
        command_owner = self.command_worker()?;
        self.settled_configuration(&policy).await?;
        ensure!(self.wait_configuration(&shared, None).await? == operation);
        ensure!(
            self.call(Method::GET, &format!("/{operation}"), None)
                .await?
                .1["commandStatus"]
                == "received"
        );
        self.product(
            &format!("policies/{policy}"),
            op(2, json!({"action":"enable"})),
        )
        .await?;
        self.product(
            &format!("policies/{shared}"),
            op(1, json!({"action":"disable"})),
        )
        .await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM mdm_planning.configuration_claims WHERE policy=$1::uuid",
                )
                .bind(&shared)
                .fetch_one(&mut db)
                .await?;
                if count == 0 {
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        ensure!(self.wait_configuration(&policy, None).await? == operation);
        // A new frozen version cancels the old command, without claiming cleanup.
        let next = self
            .next_configuration(&resource, &policy, scope, false, 2, operation)
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
        // Removing targets retires the assignment but cannot claim to undo a Windows CSP write.
        let current = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v2/policies/{policy}"),
                None,
            )
            .await?;
        self.product(
            &format!("policies/{policy}"),
            op(
                current.1["revision"].as_u64().unwrap(),
                json!({"action":"disable"}),
            ),
        )
        .await?;
        let remote = Uuid::new_v4();
        self.product("remote-operations",json!({"operationId":remote,"resource":{"id":resource,"version":"v2","platform":"windows","architecture":"x86_64","variant":"domain-firewall"},"targets":{"kind":"devices","devices":[DEVICE]},"action":{"kind":"apply_configuration"},"deadline":self.app.clock.unix_seconds()?+300})).await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let remote_command=tokio::time::timeout(Duration::from_secs(30),async {loop {let id:Option<Uuid>=sqlx::query_scalar("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.remote_operation=$1 AND d.status='published'").bind(remote).fetch_optional(&mut db).await?;if let Some(id)=id {break Ok::<_,anyhow::Error>(id);}tokio::time::sleep(Duration::from_millis(50)).await;}}).await??;
        ensure!(
            self.call(
                Method::POST,
                &format!("/{remote_command}/approve"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::CONFLICT,
            "native reapproval changed remote authority"
        );
        let third = native::begin(peer, url, initial, ack, 953, None).await?;
        let reply = peer_reply(
            peer,
            url,
            &native::report(&third.first, &third.gets, "10.0.19045.0", 200),
        )
        .await?;
        assert_work(
            &reply,
            &[("replace", rss_mdm_windows_mdm::configuration::FIREWALL_URI)],
        )?;
        let cancelled = self
            .product(
                &format!("remote-operations/{remote}/cancel"),
                json!({"operationId":Uuid::new_v4()}),
            )
            .await?;
        ensure!(cancelled["cancellationRequested"] == true);
        ensure!(command_owner.shutdown().join().await?.is_clean());
        ensure!(automation_owner.shutdown().join().await?.is_clean());
        Ok(())
    }
    fn command_worker(&self) -> anyhow::Result<rss_runtime::ShutdownStack> {
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = owner.startup()?.commit();
        launch.stage_deferred_task_with_token(self.app.execution.clone().registration().critical());
        launch.finish();
        Ok(owner)
    }
    async fn pending_configuration_input(&self) -> anyhow::Result<()> {
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(30),async {loop {
            let dirty:bool=sqlx::query_scalar("SELECT coalesce((SELECT input_revision>observed_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2),false)").bind(TENANT).bind(DEVICE).fetch_one(&mut db).await?;
            if dirty {return Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await?
    }
    async fn settled_configuration(&self, policy: &str) -> anyhow::Result<()> {
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let settled=tokio::time::timeout(Duration::from_secs(30),async {loop {
            let ready:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND kind='policy_reconcile' AND target=$2 AND NOT completed) AND coalesce((SELECT observed_revision=input_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$3),false)").bind(TENANT).bind(policy).bind(DEVICE).fetch_one(&mut db).await?;
            if ready{return Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await;
        if settled.is_err() {
            let state = crate::test_support::pg(&format!(
                "SELECT jsonb_build_object('device',(SELECT to_jsonb(d) FROM mdm_planning.configuration_devices d WHERE tenant_id='{TENANT}' AND device='{DEVICE}'),'jobs',(SELECT jsonb_agg(jsonb_build_object('kind',kind,'target',target,'completed',completed,'failure',failure)) FROM mdm_automation.automation_jobs WHERE tenant_id='{TENANT}' AND NOT completed))"
            ))?;
            anyhow::bail!("pending configuration did not settle: {state}");
        }
        settled?
    }
    async fn wait_configuration(
        &mut self,
        policy: &str,
        previous: Option<Uuid>,
    ) -> anyhow::Result<Uuid> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(30),async {loop {
            let id:Option<Uuid>=sqlx::query_scalar("SELECT c.operation FROM mdm_planning.configuration_claims c JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(c.tenant_id,c.operation) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE c.tenant_id=$1::uuid AND c.policy=$2::uuid AND c.device=$3 AND o.gateway_accepted AND d.status IN('published','received') AND ($4::uuid IS NULL OR c.operation<>$4)").bind(TENANT).bind(policy).bind(DEVICE).bind(previous).fetch_optional(&mut pg).await?;
            if let Some(id)=id {return Ok::<_,anyhow::Error>(id);}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await?
    }
    async fn next_configuration(
        &mut self,
        resource: &str,
        policy: &str,
        scope: Uuid,
        enabled: bool,
        version: u64,
        previous: Uuid,
    ) -> anyhow::Result<Uuid> {
        let op = |revision, input| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
        let r = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v3/resources/{resource}"),
                None,
            )
            .await?;
        self.product(&format!("resources/{resource}"),op(r.1["revision"].as_u64().unwrap(),json!({"action":"firewall_version","version":format!("v{version}"),"enabled":enabled}))).await?;
        let r = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v3/resources/{resource}"),
                None,
            )
            .await?;
        self.product(
            &format!("resources/{resource}"),
            op(
                r.1["revision"].as_u64().unwrap(),
                json!({"action":"activate","version":format!("v{version}")}),
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
        self.product(
            &format!("policies/{policy}"),
            op(
                p.1["revision"].as_u64().unwrap(),
                configuration_definition(resource, &format!("v{version}"), scope),
            ),
        )
        .await?;
        self.wait_configuration(policy, Some(previous)).await
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

fn configuration_definition(resource: &str, version: &str, scope: Uuid) -> Value {
    json!({"action":"put","enabled":true,"definition":{"resource":{"id":resource,"version":version,"platform":"windows","architecture":"x86_64","variant":"domain-firewall"},"scope":scope,"behavior":{"kind":"configuration","exit":"retain"}}})
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.firewall"]
async fn policy_replace_get_and_ownership() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client
        .firewall_cycle(&peer.mutual, &peer.url, &peer.message, &peer.ack)
        .await?;
    host.close().await?;
    Ok(())
}
