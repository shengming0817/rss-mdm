use super::*;
pub(super) struct Fixture<'a> {
    pub peer: &'a reqwest::Client,
    pub url: &'a str,
    pub initial: &'a s::Message,
    pub ack: &'a s::Message,
    pub resource: &'a str,
    pub policy: &'a str,
    pub scope: Uuid,
}
impl Client {
    pub(super) async fn boundary_tests(&mut self, f: Fixture<'_>) -> anyhow::Result<()> {
        for (version, value) in [(3, "1"), (4, "2"), (5, "3"), (6, "4")] {
            let operation = self
                .next_firewall_plan(f.resource, f.policy, f.scope, true, version, None)
                .await?;
            self.publish_operation(operation).await?;
            let (receipt, replace) = start_write(&f, 960 + version as u32).await?;
            let observe = peer_reply(f.peer, f.url, &receipt).await?;
            assert_work(
                &observe,
                &[("get", rss_mdm_windows_mdm::configuration::STATUS_URI)],
            )?;
            let get = get_id(&observe);
            let result = readback(&receipt, get, value);
            assert_work(&peer_reply(f.peer, f.url, &result).await?, &[])?;
            let read = self
                .call(Method::GET, &format!("/{operation}"), None)
                .await?;
            ensure!(
                read.1["commandStatus"] == "received"
                    && read.1["observation"]["effect"] == "unknown"
                    && read.1["observation"]["value"] == value
                    && read.1["observation"]["receiptAccepted"] == true
            );
            let _ = replace;
        }
        // A cancelled write's late success is retained but never accepted as execution success.
        let operation = self
            .next_firewall_plan(f.resource, f.policy, f.scope, true, 7, None)
            .await?;
        self.publish_operation(operation).await?;
        let (receipt, _) = start_write(&f, 967).await?;
        ensure!(
            self.call(
                Method::POST,
                &format!("/{operation}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::OK
        );
        assert_work(&peer_reply(f.peer, f.url, &receipt).await?, &[])?;
        let read = self
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "cancelled"
                && read.1["observation"]["progress"] != "succeeded"
                && read.1["observation"]["receiptAccepted"] == false
        );
        // Supersede before acknowledgement; old 200 cannot advance either version.
        let old = self
            .next_firewall_plan(f.resource, f.policy, f.scope, true, 8, None)
            .await?;
        self.publish_operation(old).await?;
        let (late, _) = start_write(&f, 968).await?;
        let new = self
            .next_firewall_plan(f.resource, f.policy, f.scope, false, 9, None)
            .await?;
        assert_work(&peer_reply(f.peer, f.url, &late).await?, &[])?;
        let previous = self.call(Method::GET, &format!("/{old}"), None).await?;
        ensure!(
            previous.1["commandStatus"] == "cancelled"
                && previous.1["observation"]["receiptAccepted"] == false
        );
        let current = self.call(Method::GET, &format!("/{new}"), None).await?;
        ensure!(current.1["observation"]["effect"] == "unknown");
        // A missing observation reaches the deadline without rewriting an acknowledged value.
        let deadline = self.app.clock.unix_seconds()? + 5;
        let missing = self
            .next_firewall_plan(f.resource, f.policy, f.scope, true, 10, Some(deadline))
            .await?;
        self.publish_operation(missing).await?;
        let (receipt, _) = start_write(&f, 970).await?;
        let observe = peer_reply(f.peer, f.url, &receipt).await?;
        assert_work(
            &observe,
            &[("get", rss_mdm_windows_mdm::configuration::STATUS_URI)],
        )?;
        let wait = (deadline - self.app.clock.unix_seconds()?).max(0) as u64;
        tokio::time::sleep(Duration::from_secs(wait + 1)).await;
        self.publish_operation(missing).await?;
        let mut no_result = receipt.clone();
        no_result.header.message_id = 5;
        no_result.commands = vec![status(1, 4, 0, s::CommandName::SyncHdr)];
        assert_work(&peer_reply(f.peer, f.url, &no_result).await?, &[])?;
        let state = self.call(Method::GET, &format!("/{missing}"), None).await?;
        ensure!(
            state.1["commandStatus"] == "timed_out"
                && state.1["observation"]["progress"] == "succeeded"
                && state.1["observation"]["effect"] == "unknown"
                && state.1["observation"]["quality"] == "missing"
        );
        // Expiry before the write ACK fences a late 200 as historical evidence only.
        let deadline = self.app.clock.unix_seconds()? + 5;
        let expired = self
            .next_firewall_plan(f.resource, f.policy, f.scope, true, 11, Some(deadline))
            .await?;
        self.publish_operation(expired).await?;
        let (late, _) = start_write(&f, 971).await?;
        let wait = (deadline - self.app.clock.unix_seconds()?).max(0) as u64;
        tokio::time::sleep(Duration::from_secs(wait + 1)).await;
        self.publish_operation(expired).await?;
        assert_work(&peer_reply(f.peer, f.url, &late).await?, &[])?;
        let state = self.call(Method::GET, &format!("/{expired}"), None).await?;
        ensure!(
            state.1["commandStatus"] == "timed_out"
                && state.1["observation"]["receiptAccepted"] == false
                && state.1["observation"]["progress"] != "succeeded"
        );
        let new = self
            .next_firewall_plan(f.resource, f.policy, f.scope, false, 12, None)
            .await?;
        Box::pin(self.stale_scope(&f, new)).await?;
        // Archive consumes a cancel-only frozen plan, including an unfinished command.
        let p = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v1/policies/{}", f.policy),
                None,
            )
            .await?;
        let p=self.product(&format!("policies/{}",f.policy),json!({"operationId":Uuid::new_v4(),"expectedRevision":p.1["storageRevision"],"input":{"action":"archive"}})).await?;
        let archived = self
            .execute_existing_plan(f.policy, f.scope, p["storageRevision"].as_u64().unwrap())
            .await?;
        ensure!(
            archived["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["operationId"] == new.to_string() && o["action"] == "cancel")
        );
        let state = self.call(Method::GET, &format!("/{new}"), None).await?;
        ensure!(state.1["commandStatus"] == "cancelled");
        Box::pin(self.fleet_boundary(&f)).await?;
        Ok(())
    }
    async fn stale_scope(&mut self, f: &Fixture<'_>, operation: Uuid) -> anyhow::Result<()> {
        self.publish_operation(operation).await?;
        let exchange = native::begin(f.peer, f.url, f.initial, f.ack, 972, None).await?;
        let request = native::report(&exchange.first, &exchange.gets, "10.0.19045.0", 200);
        let sent = peer_reply(f.peer, f.url, &request).await?;
        assert_work(
            &sent,
            &[("replace", rss_mdm_windows_mdm::configuration::FIREWALL_URI)],
        )?;
        self.product(&format!("scopes/{}", f.scope),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}})).await?;
        let replay = native::post(f.peer, f.url, &request).await?;
        ensure!(
            replay.status() == StatusCode::FORBIDDEN,
            "stale scope replay {}",
            replay.status()
        );
        // A fresh session receives its own capability Gets, but cannot regenerate the old write.
        let fresh = native::begin(f.peer, f.url, f.initial, f.ack, 973, None).await?;
        assert_work(
            &peer_reply(
                f.peer,
                f.url,
                &native::report(&fresh.first, &fresh.gets, "10.0.19045.0", 200),
            )
            .await?,
            &[],
        )?;
        Ok(())
    }
    async fn execute_existing_plan(
        &mut self,
        policy: &str,
        scope: Uuid,
        revision: u64,
    ) -> anyhow::Result<Value> {
        let preview = Uuid::new_v4();
        self.product(&format!("policies/{policy}/previews"),json!({"operationId":preview,"expectedRevision":revision,"input":{"scope":scope,"expectedRevision":revision}})).await?;
        let saved=self.product(&format!("policies/{policy}/plans"),json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"preview":preview}})).await?;
        self.product(&format!("policies/{policy}/plans/{preview}/execute"),json!({"operationId":Uuid::new_v4(),"expectedRevision":saved["receipt"]["storageRevision"],"deadline":self.app.clock.unix_seconds()?+300})).await
    }
}
async fn start_write(f: &Fixture<'_>, session: u32) -> anyhow::Result<(s::Message, u32)> {
    let exchange = native::begin(f.peer, f.url, f.initial, f.ack, session, None).await?;
    let response = peer_reply(
        f.peer,
        f.url,
        &native::report(&exchange.first, &exchange.gets, "10.0.19045.0", 200),
    )
    .await?;
    assert_work(
        &response,
        &[("replace", rss_mdm_windows_mdm::configuration::FIREWALL_URI)],
    )?;
    let id = response
        .commands
        .iter()
        .find_map(|c| {
            if let s::Command::Replace { id, .. } = c {
                Some(*id)
            } else {
                None
            }
        })
        .unwrap();
    let receipt = s::Message {
        header: s::Header {
            message_id: 4,
            credential: None,
            ..exchange.first.header
        },
        commands: vec![
            status(1, 3, 0, s::CommandName::SyncHdr),
            status(2, 3, id, s::CommandName::Replace),
        ],
        final_message: true,
    };
    Ok((receipt, id))
}
fn status(id: u32, message: u32, command_ref: u32, command: s::CommandName) -> s::Command {
    s::Command::Status(s::Status {
        id,
        message_ref: message,
        command_ref,
        command,
        target_refs: vec![],
        source_refs: vec![],
        code: 200,
        items: vec![],
        challenge: None,
        credential: None,
    })
}
fn get_id(message: &s::Message) -> u32 {
    message
        .commands
        .iter()
        .find_map(|c| {
            if let s::Command::Get { id, .. } = c {
                Some(*id)
            } else {
                None
            }
        })
        .unwrap()
}
fn readback(receipt: &s::Message, id: u32, value: &str) -> s::Message {
    s::Message {
        header: s::Header {
            message_id: 5,
            ..receipt.header.clone()
        },
        commands: vec![
            status(1, 4, 0, s::CommandName::SyncHdr),
            status(2, 4, id, s::CommandName::Get),
            s::Command::Results(s::Results {
                id: 3,
                message_ref: Some(4),
                command_ref: Some(id),
                command: Some(s::CommandName::Get),
                meta: None,
                items: vec![s::Item {
                    source: Some(rss_mdm_windows_mdm::configuration::STATUS_URI.into()),
                    target: None,
                    meta: None,
                    data: Some(Secret(value.into())),
                }],
            }),
        ],
        final_message: true,
    }
}
impl Client {
    async fn fleet_boundary(&mut self, f: &Fixture<'_>) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        // Controlled admission fixtures; only the earlier peer tests claim authenticated transport coverage.
        let mut devices = Vec::new();
        for i in 0..33 {
            let device = format!("firewall-fleet-{i:02}");
            let registration = Uuid::new_v4();
            let request = Uuid::new_v4();
            let grant = Uuid::new_v4();
            sqlx::query("INSERT INTO mdm_access.devices VALUES($1::uuid,$2)")
                .bind(TENANT)
                .bind(&device)
                .execute(&mut pg)
                .await?;
            sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES($1::uuid,$2::uuid,'fixture','fixture',$3,'enrollment','consumed',clock_timestamp()+interval '60 seconds')").bind(TENANT).bind(grant.to_string()).bind(&device).execute(&mut pg).await?;
            sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES($1::uuid,$2::uuid,$3::uuid)").bind(TENANT).bind(request.to_string()).bind(grant.to_string()).execute(&mut pg).await?;
            sqlx::query("INSERT INTO mdm_access.registrations VALUES($1::uuid,$2::uuid,$3,'mdm',1,$4::uuid,'active')").bind(TENANT).bind(registration.to_string()).bind(&device).bind(request.to_string()).execute(&mut pg).await?;
            sqlx::query("INSERT INTO mdm_commands.capabilities VALUES($1::uuid,$2::uuid,1,'10.0.19045.0',48,1,floor(extract(epoch FROM clock_timestamp()))::bigint)").bind(TENANT).bind(registration.to_string()).execute(&mut pg).await?;
            devices.push(device);
        }
        let grant = json!({"subject":{"kind":"user","user":crate::identity_fixture::user(TENANT,crate::identity_fixture::ADMIN)},"grants":[{"operation":"firewall_write","scope":{"kind":"all_devices"}},{"operation":"operation_cancel","scope":{"kind":"all_devices"}}]});
        ensure!(
            self.browser
                .call(
                    &self.router,
                    Method::PUT,
                    &format!("/api/v1/authorization/rules/{}", Uuid::new_v4()),
                    Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":grant}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        let policy = format!("fleet-{}", Uuid::new_v4());
        let scope = Uuid::new_v4();
        let op = |revision, input| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
        let created = self
            .product(
                &format!("policies/{policy}"),
                op(0, json!({"action":"create"})),
            )
            .await?;
        let activated=self.product(&format!("policies/{policy}"),op(created["storageRevision"].as_u64().unwrap(),json!({"action":"activate","version":1,"resource":f.resource,"resourceVersion":"v1"}))).await?;
        let definition = |count: usize| json!({"targets":devices[..count].iter().map(|id|json!({"kind":"device","id":id})).collect::<Vec<_>>(),"limitations":null,"exclusions":[]});
        self.product(
            &format!("scopes/{scope}"),
            op(0, json!({"action":"put","definition":definition(33)})),
        )
        .await?;
        let preview = Uuid::new_v4();
        let revision = activated["storageRevision"].as_u64().unwrap();
        let denied=self.browser.call(&self.router,Method::POST,&format!("/api/v1/policies/{policy}/previews"),Some(json!({"operationId":preview,"expectedRevision":revision,"input":{"scope":scope,"expectedRevision":revision}}))).await?;
        ensure!(
            denied.0 == StatusCode::BAD_REQUEST && denied.1["code"] == "configuration_target_limit",
            "33-device preview: {denied:?}"
        );
        ensure!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM mdm_management.previews WHERE id=$1::uuid"
            )
            .bind(preview.to_string())
            .fetch_one(&mut pg)
            .await?
                == 0
        );
        self.product(
            &format!("scopes/{scope}"),
            op(1, json!({"action":"put","definition":definition(32)})),
        )
        .await?;
        let accepted = self.execute_existing_plan(&policy, scope, revision).await?;
        ensure!(accepted["operations"].as_array().unwrap().len() == 32);
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE request->'task'->>'policy'=$1),(SELECT count(*) FROM mdm_commands.firewall_owners WHERE policy=$1),(SELECT count(*) FROM rss_transactional_messaging.outbox b JOIN mdm_commands.operations o ON b.message_id='dispatch.'||o.id::text AND b.tenant_id=o.tenant_id WHERE o.request->'task'->>'policy'=$1)").bind(&policy).fetch_one(&mut pg).await?;
        ensure!(
            counts == (32, 32, 32),
            "partial fleet acceptance: {counts:?}"
        );
        // Terminal command cancellation must not let a second active policy steal the node.
        let held = accepted["operations"][0]["operationId"].as_str().unwrap();
        let first = &devices[0];
        ensure!(
            self.browser
                .call(
                    &self.router,
                    Method::POST,
                    &format!("/api/v1/devices/{first}/operations/{held}/cancel"),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        let competitor = format!("conflict-{}", Uuid::new_v4());
        let small = Uuid::new_v4();
        let c = self
            .product(
                &format!("policies/{competitor}"),
                op(0, json!({"action":"create"})),
            )
            .await?;
        let c=self.product(&format!("policies/{competitor}"),op(c["storageRevision"].as_u64().unwrap(),json!({"action":"activate","version":1,"resource":f.resource,"resourceVersion":"v1"}))).await?;
        self.product(
            &format!("scopes/{small}"),
            op(0, json!({"action":"put","definition":definition(1)})),
        )
        .await?;
        let p = Uuid::new_v4();
        self.product(&format!("policies/{competitor}/previews"),json!({"operationId":p,"expectedRevision":c["storageRevision"],"input":{"scope":small,"expectedRevision":c["storageRevision"]}})).await?;
        let saved = self
            .product(
                &format!("policies/{competitor}/plans"),
                op(c["storageRevision"].as_u64().unwrap(), json!({"preview":p})),
            )
            .await?;
        let request = json!({"operationId":Uuid::new_v4(),"expectedRevision":saved["receipt"]["storageRevision"],"deadline":self.app.clock.unix_seconds()?+300});
        let conflict = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("/api/v1/policies/{competitor}/plans/{p}/execute"),
                Some(request),
            )
            .await?;
        ensure!(conflict.0 == StatusCode::CONFLICT);
        ensure!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM mdm_commands.operations WHERE request->'task'->>'policy'=$1"
            )
            .bind(&competitor)
            .fetch_one(&mut pg)
            .await?
                == 0
        );
        // Scope exit is a cancel-only plan; no target capability defaults are invented.
        self.product(
            &format!("scopes/{scope}"),
            op(2, json!({"action":"put","definition":definition(0)})),
        )
        .await?;
        let current = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v1/policies/{policy}"),
                None,
            )
            .await?;
        let exited = self
            .execute_existing_plan(
                &policy,
                scope,
                current.1["storageRevision"].as_u64().unwrap(),
            )
            .await?;
        ensure!(exited["operations"].as_array().unwrap().len() == 32);
        ensure!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM mdm_commands.firewall_owners WHERE policy=$1"
            )
            .bind(&policy)
            .fetch_one(&mut pg)
            .await?
                == 0
        );
        // Settle this scenario's queue through the real relay before the later restart test.
        let relay = self.app.commands.clone();
        let count = accepted["operations"].as_array().unwrap().len();
        tokio::spawn(async move {
            for _ in 0..=count {
                relay.relay_once().await?;
            }
            Ok::<(), Error>(())
        })
        .await??;
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox b JOIN mdm_commands.operations o ON b.message_id='dispatch.'||o.id::text AND b.tenant_id=o.tenant_id WHERE o.request->'task'->>'policy'=$1 AND b.status<>'published'").bind(&policy).fetch_one(&mut pg).await?;
        ensure!(pending == 0, "fleet dispatch did not settle");
        pg.close().await?;
        Ok(())
    }
}
