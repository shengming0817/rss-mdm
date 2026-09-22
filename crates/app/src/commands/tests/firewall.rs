//! Real authenticated product authoring -> frozen plan -> native Replace -> independent Get.
use super::*;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
impl Client {
    async fn product(&mut self, path: &str, body: Value) -> anyhow::Result<Value> {
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("/api/v1/{path}"),
                Some(body),
            )
            .await?;
        ensure!(reply.0.is_success(), "{path}: {reply:?}");
        Ok(reply.1)
    }
    pub(super) async fn firewall_cycle(
        &mut self,
        peer: &reqwest::Client,
        url: &str,
        initial: &s::Message,
        ack: &s::Message,
    ) -> anyhow::Result<()> {
        let cap = native::begin(peer, url, initial, ack, 950).await?;
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
            frozen["configuration"]["enabled"] == true
                && frozen["configuration"]["ddf"] == "DDFv2Feb2026"
        );
        let saved = self
            .product(
                &format!("policies/{policy}/plans"),
                op(revision, json!({"preview":preview})),
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
                .call(&self.router, Method::POST, &path, Some(request))
                .await?
                == accepted
        );
        let operation =
            Uuid::parse_str(accepted.1["operations"][0]["operationId"].as_str().unwrap())?;
        self.publish_operation(operation).await?;
        let write = native::begin(peer, url, initial, ack, 951).await?;
        let response = peer_reply(
            peer,
            url,
            &native::report(&write.first, &write.gets, "10.0.19045.0", 200),
        )
        .await?;
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
            .next_firewall_plan(&resource, &policy, scope, false)
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
        let second = native::begin(peer, url, initial, ack, 952).await?;
        let response = peer_reply(
            peer,
            url,
            &native::report(&second.first, &second.gets, "10.0.19045.0", 200),
        )
        .await?;
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
        Ok(())
    }
    async fn next_firewall_plan(
        &mut self,
        resource: &str,
        policy: &str,
        scope: Uuid,
        enabled: bool,
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
                json!({"action":"firewall_version","version":"v2","enabled":enabled}),
            ),
        )
        .await?;
        let p = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v1/policies/{policy}"),
                None,
            )
            .await?;
        ensure!(p.0 == StatusCode::OK);
        let p=self.product(&format!("policies/{policy}"),op(p.1["storageRevision"].as_u64().unwrap(),json!({"action":"activate","version":2,"resource":resource,"resourceVersion":"v2"}))).await?;
        let revision = p["storageRevision"].as_u64().unwrap();
        let preview = Uuid::new_v4();
        self.product(&format!("policies/{policy}/previews"),json!({"operationId":preview,"expectedRevision":revision,"input":{"scope":scope,"expectedRevision":revision}})).await?;
        let saved = self
            .product(
                &format!("policies/{policy}/plans"),
                op(revision, json!({"preview":preview})),
            )
            .await?;
        let result=self.product(&format!("policies/{policy}/plans/{preview}/execute"),json!({"operationId":Uuid::new_v4(),"expectedRevision":saved["receipt"]["storageRevision"],"deadline":self.app.clock.unix_seconds()?+300})).await?;
        Ok(Uuid::parse_str(
            result["operations"][0]["operationId"].as_str().unwrap(),
        )?)
    }
}
async fn peer_reply(
    peer: &reqwest::Client,
    url: &str,
    message: &s::Message,
) -> anyhow::Result<s::Message> {
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
