//! Persistent configuration owns the native effect through install and removal recovery.
use super::*;
use rss_mdm_apple_mdm::profile;
use serde_json::Value;
use sqlx::Connection;
impl Fixture {
    async fn policy_post(&mut self, path: &str, revision: u64, input: Value) -> Result<Value> {
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                path,
                Some(
                    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input}),
                ),
            )
            .await?;
        ensure!(reply.0.is_success(), "{path}: {reply:?}");
        Ok(reply.1)
    }
    async fn policy_operation(&self, policy: Uuid) -> Result<Uuid> {
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(30),async {loop {
            let id:Option<Uuid>=sqlx::query_scalar("SELECT c.operation FROM mdm_planning.configuration_claims c JOIN rss_device_command.commands d ON d.tenant_id=c.tenant_id AND d.command_id=c.operation::text WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND d.status IN('published','received','applied')").bind(case_tenant()).bind(policy).fetch_optional(&mut db).await?;
            if let Some(id)=id {return Ok::<_,anyhow::Error>(id);}tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await?
    }
    pub(super) async fn policy_cycle(&mut self, peer: &lifecycle::Peer) -> Result<()> {
        let mut grants = crate::test_support::identity::device_grants(
            Some(case_device()),
            &[
                "enrollment",
                "credentials",
                "inventory_read",
                "inventory_collect",
                "firewall_write",
                "operation_read",
                "operation_cancel",
            ],
        )?;
        for operation in [
            crate::authorization::Permission::ResourceRead,
            crate::authorization::Permission::ResourceWrite,
            crate::authorization::Permission::PolicyRead,
            crate::authorization::Permission::PolicyWrite,
            crate::authorization::Permission::ScopeRead,
            crate::authorization::Permission::ScopeWrite,
        ] {
            grants.push(crate::authorization::Grant {
                operation,
                scope: crate::authorization::Scope::Tenant,
            });
        }
        grants.extend(crate::test_support::identity::device_grants(
            None,
            &["inventory_read", "firewall_write"],
        )?);
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            grants,
        )
        .await?;
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let automation = crate::automation::Automation::connect(
            self.app.flow.planning.clone(),
            self.app.flow.assets.clone(),
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?;
        let mut startup = owner.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            crate::automation::Resource(automation.clone()),
        ));
        let mut launch = startup.commit();
        launch.stage_deferred_task_with_token(
            automation.registration(self.signals.flow()).critical(),
        );
        launch.finish();
        let resource = format!("profile-{}", Uuid::new_v4());
        let path = format!("/api/v3/resources/{resource}");
        self.policy_post(&path, 0, json!({"action":"create","kind":"configuration"}))
            .await?;
        self.policy_post(
            &path,
            1,
            json!({"action":"firewall_version","version":"v1","enabled":true}),
        )
        .await?;
        let current = self
            .browser
            .call(&self.router, Method::GET, &path, None)
            .await?;
        self.policy_post(
            &path,
            current.1["revision"].as_u64().unwrap(),
            json!({"action":"activate","version":"v1"}),
        )
        .await?;
        let scope = Uuid::new_v4();
        self.policy_post(&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
        let definition = json!({"scope":scope,"action": {"resource": {"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"firewall-profile"},"kind":"configuration","exit":"remove"}});
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        self.policy_post(
            &format!("/api/v2/policies/{first}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        let install = self.policy_operation(first).await?;
        let (execute, _) = peer.next("InstallProfile").await?;
        let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
        let (observe, _) = lifecycle::command(&bytes, "ProfileList")?;
        peer.manage(
            "Acknowledged",
            Some(observe),
            Some((
                "ProfileList",
                plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
                    (
                        "PayloadIdentifier",
                        profile::identifier(case_tenant(), case_device()).into(),
                    ),
                    ("PayloadUUID", install.to_string().into()),
                    ("PayloadVersion", 1.into()),
                ]))]),
            )),
        )
        .await?;
        ensure!(self.operation(install).await?["commandStatus"] == "applied");
        self.policy_post(
            &format!("/api/v2/policies/{second}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        ensure!(self.policy_operation(second).await? == install);
        self.policy_post(
            &format!("/api/v2/policies/{first}"),
            1,
            json!({"action":"disable"}),
        )
        .await?;
        ensure!(self.policy_operation(second).await? == install);
        self.policy_post(
            &format!("/api/v2/policies/{second}"),
            1,
            json!({"action":"disable"}),
        )
        .await?;
        let (remove, _) = peer.next("RemoveProfile").await?;
        // A real native rejection must retain cleanup intent and admit another
        // bounded command through the same existing queue, without administrator action.
        peer.manage("Error", Some(remove), None).await?;
        let (retry, _) = peer.next("RemoveProfile").await?;
        ensure!(retry != remove);
        let bytes = peer.manage("Acknowledged", Some(retry), None).await?;
        let (observe, _) = lifecycle::command(&bytes, "ProfileList")?;
        peer.manage(
            "Acknowledged",
            Some(observe),
            Some(("ProfileList", plist::Value::Array(vec![]))),
        )
        .await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(30),async {loop {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2").bind(case_tenant()).bind(case_device()).fetch_one(&mut db).await?;
            if count==0 {return Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await??;
        ensure!(owner.shutdown().join().await?.is_clean());
        Ok(())
    }
}

use lifecycle::Peer;
impl Fixture {
    async fn approval_and_timeout(&mut self, peer: &Peer) -> Result<()> {
        let op = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        let path = format!(
            "/api/v1/devices/{DEVICE}/collection-runs",
            DEVICE = case_device()
        );
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &path,
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::ACCEPTED);
        let run = reply.1["runId"].as_str().unwrap();
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            crate::test_support::identity::device_grants(
                Some(case_device()),
                &[
                    "enrollment",
                    "credentials",
                    "inventory_read",
                    "operation_read",
                    "operation_cancel",
                ],
            )?,
        )
        .await?;
        let refused = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &path,
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(refused.0 == StatusCode::FORBIDDEN);
        let (accepted, _) = peer.next("DeviceInformation").await?;
        ensure!(
            accepted.to_string() == run,
            "accepted collection changed after author permission update"
        );
        ensure!(self.operation(op).await?["authorization"] == "blocked");
        ensure!(
            self.app
                .execution
                .apple_wake(&self.app.apple()?.channel.push_fixture().configuration)
                .await?
                .is_none(),
            "revoked approval triggered APNs"
        );
        let cancelled = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!(
                    "/api/v2/devices/{DEVICE}/operations/{op}/cancel",
                    DEVICE = case_device()
                ),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1})),
            )
            .await?;
        ensure!(cancelled.0 == StatusCode::OK);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(case_tenant())
            .execute(&mut pg)
            .await?;
        // Provider time injection, not a fabricated device response or result.
        let audited = crate::audit_test_support::read(&mut pg)
            .await?
            .iter()
            .any(|r| {
                r.action() == "collection_start" && r.result() == "denied" && r.actor().is_some()
            });
        ensure!(audited, "collection denial lost business action audit");
        sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1::uuid").bind(run).execute(&mut pg).await?;
        let mut terminal = false;
        for _ in 0..100 {
            let row:(String,Option<String>,bool)=sqlx::query_as("SELECT result,reason,batch IS NULL FROM mdm_access.collection_runs WHERE id=$1::uuid").bind(run).fetch_one(&mut pg).await?;
            if row == ("failed".into(), Some("timeout".into()), true) {
                terminal = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(
            terminal,
            "unreported collection did not expire without an Observation report"
        );
        let terminal = crate::audit_test_support::read(&mut pg).await?;
        ensure!(terminal.iter().any(|r| r.action() == "collection_finish"
            && r.operation() == Some(run.to_string().as_str())
            && r.actor() == Some("service:collection-finalizer")));
        pg.close().await?;
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            crate::test_support::identity::device_grants(
                Some(case_device()),
                &[
                    "enrollment",
                    "credentials",
                    "inventory_read",
                    "inventory_collect",
                    "firewall_write",
                    "operation_read",
                    "operation_cancel",
                ],
            )?,
        )
        .await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.policy: native protocol and durable state"]
async fn configuration_policy_lifecycle() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.policy_cycle(&peer).await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.policy: native protocol and durable state"]
async fn current_approval_and_deadlines() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.approval_and_timeout(&peer).await?;
    drop(device);
    f.close().await
}
