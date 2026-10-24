//! Persistent configuration owns the native effect through install and removal recovery.
use super::*;
use serde_json::Value;
use sqlx::Connection;
impl Fixture {
    pub(super) async fn policy_post(
        &mut self,
        path: &str,
        revision: u64,
        input: Value,
    ) -> Result<Value> {
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
    pub(super) async fn policy_operation(&self, policy: Uuid) -> Result<Uuid> {
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let result = tokio::time::timeout(Duration::from_secs(30),async {loop {
            let id:Option<Uuid>=sqlx::query_scalar("SELECT c.operation FROM mdm_planning.configuration_claims c JOIN rss_device_command.commands d ON d.tenant_id=c.tenant_id AND d.command_id=c.operation::text WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND d.status IN('published','received','applied')").bind(case_tenant()).bind(policy).fetch_optional(&mut db).await?;
            if let Some(id)=id {return Ok::<_,anyhow::Error>(id);}tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await?;
        db.close().await?;
        result
    }
    pub(super) async fn policy_worker(&self) -> Result<rss_runtime::ShutdownStack> {
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let automation = crate::automation::Automation::connect(
            crate::automation::PlanningWork::connect(
                self.app.flow.planning.clone(),
                crate::device::test_support::options("mdm_flow_runtime")?
                    .password("runtime-fixture"),
            )
            .await?,
            self.app.flow.assets.clone(),
            self.app.flow.compliance.clone(),
        )
        .await?;
        let mut startup = owner.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            crate::automation::Resource(automation.work.clone()),
        ));
        let mut launch = startup.commit();
        launch.stage_deferred_task_with_token(
            automation.registration(self.signals.flow()).critical(),
        );
        launch.finish();
        Ok(owner)
    }
    pub(super) fn policy_grants() -> Result<Vec<crate::authorization::Grant>> {
        let mut grants = crate::test_support::identity::device_grants(
            Some(case_device()),
            &[
                "enrollment",
                "credentials",
                "inventory_read",
                "inventory_collect",
                "configuration_write",
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
            &["inventory_read", "inventory_collect", "configuration_write"],
        )?);
        Ok(grants)
    }
    pub(super) async fn configuration_policy(
        &mut self,
        apply: Value,
        remove: Option<Value>,
        exit: &str,
    ) -> Result<(Uuid, Uuid)> {
        let resource = Uuid::new_v4();
        crate::test_support::planning_http::native_configuration_resource(
            &mut self.browser,
            &self.router,
            resource,
            "macos",
            "aarch64",
            json!({"target":{"kind":"device"},"apply":apply,"remove":remove}),
        )
        .await?;
        let scope = Uuid::new_v4();
        self.policy_post(&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
        let policy = Uuid::new_v4();
        self.policy_post(&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration","exit":exit}}})).await?;
        Ok((policy, self.policy_operation(policy).await?))
    }
    pub(super) async fn policy_claims_released(&self, policy: Uuid) -> Result<()> {
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(30), async { loop {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2")
                .bind(case_tenant()).bind(policy).fetch_one(&mut db).await?;
            if count == 0 { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await??;
        db.close().await?;
        Ok(())
    }
    // Prepare one authorized operation and its retained prerequisite evidence.
    // Control admission and actual response intake remain the protocol tests' actions.
    pub(super) async fn native_context(&mut self) -> Result<()> {
        use crate::authorization::{OperationAuthority, Permission};
        use rss_mdm_execution_service::{authority::ExecutionAuthority, device_control::Kind};
        crate::test_support::identity::seed_grants(case_tenant(), crate::test_support::case::admin(), Fixture::native_grants(&["device_control"])?).await?;
        let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let snapshot =
            crate::authorization::snapshot_on(&mut db, case_tenant(), &proof.user()?.instance_id)
                .await?;
        let authority = ExecutionAuthority::DeviceControl {
            action: Kind::Restart,
            confirmation: None,
            required: vec![Permission::DeviceControl],
            evidence: vec![OperationAuthority::from_proof(
                &snapshot,
                &proof,
                case_device(),
                Permission::DeviceControl,
            )?],
        };
        let operation = Uuid::new_v4();
        let input = rss_mdm_execution_service::Create {
            operation_id: operation,
            input_version: "device-control-v1".into(),
            target: rss_mdm_execution_service::NativeTarget::Device,
            task: rss_mdm_execution_service::Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Command {
                    command: rss_mdm_apple_mdm::native::input::CommandInput {
                        request_type: "RestartDevice".into(),
                        fields: Default::default(),
                    },
                },
            },
            deadline: self.app.clock.unix_seconds()? + 300,
        };
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "command_accept");
        proof.bind_audit(&audit)?;
        let fingerprint = input
            .digest(
                &self.app.protection,
                rss_request_context::TenantId::parse(case_tenant())?,
                case_device(),
            )?
            .as_bytes()
            .to_vec();
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let source = self
            .app
            .audit_store
            .on_runtime(
                self.app.execution_runtime.clone(),
                rss_request_context::TenantId::parse(case_tenant())?,
                &budget.control(),
            )
            .await?;
        self.app
            .execution_runtime
            .local_tx_with_context(
                rss_request_context::TenantId::parse(case_tenant())?,
                crate::identity::deadline(),
                (&self.app.execution, &source, &audit),
                |(service, audit_store, audit), tx| {
                    Box::pin(async move {
                        audit_store.prepare_in(tx, audit, &[]).await.map_err(|e| {
                            rss_transactional_messaging_postgres::PgError::from(
                                sqlx::Error::Protocol(e.to_string()),
                            )
                        })?;
                        service
                            .queue_authorized_in(
                                tx,
                                case_device(),
                                &input,
                                authority,
                                fingerprint,
                                audit,
                            )
                            .await
                            .map_err(|e| {
                                rss_transactional_messaging_postgres::PgError::from(
                                    sqlx::Error::Protocol(e.to_string()),
                                )
                            })
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(anyhow::anyhow!(e)),
                |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("context preparation rollback unconfirmed")),
                |_| Err(anyhow::anyhow!("context preparation commit unconfirmed")),
                |e| Err(anyhow::anyhow!(e)),
            )?;
        audit.finalize(None);
        let mut tx = db.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *tx)
            .await?;
        self.app
            .apple()?
            .channel
            .prepare_context_fixture(&mut tx, case_tenant(), operation)
            .await?;
        tx.commit().await?;
        let detail = self.operation(operation).await?;
        let cancelled = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!(
                    "/api/v1/devices/{}/operations/{operation}/cancel",
                    case_device()
                ),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":detail["revision"]})),
            )
            .await?;
        ensure!(cancelled.0 == StatusCode::OK);
        db.close().await?;
        Ok(())
    }
    pub(super) async fn policy_cycle(&mut self, peer: &lifecycle::Peer) -> Result<()> {
        crate::test_support::identity::seed_grants(case_tenant(), crate::test_support::case::admin(), Fixture::policy_grants()?).await?;
        let owner = self.policy_worker().await?;
        let resource = Uuid::new_v4();
        let profile = Uuid::new_v4();
        crate::test_support::planning_http::native_configuration_resource(
            &mut self.browser, &self.router, resource, "macos", "aarch64",
            json!({"target":{"kind":"device"},"apply":profile_task(profile,true),"remove":remove_profile_task(profile)}),
        ).await?;
        let scope = Uuid::new_v4();
        self.policy_post(&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
        let definition = json!({"scope":scope,"action": {"resource": {"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration","exit":"remove"}});
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        self.policy_post(
            &format!("/api/v1/policies/{first}"),
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
                profile_manifest(profile, "com.apple.security.firewall"),
            )),
        )
        .await?;
        ensure!(self.operation(install).await?["commandStatus"] == "applied");
        self.policy_post(
            &format!("/api/v1/policies/{second}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        ensure!(self.policy_operation(second).await? == install);
        self.policy_post(
            &format!("/api/v1/policies/{first}"),
            1,
            json!({"action":"disable"}),
        )
        .await?;
        ensure!(self.policy_operation(second).await? == install);
        self.policy_post(
            &format!("/api/v1/policies/{second}"),
            1,
            json!({"action":"disable"}),
        )
        .await?;
        let (remove, _) = peer
            .next("RemoveProfile")
            .await
            .map_err(|e| e.context("initial shared-owner removal"))?;
        // Error alone preserves uncertain effects; a full unchanged manifest proves
        // the failed removal before Policy admits another independent cleanup command.
        let next = peer.manage("Error", Some(remove), None).await?;
        let (observe, _) = lifecycle::command(&next, "ProfileList")?;
        let mut incomplete = profile_manifest(profile, "com.apple.security.firewall");
        incomplete.as_array_mut().unwrap()[0]
            .as_dictionary_mut()
            .unwrap()
            .remove("PayloadContent");
        peer.manage(
            "Acknowledged",
            Some(observe),
            Some(("ProfileList", incomplete)),
        )
        .await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let operation: Uuid = sqlx::query_scalar(
            "SELECT operation FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(remove)
        .fetch_one(&mut db)
        .await?;
        db.close().await?;
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        self.profile_query_due(operation).await?;
        let (observe, _) = peer.next("ProfileList").await?;
        peer.manage(
            "Acknowledged",
            Some(observe),
            Some((
                "ProfileList",
                profile_manifest(profile, "com.apple.security.firewall"),
            )),
        )
        .await?;
        let (retry, _) = peer
            .next("RemoveProfile")
            .await
            .map_err(|e| e.context("retry after explicit negative removal receipt"))?;
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
        db.close().await?;
        ensure!(owner.shutdown().join().await?.is_clean());
        Ok(())
    }
}

use lifecycle::Peer;
impl Fixture {
    async fn authorization_and_timeout(&mut self, peer: &Peer) -> Result<()> {
        self.native_context().await?;
        // Drain independent trust maintenance before asserting that revoked
        // business authority cannot request a wake.
        ensure!(peer.manage("Idle", None, None).await?.is_empty());
        crate::test_support::identity::change_grants(case_tenant(), crate::test_support::case::admin(), Fixture::policy_grants()?).await?;
        let definition = self.collection_template().await?;
        crate::test_support::identity::change_grants(case_tenant(), crate::test_support::case::admin(), Fixture::native_grants(&["device_control"])?).await?;
        let op = self.create_restart().await?;
        crate::test_support::identity::change_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            crate::test_support::identity::device_grants(
                Some(case_device()),
                &[
                    "enrollment",
                    "credentials",
                    "inventory_read",
                    "inventory_collect",
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
                &format!("/api/v1/policies/{}", Uuid::new_v4()),
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}})),
            )
            .await?;
        ensure!(refused.0 == StatusCode::FORBIDDEN);
        ensure!(self.operation(op).await?["authorization"] == "blocked");
        ensure!(
            self.app
                .execution
                .apple_wake(&self.app.apple()?.channel.push_fixture().configuration)
                .await?
                .is_none(),
            "revoked authorization triggered APNs"
        );
        let cancelled = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!(
                    "/api/v1/devices/{DEVICE}/operations/{op}/cancel",
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
                r.action() == "management_write" && r.result() == "denied" && r.actor().is_some()
            });
        ensure!(audited, "collection denial lost business action audit");
        // Publish a new collection only after its own current authorization is restored.
        crate::test_support::identity::change_grants(case_tenant(), crate::test_support::case::admin(), Fixture::policy_grants()?).await?;
        let owner = self.policy_worker().await?;
        let queued = self.pending_collections(&definition, 1, peer).await;
        crate::test_support::runtime::stop_worker(Some(owner)).await?;
        let run = queued?[0];
        ensure!(peer.next_collection().await?.0 == run);
        let changed = sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NULL").bind(case_tenant()).bind(run).execute(&mut pg).await?.rows_affected();
        ensure!(
            changed == 1,
            "timeout did not target the pending collection"
        );
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
        crate::test_support::identity::change_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            crate::test_support::identity::device_grants(
                Some(case_device()),
                &[
                    "enrollment",
                    "credentials",
                    "inventory_read",
                    "inventory_collect",
                    "configuration_write",
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
async fn current_authorization_and_deadlines() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.authorization_and_timeout(&peer).await?;
    drop(device);
    f.close().await
}
