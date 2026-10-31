//! Real owner composition seams; state reduction and protocol matrices remain in their owners.
mod composition;
mod inventory;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    device_material_support as material, planning_t2_support as planning,
};
use anyhow::Result;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_audit_integration::{AuditIntent, AuditStore, RequestAudit};
use rss_mdm_script_service as script;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn context() -> w::SoftwareExecutionContext {
    serde_json::from_value(json!({"revision":1,"osVersion":[10,0,26100,0],"systemBroker":true,"userHelper":false,"interactiveUser":null,"msixSideload":false,"msixUnsigned":false,"sourceCredentials":[]})).unwrap()
}
fn request(c: &Context) -> RequestAudit {
    RequestAudit::new(
        c.tenant.to_string(),
        "agent_task_event",
        AuditIntent::Management,
    )
}
struct Harness {
    c: Context,
    a: super::execution::Assembly,
    audit: Arc<AuditStore>,
    delivery: rss_mdm_agent_channel::delivery::Delivery,
    p: rss_mdm_registration_service::DevicePrincipal,
    object: rss_mdm_inventory_service::objects::DeviceObject,
    scope: Uuid,
}
async fn delivery(
    c: &Context,
    a: &super::execution::Assembly,
) -> Result<(Arc<AuditStore>, rss_mdm_agent_channel::delivery::Delivery)> {
    let audit = Arc::new(
        c.audit
            .on_runtime(
                a.runtime.clone(),
                c.tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(
                    std::time::Duration::from_secs(5),
                )
                .control(),
            )
            .await?,
    );
    Ok((
        audit.clone(),
        rss_mdm_agent_channel::delivery::Delivery {
            runtime: a.runtime.clone(),
            tenant: c.tenant,
            audit,
            signing: a.signing.clone(),
            tasks: Arc::new(super::agent_tasks::AgentTasks {
                requests: a.self_service.clone(),
                execution: a.service.clone(),
                scripts: a.scripts.clone(),
                collections: a.collections.clone(),
            }),
            content: None,
        },
    ))
}
impl Harness {
    async fn open() -> Result<Self> {
        let c = Context::open("shared", &[]).await?;
        let protection = material::protection(&c)?;
        let trust = material::seed_trust(
            &c,
            &protection,
            &[rss_mdm_agent_wire::task_trust::KeyState::Active],
        )
        .await?;
        let (registration, grant, device) = material::seed_registration(&c).await?;
        let caps = vec![
            w::Capability::InventoryCollectionV1,
            w::Capability::TaskExecuteV1,
        ];
        let p =
            material::authenticated_agent(&c, registration, grant, &device, caps.clone()).await?;
        material::seed_ack(&c, &trust, registration, 2).await?;
        let mut tx = command::seed_transaction(&c).await?;
        sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2,1,$3,'windows','x86_64',$4)").bind(c.tenant.to_string()).bind(registration).bind(serde_json::to_string(&caps)?).bind(serde_json::to_value(context())?).execute(&mut *tx).await?;
        tx.commit().await?;
        let object = serde_json::from_value(
            json!({"object":{"kind":"endpoint","id":device},"associationVersion":null,"verified":true,"members":[{"device":device,"channel":"agent","registrationId":registration,"generation":2}]}),
        )?;
        let scope = planning::published(&c, &object).await?.scope;
        let a = command::open(&c, true).await?;
        let (audit, delivery) = delivery(&c, &a).await?;
        Ok(Self {
            c,
            a,
            audit,
            delivery,
            p,
            object,
            scope,
        })
    }
    async fn close(self) -> Result<()> {
        drop(self.delivery);
        drop(self.audit);
        command::close(self.a).await?;
        self.c.close().await;
        Ok(())
    }
    async fn policy(&self, resource: &str) -> Result<(Uuid, Uuid)> {
        use sha2::{Digest, Sha256};
        let policy = Uuid::new_v4();
        let version = Uuid::new_v4();
        let definition: rss_mdm_policy::Definition = serde_json::from_value(
            json!({"scope":self.scope,"action":{"kind":"execution","resource":{"id":resource,"version":"1","variant":"default","platform":"windows","architecture":"x86_64"},"parameters":{},"schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null},"frequency":"every_trigger","runLifetimeSeconds":300}}),
        )?;
        definition.validate()?;
        let rss_mdm_policy::Action::Execution {
            schedule,
            parameters,
            ..
        } = &definition.action
        else {
            unreachable!()
        };
        let action = script::FrozenScript {
            input: script::frozen::ScriptInput {
                platform: rss_mdm_policy::Platform::Windows,
                architecture: rss_mdm_policy::Architecture::X86_64,
                schedule: schedule.clone(),
                run_lifetime_seconds: 300,
            },
            parameters: parameters.clone(),
            resource: w::TaskResource {
                id: resource.into(),
                version: "1".into(),
                variant: "default".into(),
            },
            definition: serde_json::from_value(
                json!({"profile":"power_shell7","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false},"purpose":{"kind":"action"},"timeoutSeconds":1,"outputBytes":4096,"maxRows":1}),
            )?,
            collection: None,
            resource_digest: [1; 32],
            artifact_reference: "artifact".into(),
            content: w::TaskContent {
                length: 3,
                sha256: [2; 32],
            },
        };
        let frozen = serde_json::to_value(script::policy::Published {
            action: Box::new(action),
            frequency: rss_mdm_policy::Frequency::EveryTrigger,
        })?;
        let author = rss_mdm_authorization_service::Actor::Account {
            user: self.c.user(Uuid::new_v4()),
        };
        let mut tx = command::seed_transaction(&self.c).await?;
        sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(self.c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(author)?).bind(now()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'execution',$4,$5)").bind(self.c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok((policy, version))
    }
    async fn run(&self, version: Uuid, resource: &str, deadline: i64) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let mut tx = command::seed_transaction(&self.c).await?;
        sqlx::query("INSERT INTO mdm_script.runs(tenant_id,id,policy_version,resource_id,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,source_objects,origin,gateway_accepted) VALUES($1::uuid,$2,$3,$4,$5,$6,2,$7,$8,$8,$9,$10,$11,$12,'\"policy\"',true)").bind(self.c.tenant.to_string()).bind(id).bind(version).bind(resource).bind(self.p.device()).bind(self.p.registration()).bind(id.to_string()).bind(now()).bind(deadline).bind(serde_json::to_value(rss_mdm_task_state::RunState::new(deadline,now())?)?).bind(vec![0u8;32]).bind(json!([self.object])).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
    async fn claim(&self) -> Result<w::SignedTask> {
        let input = w::TaskClaimRequest::new(
            Uuid::new_v4(),
            vec![w::ExecutorProfile::PowerShell7],
            context(),
        )?;
        Ok(self
            .delivery
            .claim(&self.p, &input, &request(&self.c))
            .await?
            .task()
            .expect("eligible Script offer")
            .clone())
    }
    async fn event(&self, offer: &w::SignedTask, event: w::TaskEvent) -> Result<w::TaskEventAck> {
        let input =
            w::TaskEventRequest::new(Uuid::new_v4(), offer.payload.attempt_id(), event, context())?;
        Ok(self
            .delivery
            .event(&self.p, offer.payload.task_id(), &input, &request(&self.c))
            .await?)
    }
    async fn admit(&self, version: Uuid, id: Uuid) -> Result<w::PolicyEventDecision> {
        let transactions = script::Transactions::bind(
            self.a.runtime.clone(),
            self.c.tenant,
            self.audit.clone(),
            Arc::new(script::Materials {
                agent_store: Arc::new(super::agent_facts::AgentFacts),
                source: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
                    Arc::new(rss_mdm_device_service::planning::PlanningObjects),
                )),
                capacity: Arc::new(super::capacity::Capacity),
                instance: self.c.inputs.installation.instance_id.clone(),
            }),
        )
        .await?;
        let target = script::Target {
            device: self.p.device().into(),
            registration: self.p.registration(),
            generation: self.p.generation(),
        };
        Ok(script::transaction::run(
            &self.audit,
            &self.a.runtime,
            self.c.tenant,
            &request(&self.c),
            (transactions, target),
            move |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .accept_event_in(
                            tx,
                            version,
                            &ctx.1,
                            (
                                id,
                                rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                            ),
                            now() + 300,
                        )
                        .await
                })
            },
        )
        .await?)
    }
    async fn state(&self, id: Uuid) -> Result<Value> {
        Ok(sqlx::query_scalar(
            "SELECT state FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(self.c.tenant.to_string())
        .bind(id)
        .fetch_one(&self.c.operator)
        .await?)
    }
}
#[tokio::test]
#[ignore = "T2: current Script executor qualification is checked between Offer and Start"]
async fn start_rechecks_current_profile_without_creating_another_attempt() -> Result<()> {
    let h = Harness::open().await?;
    let (_, version) = h.policy("script-start").await?;
    let id = h.run(version, "script-start", now() + 300).await?;
    let offer = h.claim().await?;
    assert_eq!(offer.payload.task_id(), id);
    h.event(&offer, w::TaskEvent::Received).await?;
    let input = w::TaskClaimRequest::new(Uuid::new_v4(), vec![], context())?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_agent.bindings SET announcement=$3 WHERE tenant_id=$1::uuid AND registration=$2").bind(h.c.tenant.to_string()).bind(h.p.registration()).bind(serde_json::to_value(input)?).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(h.event(&offer, w::TaskEvent::Start).await.is_err());
    assert_eq!(h.state(id).await?["execution"], "not_started");
    let restored = w::TaskClaimRequest::new(
        Uuid::new_v4(),
        vec![w::ExecutorProfile::PowerShell7],
        context(),
    )?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_agent.bindings SET announcement=$3 WHERE tenant_id=$1::uuid AND registration=$2").bind(h.c.tenant.to_string()).bind(h.p.registration()).bind(serde_json::to_value(restored)?).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        h.event(&offer, w::TaskEvent::Start)
            .await?
            .permit()
            .is_some()
    );
    assert_eq!(h.state(id).await?["execution"], "running");
    h.close().await
}
#[tokio::test]
#[ignore = "T2: durable Unknown resource barrier survives service reconstruction and original-attempt late evidence"]
async fn unknown_survives_restart_and_only_original_attempt_can_settle_it() -> Result<()> {
    let mut h = Harness::open().await?;
    let (policy, version) = h.policy("script-unknown").await?;
    let deadline = now() + 15;
    let id = h.run(version, "script-unknown", deadline).await?;
    let offer = h.claim().await?;
    assert_eq!(offer.payload.task_id(), id);
    h.event(&offer, w::TaskEvent::Received).await?;
    h.event(&offer, w::TaskEvent::Start).await?;
    let executed = now();
    tokio::time::sleep(std::time::Duration::from_secs(
        (deadline - now() + 1).max(0) as u64,
    ))
    .await;
    script::transaction::run(
        &h.audit,
        &h.a.runtime,
        h.c.tenant,
        &request(&h.c),
        (&h.a.scripts, id),
        |ctx, tx| Box::pin(async move { script::recovery::recover_one(ctx.0, tx, ctx.1).await }),
    )
    .await?;
    assert_eq!(h.state(id).await?["execution"], "unknown");
    let a = command::open(&h.c, true).await?;
    let (audit, delivery) = delivery(&h.c, &a).await?;
    drop(std::mem::replace(&mut h.delivery, delivery));
    drop(std::mem::replace(&mut h.audit, audit));
    command::close(std::mem::replace(&mut h.a, a)).await?;
    let (other_policy, other_version) = h.policy("script-unknown").await?;
    let target = script::Target {
        device: h.p.device().into(),
        registration: Uuid::new_v4(),
        generation: 3,
    };
    let pending = |resource: &str| {
        let resource = resource.to_owned();
        let target = target.clone();
        script::transaction::inspect(
            &h.a.runtime,
            h.c.tenant,
            (target, resource),
            move |ctx, tx| {
                Box::pin(async move {
                    script::storage::pending_in(
                        tx,
                        other_policy,
                        other_version,
                        &ctx.0,
                        &ctx.1,
                        now(),
                    )
                    .await
                })
            },
        )
    };
    assert!(pending("script-unknown").await?.0);
    assert!(!pending("another-resource").await?.0);
    let blocked = Uuid::new_v4();
    assert!(matches!(
        h.admit(other_version, blocked).await?,
        w::PolicyEventDecision::Rejected { .. }
    ));
    let absent:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2) AND NOT EXISTS(SELECT 1 FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$3)").bind(h.c.tenant.to_string()).bind(blocked).bind(format!("script.{blocked}")).fetch_one(&h.c.operator).await?;
    assert!(absent);
    let (_, independent) = h.policy("another-resource").await?;
    assert!(matches!(
        h.admit(independent, Uuid::new_v4()).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));

    let result = w::TaskResult::new(
        Some(0),
        w::OutputQuality::Complete,
        json!({"ok":true}),
        w::TaskDiagnostics::new(
            "private stdout".into(),
            "private stderr".into(),
            1,
            executed,
            None,
        )?,
        executed,
    )?;
    let wrong = w::TaskEventRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        w::TaskEvent::Result(result.clone()),
        context(),
    )?;
    assert!(
        h.delivery
            .event(&h.p, id, &wrong, &request(&h.c))
            .await
            .is_err()
    );
    assert_eq!(h.state(id).await?["execution"], "unknown");
    h.event(&offer, w::TaskEvent::Result(result)).await?;
    assert_eq!(h.state(id).await?["execution"], "succeeded");
    assert!(!pending("script-unknown").await?.0);
    assert!(matches!(
        h.admit(other_version, Uuid::new_v4()).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));

    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::{RUNS_SCHEMA, Reads};
    let account =
        h.c.account(&[Permission::PolicyRead, Permission::OperationRead])
            .await?;
    let proof = h.c.authenticate(&account).await?;
    let page = RUNS_SCHEMA.page(Some(10), None, 4096)?;
    let codec = rss_mdm_query::cursor::CursorCodec::new(&[3; 32])?;
    let summaries = Reads::runs(
        h.a.task_reads.as_ref(),
        &proof,
        &h.c.request(&proof)?,
        policy,
        &page,
        &codec,
    )
    .await?;
    assert_eq!(summaries.items.len(), 1);
    let summary = serde_json::to_value(&summaries.items[0])?;
    assert_eq!(summary["kind"], "script");
    assert!(summary["result"].get("output").is_none());
    assert!(summary["result"]["diagnostics"].get("stdout").is_none());
    assert!(summary["result"]["diagnostics"].get("stderr").is_none());
    h.close().await
}
