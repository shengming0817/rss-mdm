//! Policy event batches own acceptance identities and references, never execution state.
//! ref: meilisearch crates/index-scheduler/src/queue/batches.rs (atomic batch/member references).
use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_authorization_service::OperationAuthority;
use rss_mdm_execution_service::{ExecutionService, Target};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

pub mod queries;

pub struct Events {
    pub planning: Arc<Planning>,
    pub execution: Arc<ExecutionService>,
}
#[derive(Clone, Copy)]
enum Requester<'a> {
    Management(&'a AuthorizedPrincipal),
    Agent(&'a rss_mdm_registration_service::device::DevicePrincipal),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Caller {
    Management { actor: crate::authorization::Actor },
    Agent { target: Target },
}
impl Caller {
    fn key(&self) -> std::result::Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::Malformed)
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct MemberAuthority {
    permissions: Vec<(Permission, OperationAuthority)>,
    retirement_target: Option<rss_mdm_inventory_service::objects::DeviceObject>,
}
struct Dispatch<'a> {
    policy: &'a rss_mdm_policy::Policy,
    target: &'a Target,
    member: Uuid,
    deadline: i64,
    input: &'a wire::PolicyEventRequest,
    audit: &'a RequestAudit,
    retirement_target: Option<&'a rss_mdm_inventory_service::objects::DeviceObject>,
}
const MAX_MEMBERS: usize = 1000;
impl Events {
    pub async fn invoke_management(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &wire::PolicyEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::PolicyRead)?;
        if input.execution_context.is_some()
            || !matches!(
                input.source,
                wire::PolicyEventSource::Human | wire::PolicyEventSource::Ai
            )
        {
            return Err(Error::Malformed);
        }
        self.invoke(Requester::Management(proof), device, input, audit)
            .await
    }
    pub async fn invoke_agent(
        &self,
        principal: &rss_mdm_registration_service::device::DevicePrincipal,
        input: &wire::PolicyEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        self.invoke(
            Requester::Agent(principal),
            principal.device(),
            input,
            audit,
        )
        .await
    }
    async fn invoke(
        &self,
        requester: Requester<'_>,
        device: &str,
        input: &wire::PolicyEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if input.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        let p = &self.planning;
        let (caller, proof) = match requester {
            Requester::Management(proof) => (
                Caller::Management {
                    actor: proof.actor(),
                },
                Some(proof),
            ),
            Requester::Agent(principal) => (
                Caller::Agent {
                    target: Target {
                        device: principal.device().into(),
                        registration: principal.registration(),
                        generation: principal.generation(),
                    },
                },
                None,
            ),
        };
        audit.operation(
            input.operation_id,
            "policy_event",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let agent = matches!(caller, Caller::Agent { .. });
        let audit_store = if agent {
            self.execution.event_transaction_owner().2
        } else {
            &p.audit_store
        };
        run(audit_store,if agent{self.execution.event_runtime()}else{&p.runtime},p.tenant,audit,(self,&caller,requester,proof,device,input,audit),|ctx,tx|Box::pin(async move{
            let(s,caller,requester,proof,device,input,audit)=*ctx;
            if let Requester::Agent(principal)=requester {s.execution.verify_event_device_in(tx,principal,Some(input)).await?;}
            let snapshot=match proof {Some(p)=>{let snapshot=crate::action_admission::current(tx,p).await?;snapshot.require(p,Permission::PolicyRead,None)?;Some(snapshot)},None=>None};
            crate::transaction::lock(tx).await?;
            let audit_store=if matches!(caller,Caller::Agent{..}) {s.execution.event_transaction_owner().2} else {&s.planning.audit_store};
            audit_store.prepare_in(tx,audit,&[]).await?;
            if let Caller::Agent{target}=caller && !s.execution.event_device_current_in(tx,target).await? {return Err(Error::Forbidden.into());}
            let actor=caller.key()?;
            let hash=fingerprint(&(caller,device,input))?;
            let tenant=tx.tenant_id().to_string();let operation=input.operation_id;let actor_query=actor.clone();
            let old:Option<(Vec<u8>,Uuid,i64)>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_as("SELECT fingerprint,id,(SELECT count(*) FROM mdm_planning.event_members m WHERE(m.tenant_id,m.batch)=(b.tenant_id,b.id)) FROM mdm_planning.event_batches b WHERE tenant_id=$1::uuid AND actor=$2 AND request=$3").bind(tenant).bind(actor_query).bind(operation).fetch_optional(c).await})).await?;
            if let Some((prior,batch,members))=old {if prior!=hash{return Err(Error::Conflict.into());}return Ok(json!(wire::PolicyEventAccepted{operation_id:operation,batch_id:batch,members:members as u32}));}
            if let Caller::Agent{target}=caller && !s.execution.event_parent_current_in(tx,target,&input.source).await? {return Err(Error::Forbidden.into());}
            if let Caller::Agent{target}=caller {s.execution.apply_event_context_in(tx,target,input.execution_context.as_ref().ok_or(Error::Malformed)?).await?;}
            let tenant=tx.tenant_id().to_string();let name=input.event.as_str().to_owned();
            let ids:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND definition->>'customEvent'=$2 AND state<>'archived' ORDER BY id LIMIT 1001").bind(tenant).bind(name).fetch_all(c).await})).await?;
            if ids.len()>MAX_MEMBERS {return Err(Error::Malformed.into());}
            let now=crate::action_admission::now(tx).await?;let batch=Uuid::new_v4();
            let mut member_count=0;
            let document=json(input)?;let caller_document=json(caller)?;
            let tenant=tx.tenant_id().to_string();let device_owned=device.to_owned();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.event_batches(tenant_id,id,request,actor,caller,device,input,fingerprint,created_at,deadline) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(tenant).bind(batch).bind(operation).bind(actor).bind(caller_document).bind(device_owned).bind(document).bind(hash).bind(now).bind(now.saturating_add(604800)).execute(c).await?;Ok(())})).await?;
            let management_reader=rss_mdm_policy_postgres::PolicyReader::bind(s.planning.runtime.clone(),s.planning.tenant);
            let reader=if matches!(caller,Caller::Agent{..}) {s.execution.event_policy_reader()} else {&management_reader};
            for id in ids {
                let policy=checked(reader.read_in(tx,id).await?)?.ok_or(Error::NotFound)?;
                let permission=rss_mdm_execution_service::policy_permission(&policy.definition.action);
                let mut permissions=Vec::new();let mut decision=wire::PolicyEventDecision::Pending;
                let retirement_target=if matches!(policy.definition.action,rss_mdm_policy::Action::UnmanageDevice{..}) {
                    let tenant=tx.tenant_id();let reader=s.planning.objects.clone();let device=device.to_owned();
                    let object=tx.with_connection(move|c|Box::pin(async move{reader.endpoint(c,tenant,&device).await})).await?;
                    Some(tx.with_connection(move|c|Box::pin(async move{Ok(rss_mdm_device_service::lifecycle::complete_target_in(c,tenant,&object).await)})).await?.map_err(Error::from)?)
                }else{None};
                if let (Some(snapshot),Some(proof))=(&snapshot,proof){
                    let mut required=vec![permission];
                    if matches!(policy.definition.action,rss_mdm_policy::Action::EnsureAgentInstalled{..}){required.push(Permission::Enrollment);}
                    let devices=retirement_target.as_ref().map_or_else(||vec![device.to_owned()],|object|object.members.iter().map(|m|m.device.clone()).collect());
                    for device in devices {for p in &required {match OperationAuthority::from_proof(snapshot,proof,&device,*p){Ok(a)=>permissions.push((*p,a)),Err(_)=>decision=wire::PolicyEventDecision::Rejected{reason:"permission_denied".into()}}}}
                }
                let channel=policy.definition.action.target_channel().map_or("agent",|c|match c{rss_mdm_policy::SoftwareChannel::Agent=>"agent",rss_mdm_policy::SoftwareChannel::Mdm=>"mdm"});
                let mut target=rss_mdm_execution_service::policy_events::target_in(tx,device,channel).await?;
                if target.is_none() && matches!(policy.definition.action,rss_mdm_policy::Action::UnmanageDevice{..}) {target=rss_mdm_execution_service::policy_events::target_in(tx,device,"mdm").await?;}
                if matches!(caller,Caller::Agent{..}) {
                    let Some(ref target)=target else {continue;};
                    if !s.execution.event_scope_in(tx,&policy,target).await? {continue;}
                }
                member_count+=1;
                if target.is_none(){decision=wire::PolicyEventDecision::Rejected{reason:"registration_unavailable".into()};}
                let member=Uuid::new_v4();
                if !matches!(decision,wire::PolicyEventDecision::Pending) {
                    let mut activity=rss_mdm_audit_integration::activity::Activity::new(rss_mdm_audit_integration::activity::ActivityKind::Batch,rss_mdm_audit_integration::activity::ActivityPhase::Decided);
                    let visible_target=match &target {Some(t)=>Some(t.clone()),None=>match caller {Caller::Agent{target}=>Some(target.clone()),_=>rss_mdm_execution_service::policy_events::target_in(tx,device,"mdm").await?}};
                    activity.target=visible_target.map(|t|rss_mdm_audit_integration::activity::ActivityTarget{device:t.device,registration:t.registration,generation:t.generation});
                    activity.links.batch=Some(batch);activity.links.member=Some(member);activity.links.policy=Some(policy.id);activity.links.version=Some(policy.version);activity.links.request=Some(operation);
                    activity.decision=Some("rejected".into());
                    activity.origin=match input.source {wire::PolicyEventSource::Human=>"human",wire::PolicyEventSource::Ai=>"ai",wire::PolicyEventSource::Policy{..}=>"policy"}.into();
                    audit_store.append_in(tx,&rss_mdm_audit_integration::Fact::business(audit,&format!("policy-event:{batch}:{member}"),200,"rejected",None)?.with_activity(&activity)?).await?;
                }
                let tenant=tx.tenant_id().to_string();let target=json(&target)?;let authority=json(&MemberAuthority{permissions,retirement_target})?;let decision=json(&decision)?;
                tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.event_members(tenant_id,batch,id,policy,revision,version,target,authority,decision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)").bind(tenant).bind(batch).bind(member).bind(policy.id).bind(policy.revision).bind(policy.version).bind(target).bind(authority).bind(decision).execute(c).await?;Ok(())})).await?;
            }
            crate::automation::jobs::enqueue_job_in(tx,batch,&crate::automation::JobInput::PolicyEvent{batch}).await?;
            let mut activity=rss_mdm_audit_integration::activity::Activity::new(rss_mdm_audit_integration::activity::ActivityKind::Batch,rss_mdm_audit_integration::activity::ActivityPhase::Accepted);
            activity.links.batch=Some(batch);activity.links.request=Some(operation);
            activity.origin=match input.source {wire::PolicyEventSource::Human=>"human",wire::PolicyEventSource::Ai=>"ai",wire::PolicyEventSource::Policy{..}=>"policy"}.into();
            let target=if let Caller::Agent{target}=caller {Some(target.clone())}else{rss_mdm_execution_service::policy_events::target_in(tx,device,"agent").await?};
            let target=match target {Some(t)=>Some(t),None=>rss_mdm_execution_service::policy_events::target_in(tx,device,"mdm").await?};
            activity.target=target.map(|t|rss_mdm_audit_integration::activity::ActivityTarget{device:t.device,registration:t.registration,generation:t.generation});
            audit_store.append_in(tx,&rss_mdm_audit_integration::Fact::business(audit,&format!("policy-event:{batch}:accepted"),202,"success",None)?.with_activity(&activity)?).await?;
            if let Some(proof)=proof{proof.check_live()?;}
            Ok(json!(wire::PolicyEventAccepted{operation_id:operation,batch_id:batch,members:member_count}))
        }),TransactionOwner::Planning).await
    }
}

impl Planning {
    pub(crate) async fn advance_event_in(
        &self,
        execution: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        batch: Uuid,
    ) -> Result<()> {
        let audit_store = execution.event_transaction_owner().2;
        let tenant = tx.tenant_id().to_string();
        let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT b.caller,b.input,b.deadline,m.id,m.policy,m.version,m.target,m.authority FROM mdm_planning.event_batches b JOIN mdm_planning.event_members m ON(m.tenant_id,m.batch)=(b.tenant_id,b.id) WHERE b.tenant_id=$1::uuid AND b.id=$2 AND m.decision->>'state'='pending' ORDER BY m.id LIMIT 1 FOR UPDATE OF m").bind(tenant).bind(batch).fetch_optional(c).await})).await?;
        let Some(row) = row else {
            return crate::automation::jobs::finish_job_in(tx, audit_store, batch, None).await;
        };
        let member: Uuid = row.try_get("id")?;
        let id: Uuid = row.try_get("policy")?;
        let version: Uuid = row.try_get("version")?;
        let deadline: i64 = row.try_get("deadline")?;
        let target: Target = stored(serde_json::from_value(row.try_get("target")?))?;
        let caller: Caller = stored(serde_json::from_value(row.try_get("caller")?))?;
        let authority: MemberAuthority = stored(serde_json::from_value(row.try_get("authority")?))?;
        let input: wire::PolicyEventRequest =
            stored(serde_json::from_value(row.try_get("input")?))?;
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "policy_event_member",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("policy-event");
        audit.operation(
            member,
            "policy_event_member",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.registration(target.registration);
        audit.target(&target.device);
        audit_store.prepare_in(tx, &audit, &[]).await?;
        let now = crate::action_admission::now(tx).await?;
        let reader = execution.event_policy_reader();
        let policy = policies::storage::read_in(reader, tx, id).await?;
        let mut valid = execution.event_device_current_in(tx, &target).await?;
        for (permission, proof) in authority.permissions {
            valid &= tx
                .with_connection(move |c| {
                    Box::pin(async move { Ok(proof.valid(c, permission, now).await) })
                })
                .await??;
        }
        if let Caller::Agent { target: ref origin } = caller {
            valid &= execution.event_device_current_in(tx, origin).await?;
        }
        let decision = if now >= deadline {
            wire::PolicyEventDecision::Expired
        } else if !valid {
            rss_mdm_execution_service::policy_events::rejected("authority_changed")
        } else if let Some(policy) = policy.filter(|p| p.version == version) {
            if !policy.state.is_enabled() {
                rss_mdm_execution_service::policy_events::rejected("policy_disabled")
            } else {
                self.dispatch_event_in(
                    execution,
                    tx,
                    Dispatch {
                        policy: &policy,
                        target: &target,
                        member,
                        deadline,
                        input: &input,
                        audit: &audit,
                        retirement_target: authority.retirement_target.as_ref(),
                    },
                )
                .await?
            }
        } else {
            rss_mdm_execution_service::policy_events::rejected("policy_changed")
        };
        let mut activity = rss_mdm_audit_integration::activity::Activity::new(
            rss_mdm_audit_integration::activity::ActivityKind::Batch,
            rss_mdm_audit_integration::activity::ActivityPhase::Decided,
        );
        activity.target = Some(rss_mdm_audit_integration::activity::ActivityTarget {
            device: target.device.clone(),
            registration: target.registration,
            generation: target.generation,
        });
        activity.links.batch = Some(batch);
        activity.links.member = Some(member);
        activity.links.policy = Some(id);
        activity.links.version = Some(version);
        activity.links.request = Some(input.operation_id);
        activity.origin = match input.source {
            wire::PolicyEventSource::Human => "human",
            wire::PolicyEventSource::Ai => "ai",
            wire::PolicyEventSource::Policy { .. } => "policy",
        }
        .into();
        activity.decision = Some(
            match &decision {
                wire::PolicyEventDecision::Pending => "pending",
                wire::PolicyEventDecision::Accepted { .. } => "accepted",
                wire::PolicyEventDecision::NoChange { .. } => "no_change",
                wire::PolicyEventDecision::Rejected { .. } => "rejected",
                wire::PolicyEventDecision::Expired => "expired",
            }
            .into(),
        );
        if let wire::PolicyEventDecision::Accepted { operations } = &decision {
            activity.links.operations = operations
                .iter()
                .map(|r| {
                    use rss_mdm_audit_integration::activity::ActivityOperation as A;
                    match r {
                        wire::PolicyEventOperation::Run { id } => A::Run { id: *id },
                        wire::PolicyEventOperation::Native { id } => A::Native { id: *id },
                        wire::PolicyEventOperation::Retirement { id } => A::Retirement { id: *id },
                    }
                })
                .collect();
        }
        let tenant = tx.tenant_id().to_string();
        let decision = json(&decision)?;
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.event_members SET decision=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(member).bind(decision).execute(c).await?;Ok(())})).await?;
        audit_store
            .append_in(
                tx,
                &rss_mdm_audit_integration::Fact::business(
                    &audit,
                    &format!("policy-event:{batch}:{member}"),
                    200,
                    "success",
                    None,
                )?
                .with_activity(&activity)?,
            )
            .await?;
        audit.finalize(None);
        Ok(())
    }
    async fn dispatch_event_in(
        &self,
        execution: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        dispatch: Dispatch<'_>,
    ) -> Result<wire::PolicyEventDecision> {
        let Dispatch {
            policy,
            target,
            member,
            deadline,
            input,
            audit,
            retirement_target,
        } = dispatch;
        use rss_mdm_policy::Action;
        if matches!(input.source, wire::PolicyEventSource::Ai)
            && matches!(policy.definition.action, Action::Execution { .. })
            && !policy.definition.self_service.as_ref().is_some_and(|s| {
                s.allow_ai == Some(true) && s.risk_level.is_some_and(|risk| risk.value() == 1)
            })
        {
            return Ok(rss_mdm_execution_service::policy_events::rejected(
                "ai_not_allowed",
            ));
        }
        match &policy.definition.action {
            Action::TelemetryProfile { .. } => {
                let device = target.device.clone();
                let id = policy.id;
                let version = policy.version;
                {
                    let tenant = self.tenant;
                    let objects = self.objects.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(policies::telemetry::resolve_target_on(
                                tenant, objects, c, &device, id, version,
                            )
                            .await)
                        })
                    })
                }
                .await??;
                Ok(wire::PolicyEventDecision::NoChange {
                    reason: "configuration_available".into(),
                })
            }
            Action::UnmanageDevice { .. } => {
                self.accept_event_retirement_in(
                    execution,
                    tx,
                    policy,
                    target,
                    member,
                    retirement_target.ok_or(Error::Malformed)?,
                )
                .await
            }
            _ => Ok(execution
                .accept_policy_event_in(tx, policy, target, member, deadline, audit)
                .await?),
        }
    }
}
impl Planning {
    async fn accept_event_retirement_in(
        &self,
        execution: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::Policy,
        target: &Target,
        member: Uuid,
        frozen_target: &rss_mdm_inventory_service::objects::DeviceObject,
    ) -> Result<wire::PolicyEventDecision> {
        use rss_mdm_execution_service::source_authority::SourceAuthority;
        let tenant = tx.tenant_id();
        let reader = self.objects.clone();
        let device = target.device.clone();
        let scope = policy.definition.scope;
        let object = tx
            .with_connection(move |c| {
                Box::pin(async move { reader.endpoint(c, tenant, &device).await })
            })
            .await?;
        let reader = self.objects.clone();
        let object = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_device_service::lifecycle::complete_target_in(c, tenant, &object)
                            .await,
                    )
                })
            })
            .await?
            .map_err(Error::from)?;
        if &object != frozen_target {
            return Ok(rss_mdm_execution_service::policy_events::rejected(
                "target_changed",
            ));
        }
        for member in &object.members {
            let source = super::execution_source::ExecutionSource::new(self.objects.clone());
            let member = member.clone();
            let eligible = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .admission_on(c, tenant, scope, member.channel, &member.device)
                            .await)
                    })
                })
                .await?
                .map_err(rss_mdm_execution_service::Error::from)?;
            if !matches!(
                eligible,
                rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { .. }
            ) {
                return Ok(rss_mdm_execution_service::policy_events::rejected(
                    "scope_not_eligible",
                ));
            }
        }
        let published = checked(
            execution
                .event_policy_reader()
                .version_in(tx, policy.version)
                .await?,
        )?
        .ok_or(Error::NotFound)?;
        let frozen: rss_mdm_execution_service::frozen::Frozen =
            stored(serde_json::from_value(published.frozen))?;
        let rss_mdm_execution_service::frozen::Frozen::UnmanageDevice {
            actor,
            run_lifetime_seconds,
            schedule,
        } = frozen
        else {
            return Err(Error::Malformed.into());
        };
        let now = crate::action_admission::now(tx).await?;
        if !schedule
            .occurrence(now, target.device.as_bytes())?
            .is_some_and(|s| s.available_at <= now && s.window_end.is_none_or(|end| now < end))
        {
            return Ok(rss_mdm_execution_service::policy_events::rejected(
                "outside_window",
            ));
        }
        let id = policy.id;
        let version = policy.version;
        let occurrence = format!("event:{member}");
        let accepted = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_device_service::lifecycle::accept_in(
                        c,
                        tenant,
                        reader.as_ref(),
                        &rss_mdm_device_service::lifecycle::Acceptance {
                            policy: id,
                            version,
                            occurrence: &occurrence,
                            target: &object,
                            actor: &actor,
                            delivery_seconds: run_lifetime_seconds,
                            now,
                        },
                    )
                    .await)
                })
            })
            .await?
            .map_err(Error::from)?;
        rss_mdm_execution_service::unmanage::wake_in(
            execution.event_transaction_owner().1,
            tx,
            accepted.0,
        )
        .await?;
        Ok(wire::PolicyEventDecision::Accepted {
            operations: vec![wire::PolicyEventOperation::Retirement { id: accepted.0 }],
        })
    }
    /// Called only after confirmed rollback, under the original job claim.
    pub(crate) async fn reject_event_member_in(
        &self,
        audit_store: &rss_mdm_audit_integration::AuditStore,
        tx: &mut PgTransaction<'_>,
        batch: Uuid,
        reason: &str,
    ) -> Result<()> {
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "policy_event_member",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("policy-event");
        audit_store.prepare_in(tx, &audit, &[]).await?;
        let tenant = tx.tenant_id().to_string();
        let decision = json!({"state":"rejected","reason":reason});
        let member:Option<Uuid>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("UPDATE mdm_planning.event_members SET decision=$3 WHERE tenant_id=$1::uuid AND id=(SELECT id FROM mdm_planning.event_members WHERE tenant_id=$1::uuid AND batch=$2 AND decision->>'state'='pending' ORDER BY id LIMIT 1) RETURNING id").bind(tenant).bind(batch).bind(decision).fetch_optional(c).await})).await?;
        if let Some(member) = member {
            let tenant = tx.tenant_id().to_string();
            let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT m.target,m.policy,m.version,b.request,b.input FROM mdm_planning.event_members m JOIN mdm_planning.event_batches b ON(b.tenant_id,b.id)=(m.tenant_id,m.batch) WHERE m.tenant_id=$1::uuid AND m.id=$2").bind(tenant).bind(member).fetch_one(c).await})).await?;
            let target: Target = stored(serde_json::from_value(row.try_get("target")?))?;
            let input: wire::PolicyEventRequest =
                stored(serde_json::from_value(row.try_get("input")?))?;
            let mut activity = rss_mdm_audit_integration::activity::Activity::new(
                rss_mdm_audit_integration::activity::ActivityKind::Batch,
                rss_mdm_audit_integration::activity::ActivityPhase::Decided,
            );
            activity.target = Some(rss_mdm_audit_integration::activity::ActivityTarget {
                device: target.device.clone(),
                registration: target.registration,
                generation: target.generation,
            });
            activity.links.batch = Some(batch);
            activity.links.member = Some(member);
            activity.links.policy = Some(row.try_get("policy")?);
            activity.links.version = Some(row.try_get("version")?);
            activity.links.request = Some(row.try_get("request")?);
            activity.decision = Some("rejected".into());
            activity.origin = match input.source {
                wire::PolicyEventSource::Human => "human",
                wire::PolicyEventSource::Ai => "ai",
                wire::PolicyEventSource::Policy { .. } => "policy",
            }
            .into();
            audit.registration(target.registration);
            audit.target_device(&target.device);
            audit.operation(
                member,
                "policy_event_member",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit_store
                .append_in(
                    tx,
                    &rss_mdm_audit_integration::Fact::business(
                        &audit,
                        &format!("policy-event:{batch}:{member}"),
                        200,
                        "rejected",
                        None,
                    )?
                    .with_activity(&activity)?,
                )
                .await?;
        }
        audit.finalize(None);
        Ok(())
    }
}
