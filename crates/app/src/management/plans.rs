use super::*;
use rss_mdm_policy as p;
use rss_mdm_policy_postgres as pg;
use serde_json::json;
impl Management {
    async fn device_identities(
        &self,
        tx: &mut PgTransaction<'_>,
        devices: &[String],
    ) -> Result<std::collections::BTreeMap<String, DeviceIdentity>> {
        let mut identities = std::collections::BTreeMap::new();
        for device in devices {
            identities.insert(device.clone(), storage::device(tx, device).await?);
        }
        Ok(identities)
    }
    pub(super) async fn policy_read(&self, tx: &mut PgTransaction<'_>, id: &str) -> Result<Value> {
        let id = input(p::PolicyId::new(self.tenant, id))?;
        let state = checked(self.policies.get_in(tx, &id).await?)?
            .ok_or(Error::ManagementNotFound(Missing::Policy))?;
        Ok(
            json!({"id":id.value(),"storage_revision":state.storage_revision(),"revision":state.policy().revision(),"status":policy_status(state.policy().status()),"plan":state.current_plan_id().map(|id|hex(*id.bytes())),"fresh":state.plan_is_fresh()}),
        )
    }
    pub(super) async fn policy_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        op: &Operation<PolicyChange>,
        at: Timepoint,
    ) -> Result<Value> {
        let id = input(p::PolicyId::new(self.tenant, id))?;
        let command = match &op.input {
            PolicyChange::Create => pg::Command::Create { policy: id.clone() },
            PolicyChange::Activate {
                version,
                resource,
                resource_version,
            } => {
                let rid = input(rss_mdm_resource::Id::new(resource))?;
                let vid = input(rss_mdm_resource::Id::new(resource_version))?;
                let (v, state, _) = checked(self.resources.lock_version_in(tx, &rid, &vid).await?)?;
                if !matches!(
                    state,
                    rss_mdm_resource::State::Frozen | rss_mdm_resource::State::Active
                ) {
                    return Err(Error::Conflict.into());
                }
                let payload = input(p::PayloadRef::new(
                    input(p::PayloadId::new(
                        self.tenant,
                        format!("r-{}", hex(v.digest().bytes())),
                    ))?,
                    1,
                    v.digest().bytes(),
                ))?;
                let version_number = *version;
                let version = input(p::Version::new(
                    id.clone(),
                    *version,
                    payload,
                    p::RemovalRule::CancelOutstandingRetainEffects,
                ))?;
                let tenant = self.tenant.to_string();
                let policy_key = id.value().to_owned();
                let r = resource.clone();
                let v = resource_version.clone();
                tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_management.firewall_versions SELECT $1::uuid,$2,$3,resource,version FROM mdm_management.firewall_resources WHERE tenant_id=$1::uuid AND resource=$4 AND version=$5 ON CONFLICT DO NOTHING").bind(tenant).bind(policy_key).bind(version_number as i64).bind(r).bind(v).execute(c).await?;Ok(())})).await?;
                let tenant = self.tenant.to_string();
                let resource = resource.clone();
                let resource_version = resource_version.clone();
                let policy = id.value().to_owned();
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("INSERT INTO mdm_management.resource_references VALUES($1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING").bind(tenant).bind(resource).bind(resource_version).bind(policy).execute(c).await?;Ok(())
                })).await?;
                pg::Command::Transition {
                    policy: id.clone(),
                    transition: p::Transition::Activate(version),
                }
            }
            other => pg::Command::Transition {
                policy: id.clone(),
                transition: match other {
                    PolicyChange::Pause => p::Transition::Pause,
                    PolicyChange::Resume => p::Transition::Resume,
                    PolicyChange::Archive => p::Transition::Archive,
                    _ => unreachable!(),
                },
            },
        };
        let request = pg::Request {
            id: input(p::RequestId::new(self.tenant, op.operation_id.to_string()))?,
            expected_storage_revision: op.expected_revision,
            as_of: at,
            command,
        };
        json(&checked(self.policies.execute_in(tx, &request).await?)?)
    }
    pub(super) async fn preview(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        preview: Uuid,
        request: &PreviewInput,
        at: Timepoint,
    ) -> Result<Value> {
        let id = input(p::PolicyId::new(self.tenant, id))?;
        let state = checked(self.policies.get_in(tx, &id).await?)?
            .ok_or(Error::ManagementNotFound(Missing::Policy))?;
        if state.storage_revision() != request.expected_revision {
            return Err(Error::Conflict.into());
        }
        let (revision, definition) = self.scope_definition(tx, request.scope).await?;
        let (sources, resolution) = self.sources(tx, &definition, at).await?;
        let devices = resolution
            .members
            .iter()
            .map(|d| d.value().to_owned())
            .collect::<Vec<_>>();
        let target = targets(self.tenant, preview, &devices)?;
        let mut facts = Vec::new();
        let mut after = None;
        loop {
            let page = checked(
                self.policies
                    .execution_facts_in(tx, &id, after, 1000)
                    .await?,
            )?;
            facts.extend(page.records);
            if facts.len() > pg::MAX_FACTS {
                return Err(Error::Malformed.into());
            }
            after = page.next;
            if after.is_none() {
                break;
            }
        }
        for fact in self.firewall_facts(tx, &id).await? {
            facts.retain(|f| f.key() != fact.key());
            facts.push(fact);
        }
        let plan = input(p::reconcile(p::PlanInput {
            policy: state.policy(),
            targets: &target,
            executions: &facts,
            request: input(p::RequestId::new(self.tenant, preview.to_string()))?,
            as_of: at,
        }))?;
        let registrations = self.device_identities(tx, &devices).await?;
        let configuration = self.freeze_firewall(tx, state.policy(), &devices).await?;
        let result = Preview {
            configuration,
            registrations,
            id: preview,
            policy: id.value().into(),
            policy_revision: state.storage_revision(),
            scope: request.scope,
            scope_revision: revision,
            as_of: at.unix_seconds(),
            sources,
            devices,
            explanation: scopes::explanation(&resolution),
            plan: plan_json(&plan),
        };
        let tenant = self.tenant.to_string();
        let document = input(serde_json::to_string(&result))?;
        let scope = request.scope;
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.previews VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb)").bind(tenant).bind(preview.to_string()).bind(scope.to_string()).bind(revision as i64).bind(document).execute(c).await?;Ok(())
        })).await?;
        json(&result)
    }
    pub(super) async fn save_plan(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        request: &Operation<SavePlan>,
        _at: Timepoint,
    ) -> Result<Value> {
        let preview = storage::preview(tx, request.input.preview)
            .await?
            .ok_or(Error::ManagementNotFound(Missing::Preview))?;
        if preview.policy != id || preview.policy_revision != request.expected_revision {
            return Err(Error::Conflict.into());
        }
        let at = input(Timepoint::try_from(preview.as_of))?;
        let (revision, definition) = self
            .scope_definition(tx, preview.scope)
            .await
            .map_err(stale)?;
        let (sources, _) = self.sources(tx, &definition, at).await.map_err(stale)?;
        if revision != preview.scope_revision || sources != preview.sources {
            return Err(Error::Conflict.into());
        }
        if self
            .device_identities(tx, &preview.devices)
            .await
            .map_err(stale)?
            != preview.registrations
        {
            return Err(Error::Conflict.into());
        }
        if let Some(configuration) = &preview.configuration {
            for (device, expected) in &configuration.devices {
                if super::configuration::evidence(tx, device).await? != *expected {
                    return Err(Error::Conflict.into());
                }
            }
        }
        let policy = input(p::PolicyId::new(self.tenant, id))?;
        let mut selected_revision = preview.policy_revision;
        let updates = self.firewall_facts(tx, &policy).await?;
        if !updates.is_empty() {
            selected_revision = checked(
                self.policies
                    .execute_in(
                        tx,
                        &pg::Request {
                            id: input(p::RequestId::new(
                                self.tenant,
                                format!("{}-facts", request.operation_id),
                            ))?,
                            expected_storage_revision: selected_revision,
                            as_of: at,
                            command: pg::Command::ReplaceFacts {
                                policy: policy.clone(),
                                facts: updates,
                            },
                        },
                    )
                    .await?,
            )?
            .storage_revision;
        }
        let select = pg::Request {
            id: input(p::RequestId::new(
                self.tenant,
                format!("{}-targets", request.operation_id),
            ))?,
            expected_storage_revision: selected_revision,
            as_of: at,
            command: pg::Command::SelectTargets {
                policy: policy.clone(),
                snapshot: targets(self.tenant, preview.id, &preview.devices)?,
                references: vec![pg::AssignmentReference {
                    id: preview.scope.to_string(),
                    revision: preview.scope_revision,
                }],
            },
        };
        let selected = checked(self.policies.execute_in(tx, &select).await?)?;
        let replan = pg::Request {
            id: input(p::RequestId::new(
                self.tenant,
                format!("{}-plan", request.operation_id),
            ))?,
            expected_storage_revision: selected.storage_revision,
            as_of: at,
            command: pg::Command::Replan {
                policy: policy.clone(),
            },
        };
        let result = checked(self.policies.execute_in(tx, &replan).await?)?;
        let state = checked(self.policies.get_in(tx, &policy).await?)?.ok_or(Error::Conflict)?;
        let plan = state.current_plan_id().ok_or(Error::Conflict)?;
        if preview.plan["id"] != json!(hex(*plan.bytes())) {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant.to_string();
        let policy = id.to_owned();
        let bytes = plan.bytes().to_vec();
        let saved_revision = result.storage_revision as i64;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO mdm_management.plan_references VALUES($1::uuid,$2::uuid,$3,$4,$5)",
                )
                .bind(tenant)
                .bind(preview.id.to_string())
                .bind(policy)
                .bind(bytes)
                .bind(saved_revision)
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await?;
        Ok(json!({"receipt":result,"preview":preview.id,"plan":preview.plan}))
    }
}
fn targets(tenant: TenantId, id: Uuid, devices: &[String]) -> Result<p::TargetSnapshot> {
    input(p::TargetSnapshot::new(
        input(p::TargetSnapshotId::new(tenant, id.to_string()))?,
        1,
        p::SnapshotCompleteness::Complete,
        devices
            .iter()
            .map(|d| input(p::DeviceId::new(tenant, d)))
            .collect::<Result<_>>()?,
    ))
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn plan_json(plan: &p::Plan) -> Value {
    let intents=plan.intents().iter().map(|i|match i {
        p::Intent::Add(e)=>json!({"kind":"add","device":e.key().device().value(),"version":e.key().version()}),
        p::Intent::Retain {execution,reason}=>json!({"kind":"retain","device":execution.device().value(),"version":execution.version().number(),"reason":retain_reason(*reason)}),
        p::Intent::Supersede {replacement,previous}=>json!({"kind":"supersede","device":replacement.key().device().value(),"version":replacement.key().version(),"previous_versions":previous.iter().map(|e|e.version()).collect::<Vec<_>>()}),
        p::Intent::Cancel {execution,reason}=>json!({"kind":"cancel","device":execution.device().value(),"version":execution.version().number(),"reason":cancel_reason(*reason)}),
    }).collect::<Vec<_>>();
    json!({"id":hex(*plan.id().bytes()),"scheduling_open":plan.scheduling_open(),"intents":intents,"dispatch":"not_requested"})
}

fn policy_status(s: p::Status) -> &'static str {
    match s {
        p::Status::Draft => "draft",
        p::Status::Active => "active",
        p::Status::Paused => "paused",
        p::Status::Archived => "archived",
    }
}
fn retain_reason(r: p::RetainReason) -> &'static str {
    match r {
        p::RetainReason::Current => "current",
        p::RetainReason::Paused => "paused",
        p::RetainReason::Historical => "historical",
    }
}
fn cancel_reason(r: p::CancelReason) -> &'static str {
    match r {
        p::CancelReason::ScopeExit => "scope_exit",
        p::CancelReason::Archived => "archived",
        p::CancelReason::Superseded => "superseded",
    }
}

fn stale(error: Fault) -> Fault {
    match error {
        Fault::Request(Error::ManagementNotFound(_)) => Error::Conflict.into(),
        other => other,
    }
}
