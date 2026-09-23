use super::*;
use rss_mdm_policy as p;
use rss_mdm_policy_postgres as pg;
use serde_json::json;
use sqlx::Row;
impl Management {
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
                let version = input(p::Version::new(
                    id.clone(),
                    *version,
                    payload,
                    p::RemovalRule::CancelOutstandingRetainEffects,
                ))?;
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
        let receipt = checked(self.policies.execute_in(tx, &request).await?)?;
        let mut response = json(&receipt)?;
        if !matches!(op.input, PolicyChange::Create) {
            let tenant = self.tenant.to_string();
            let policy = id.value().to_owned();
            let binding=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("SELECT scope::text,revision FROM mdm_management.policy_assignments WHERE tenant_id=$1::uuid AND policy=$2")
                    .bind(tenant).bind(policy).fetch_optional(c).await
            })).await?;
            if let Some(binding) = binding {
                let scope = stored(Uuid::parse_str(binding.try_get("scope")?))?;
                let resolution = Uuid::new_v4();
                let task = Uuid::new_v4();
                self.enqueue_job_in(tx, resolution, &automation::JobInput::Scope { scope })
                    .await?;
                self.enqueue_job_in(
                    tx,
                    task,
                    &automation::JobInput::Policy {
                        policy: id.value().into(),
                        scope,
                        resolution,
                        assignment_revision: Some(binding.try_get("revision")?),
                        expected_revision: receipt.storage_revision,
                        as_of: at.unix_seconds(),
                    },
                )
                .await?;
                response["task"] = serde_json::json!(task);
            }
        }
        Ok(response)
    }
    pub(super) async fn preview(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        preview: Uuid,
        request: &PreviewInput,
        at: Timepoint,
    ) -> Result<Value> {
        self.start_policy_preview_in(
            tx,
            id,
            preview,
            request.expected_revision,
            request.scope,
            at,
        )
        .await
    }
    pub(super) async fn save_plan(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        request: &Operation<SavePlan>,
        at: Timepoint,
    ) -> Result<Value> {
        self.save_ready_candidate_in(tx, id, request, at).await
    }
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn policy_status(s: p::Status) -> &'static str {
    match s {
        p::Status::Draft => "draft",
        p::Status::Active => "active",
        p::Status::Paused => "paused",
        p::Status::Archived => "archived",
    }
}
