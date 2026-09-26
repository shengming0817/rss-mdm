use super::{ActionPlans, model::*, storage as db};
use crate::action_admission as storage;
use crate::planning::action_schedule::Trigger;
use crate::planning::error::ActionRejection;
use crate::transaction::{Result, checked_input, fingerprint};
use crate::{
    Error,
    authorization::{Approval, Permission, context::AuthorizedPrincipal},
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::{Value, json};
use uuid::Uuid;
pub(crate) struct Created {
    pub response: Value,
    pub created: bool,
}
pub(crate) struct Approved {
    pub response: Value,
    pub changed: bool,
}
impl ActionPlans {
    pub(crate) async fn create_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        input: &Create,
        audit: &RequestAudit,
    ) -> Result<Created> {
        self.content.as_ref().ok_or(Error::Unsupported)?;
        let service = self;
        let (snapshot, now) = admit_creation_in(tx, proof, input).await?;
        let actor = format!("user:{}", proof.principal_id());
        let hash = fingerprint(&(proof.user(), input))?;
        let event_key = format!("action-plan:{actor}:{}:create", input.operation_id);
        if let Some(value) = db::replay(tx, &actor, input.operation_id, &hash).await? {
            let old = db::load_plan(tx, input.operation_id).await?;
            snapshot.require_devices(
                proof,
                Permission::ScriptExecute,
                &old.frozen.targets.devices,
            )?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            let fact = Fact::business(audit, &event_key, &hash, 202, "success", None)?;
            service.audit_store.append_in(tx, &fact, true).await?;
            proof.check_live()?;
            return Ok(Created {
                response: value,
                created: false,
            });
        }

        if input.schedule.until <= now {
            return Err(Error::Malformed.into());
        }
        let targets = super::targets::freeze_in(tx, &input.targets).await?;
        let approvals = Approval::for_devices(
            &snapshot,
            proof,
            &targets.devices,
            Permission::ScriptExecute,
        )?;
        check_capacity_in(tx, input, &targets, now).await?;
        let target_count = targets.devices.len();
        let frozen = self.freeze_resource_in(tx, input, targets).await?;
        db::insert_plan_in(tx, &frozen, &proof.user(), &approvals, &hash).await?;

        let response = creation_receipt(input.operation_id, target_count);
        let fact = Fact::business(audit, &event_key, &hash, 202, "success", None)?;
        service.audit_store.append_in(tx, &fact, false).await?;
        db::receipt(tx, &actor, input.operation_id, hash, &response).await?;
        proof.check_live()?;
        Ok(Created {
            response,
            created: true,
        })
    }
    pub(crate) async fn approve_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        change: &Change,
        audit: &RequestAudit,
    ) -> Result<Approved> {
        if change.operation_id.is_nil() {
            return Err(Error::Malformed.into());
        }
        let service = self;

        storage::lock(tx, "action-owner").await?;
        let mut plan = db::load_plan(tx, id).await?;
        if plan.author == proof.user() {
            return Err(Error::Forbidden.into());
        }
        let snapshot = storage::current(tx, proof).await?;
        let approvals = Approval::for_devices(
            &snapshot,
            proof,
            &plan.frozen.targets.devices,
            Permission::ScriptApprove,
        )?;
        let actor = format!("user:{}", proof.principal_id());
        let hash = fingerprint(&("approve", id, proof.user()))?;
        let event_key = format!("action-plan:{actor}:{}:approve", change.operation_id);
        if let Some(value) = db::replay(tx, &actor, change.operation_id, &hash).await? {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?;
            service.audit_store.append_in(tx, &fact, true).await?;
            proof.check_live()?;
            return Ok(Approved {
                response: value,
                changed: false,
            });
        }
        let now = storage::now(tx).await?;
        if !plan.active || now >= plan.frozen.input.schedule.until {
            return Err(Error::Conflict.into());
        }
        if plan.reviewer.is_some() {
            return Err(Error::Conflict.into());
        }
        let tenant = tx.tenant_id().to_string();
        let reviewer = checked_input(serde_json::to_value(proof.user()))?;
        let approvals_value = checked_input(serde_json::to_value(&approvals))?;
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.action_plans SET reviewer=$3,reviewer_approvals=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(reviewer).bind(approvals_value).execute(c).await?;Ok(())})).await?;
        plan.reviewer = Some(proof.user());
        plan.reviewer_approvals = approvals;

        let response = json!({"planId":id,"revision":1,"authorization":"approved"});
        let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?;
        service.audit_store.append_in(tx, &fact, false).await?;
        db::receipt(tx, &actor, change.operation_id, hash, &response).await?;
        proof.check_live()?;
        Ok(Approved {
            response,
            changed: true,
        })
    }
    pub(crate) async fn read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value> {
        let store = &self.audit_store;
        storage::lock(tx, "action-owner").await?;
        let plan = db::load_plan(tx, id).await?;
        let snapshot = storage::current(tx, proof).await?;
        snapshot.require_devices(
            proof,
            Permission::OperationRead,
            &plan.frozen.targets.devices,
        )?;
        store.append_request_in(tx, audit, 200, "success").await?;
        Ok(
            json!({"planId":id,"revision":1,"active":plan.active,"approved":plan.reviewer.is_some(),"definition":plan.frozen,"runsUrl":format!("/api/v3/script-plans/{id}/runs")}),
        )
    }
    pub(crate) async fn cancel_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        change: &Change,
        audit: &RequestAudit,
    ) -> Result<Value> {
        if change.operation_id.is_nil() {
            return Err(Error::Malformed.into());
        }
        let store = &self.audit_store;
        storage::lock(tx, "action-owner").await?;
        let plan = db::load_plan(tx, id).await?;
        let snapshot = storage::current(tx, proof).await?;
        snapshot.require_devices(
            proof,
            Permission::OperationCancel,
            &plan.frozen.targets.devices,
        )?;
        let actor = format!("user:{}", proof.principal_id());
        let hash = fingerprint(&("cancel", id, proof.user()))?;
        let event_key = format!("action-plan:{actor}:{}:cancel", change.operation_id);
        if let Some(value) = db::replay(tx, &actor, change.operation_id, &hash).await? {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?;
            store.append_in(tx, &fact, true).await?;
            return Ok(value);
        }
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.action_plans SET active=false WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())})).await?;
        let response = json!({"planId":id,"cancelRequested":true});
        let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?;
        store.append_in(tx, &fact, false).await?;
        db::receipt(tx, &actor, change.operation_id, hash, &response).await?;
        proof.check_live()?;
        Ok(response)
    }
}

impl ActionPlans {
    async fn freeze_resource_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Create,
        targets: FrozenTargets,
    ) -> Result<Frozen> {
        let (version, state) = rss_mdm_resource_postgres::lock_reference_in(
            tx,
            &checked_input(r::Id::new(&input.resource))?,
            &checked_input(r::Id::new(&input.version))?,
        )
        .await?
        .map_err(|_| Error::from(ActionRejection::ResourceUnavailable))?;
        if state != r::State::Active {
            return Err(Error::from(ActionRejection::ResourceUnavailable).into());
        }
        let variant = input.variant(&version)?;
        let r::Declaration::Script {
            artifact,
            definition,
        } = variant.declaration()
        else {
            return Err(Error::Malformed.into());
        };
        definition
            .validate_parameters(&input.parameters)
            .map_err(|_| Error::Malformed)?;
        if artifact.length() > 16_777_216 {
            return Err(Error::Malformed.into());
        }
        let content = self.content.clone().ok_or(Error::Unsupported)?;
        let item = artifact.clone();
        let bytes = tokio::task::spawn_blocking(move || content.read(&item))
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))??;
        if definition.spec().profile == r::ScriptProfile::OsqueryInfoV1
            && bytes != b"SELECT version FROM osquery_info;\n"
        {
            return Err(Error::Malformed.into());
        }
        let frozen = Frozen {
            targets,
            input: input.clone(),
            definition: definition.clone(),
            resource_digest: version.digest().bytes(),
            artifact_reference: artifact.reference().as_str().into(),
            content: rss_mdm_agent_wire::TaskContent {
                length: artifact.length(),
                sha256: artifact.digest().bytes(),
            },
        };
        Ok(frozen)
    }
}

async fn check_capacity_in(
    tx: &mut PgTransaction<'_>,
    input: &Create,
    targets: &FrozenTargets,
    now: i64,
) -> Result<()> {
    if matches!(
        input.schedule.trigger,
        Trigger::Registration | Trigger::CheckIn { .. }
    ) {
        let tenant = tx.tenant_id().to_string();
        let devices = targets.devices.clone();
        let full=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT device FROM mdm_planning.action_plans CROSS JOIN LATERAL jsonb_array_elements_text(document->'targets'->'devices') device WHERE tenant_id=$1::uuid AND active AND (document->'input'->'schedule'->>'until')::bigint>$3 AND document->'input'->'schedule'->'trigger'->>'kind' IN ('check_in','registration') AND device=ANY($2) GROUP BY device HAVING count(*)>=128)").bind(tenant).bind(devices).bind(now).fetch_one(c).await})).await?;
        if full {
            return Err(Error::from(ActionRejection::Capacity).into());
        }
    }
    Ok(())
}

fn creation_receipt(id: Uuid, target_count: usize) -> Value {
    json!({"operationId":id,"planId":id,"revision":1,"authorization":"pending_review","targetCount":target_count,"nextStage":"review"})
}

async fn admit_creation_in(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    input: &Create,
) -> Result<(crate::authorization::Snapshot, i64)> {
    crate::transaction::lock(tx)
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))?;
    storage::lock(tx, "action-owner").await?;
    let now = storage::now(tx).await?;
    input.validate()?;
    let snapshot = storage::current(tx, proof).await?;
    if matches!(input.targets, Targets::Scope { .. }) {
        snapshot.require(proof, Permission::ScopeRead, None)?;
    }
    Ok((snapshot, now))
}
