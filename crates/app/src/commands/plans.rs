//! Frozen product plans are the only admission path for firewall writes.
use super::*;
use crate::{PlanFailureReason as Reason, PlanStage};
use crate::{
    authorization::Permission,
    identity::Principal,
    management::{
        configuration::Evidence,
        model::{FrozenIntent, Preview},
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Execute {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub deadline: i64,
}
impl Execute {
    fn validate_deadline(&self, now: i64) -> std::result::Result<(), Error> {
        if self.deadline <= now || self.deadline.checked_mul(1_000_000).is_none() {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
impl Commands {
    pub(super) async fn execute_plan(
        &self,
        proof: &Principal,
        policy: &str,
        plan: Uuid,
        input: &Execute,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        proof.require(Permission::PlanExecute, None)?;
        self.transact(
            (self, proof, policy, plan, input, audit),
            audit,
            |ctx, tx| {
                Box::pin(async move {
                    let (service, proof, policy, plan, input, audit) = *ctx;
                    service
                        .execute_plan_in(tx, proof, policy, plan, input, audit)
                        .await
                })
            },
        )
        .await
    }
    async fn execute_plan_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &Principal,
        policy: &str,
        plan: Uuid,
        input: &Execute,
        audit: &Audit,
    ) -> Result<Value> {
        let s = self;
        self.lock_plan_request(tx, proof, input).await?;
        let fingerprint = Sha256::digest(invalid(serde_json::to_vec(&(
            proof.user(),
            policy,
            plan,
            input,
        )))?)
        .to_vec();
        storage::lock(tx, &format!("request:{}", input.operation_id)).await?;
        if let Some(response) =
            replay_execution(tx, proof, input.operation_id, &fingerprint, audit).await?
        {
            return Ok(response);
        }
        input.validate_deadline(storage::now(tx).await?)?;
        let preview =
            validate_execute_plan(tx, proof, policy, plan, input.expected_revision).await?;
        let targets = actionable_targets(&preview);
        let mut results = self.cancel_intents(tx, proof, &preview).await?;
        for device in targets {
            results.push(
                s.admit_target(tx, proof, &preview, device, input, audit)
                    .await?,
            );
        }
        let response = json!({"plan":plan,"operations":results});
        let tenant = s.tenant.to_string();
        let key = policy.to_owned();
        let value = response.clone();
        let rev = input.expected_revision;
        let request = input.operation_id;
        tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("INSERT INTO mdm_commands.requests(tenant_id,id,plan,fingerprint,response) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5)").bind(&tenant).bind(request.to_string()).bind(plan.to_string()).bind(fingerprint).bind(value).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_commands.plan_executions VALUES($1::uuid,$2::uuid,$3,$4,$5::uuid)").bind(tenant).bind(plan.to_string()).bind(key).bind(rev).bind(request.to_string()).execute(c).await?;Ok(())
        })).await?;
        audit.management_result(crate::audit::ManagementResult::Performed);
        storage::audit(tx, audit, 202).await?;
        proof.check_live()?;
        Ok(response)
    }
    async fn lock_plan_request(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &Principal,
        input: &Execute,
    ) -> Result<()> {
        storage::admit(tx).await?;
        let tenant = self.tenant.to_string();
        let instance = self.instance.clone();
        let auth = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::authorization::lock_on(c, &tenant, &instance)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                    Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
                })
            })
            .await??;
        auth.require(proof, Permission::PlanExecute, None)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                    .bind(tenant)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        if input.operation_id.is_nil() || input.expected_revision < 1 {
            return Err(Error::Malformed.into());
        }
        Ok(())
    }
    async fn cancel_intents(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &Principal,
        preview: &Preview,
    ) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        for intent in &preview.plan.intents {
            let Some((device, version)) = intent.cancellation(preview) else {
                continue;
            };
            storage::authorized(tx, proof, device, Permission::FirewallWrite).await?;
            storage::authorized(tx, proof, device, Permission::OperationCancel).await?;
            storage::lock(tx, device).await?;
            let tenant = self.tenant.to_string();
            let name = device.to_owned();
            let policy = preview.policy.clone();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("DELETE FROM mdm_commands.firewall_owners WHERE tenant_id=$1::uuid AND device=$2 AND policy=$3 AND version=$4").bind(tenant).bind(name).bind(policy).bind(version as i64).execute(c).await?;Ok(())})).await?;
            let tenant = self.tenant.to_string();
            let device = device.to_owned();
            let policy = preview.policy.clone();
            let ids=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND device=$2 AND request->'task'->>'policy'=$3 AND request->'task'->>'kind'='firewall' AND (request->'task'->>'version')::bigint=$4 ORDER BY id").bind(tenant).bind(device).bind(policy).bind(version as i64).fetch_all(c).await})).await?;
            for id in ids {
                let op = storage::load(tx, corrupt(Uuid::parse_str(&id))?).await?;
                let command = self.required_command(tx, &op).await?;
                if !command.status().is_terminal()
                    && self
                        .store
                        .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
                        .await?
                        .outcome
                        == dc::Outcome::OutOfOrder
                {
                    return Err(Error::Conflict.into());
                }
                let command = self.required_command(tx, &op).await?;
                results.push(json!({"operationId":op.id,"commandId":op.id,"action":"cancel","commandStatus":service::status(command.status())}));
            }
        }
        Ok(results)
    }
    async fn admit_target(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &Principal,
        preview: &Preview,
        device: &str,
        input: &Execute,
        audit: &Audit,
    ) -> Result<Value> {
        let s = self;
        let frozen = preview.configuration.as_ref().ok_or(Error::Malformed)?;
        let policy = preview.policy.as_str();
        let plan = preview.id;
        let expected = frozen
            .devices
            .get(device)
            .ok_or(Reason::StalePlan.at(Some(device), PlanStage::Execute))?;
        storage::authorized(tx, proof, device, Permission::FirewallWrite).await?;
        storage::lock(tx, device).await?;
        let tenant = s.tenant.to_string();
        let name = device.to_owned();
        let owner=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT policy,version,operation::text FROM mdm_commands.firewall_owners WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(name).fetch_optional(c).await})).await?;
        if let Some(owner) = owner {
            if owner.try_get::<String, _>("policy")? != policy
                || owner.try_get::<i64, _>("version")? as u64 >= frozen.version
            {
                return Err(Reason::OwnerConflict
                    .at(Some(device), PlanStage::Execute)
                    .into());
            }
            let old = storage::load(
                tx,
                corrupt(Uuid::parse_str(&owner.try_get::<String, _>("operation")?))?,
            )
            .await?;
            if !s.required_command(tx, &old).await?.status().is_terminal()
                && s.store
                    .cancel(tx, old.scope, &old.command_id()?, old.coordinate)
                    .await?
                    .outcome
                    == dc::Outcome::OutOfOrder
            {
                return Err(Reason::OwnerConflict
                    .at(Some(device), PlanStage::Execute)
                    .into());
            }
        }
        let digest = Sha256::digest(format!("{plan}:{device}"));
        let id = Uuid::from_bytes(digest[..16].try_into().expect("digest width"));
        let create = Create {
            operation_id: id,
            deadline: input.deadline,
            task: Task::Firewall {
                enabled: frozen.enabled,
                plan,
                policy: policy.into(),
                version: frozen.version,
                os_version: expected.os_version.clone(),
                edition: expected.edition,
            },
        };
        let command_audit = audit.transaction_copy();
        command_audit.operation(id, "command_accept");
        command_audit.target(device);
        let result = s
            .create_in(tx, proof, device, &create, &command_audit)
            .await?;
        let tenant = s.tenant.to_string();
        let name = device.to_owned();
        let policy = policy.to_owned();
        let version = frozen.version as i64;
        let claimed=tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.firewall_owners VALUES($1::uuid,$2,$6,$3,$4,$5::uuid) ON CONFLICT(tenant_id,device,node) DO UPDATE SET version=excluded.version,operation=excluded.operation WHERE mdm_commands.firewall_owners.policy=excluded.policy AND mdm_commands.firewall_owners.version<excluded.version").bind(tenant).bind(name).bind(policy).bind(version).bind(id.to_string()).bind(rss_mdm_windows_mdm::configuration::FIREWALL_URI).execute(c).await.map(|r|r.rows_affected())})).await?;
        if claimed != 1 {
            return Err(Reason::OwnerConflict
                .at(Some(device), PlanStage::Execute)
                .into());
        }

        let target = service::target(s.tenant, device);
        let tenant = s.tenant.to_string();
        let scope = target.scope().reconciler().to_owned();
        let entity = target.entity().to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,$3)")
                    .bind(tenant)
                    .bind(scope)
                    .bind(entity)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(result)
    }
}
async fn validate_execute_plan(
    tx: &mut PgTransaction<'_>,
    proof: &Principal,
    policy: &str,
    plan: Uuid,
    expected_revision: i64,
) -> Result<Preview> {
    let tenant = tx.tenant_id().to_string();
    let executed=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_commands.plan_executions WHERE tenant_id=$1::uuid AND plan=$2::uuid)").bind(tenant).bind(plan.to_string()).fetch_one(c).await})).await?;
    if executed {
        return Err(Error::Conflict.into());
    }
    let preview = load_saved_plan(tx, policy, plan, expected_revision).await?;
    validate_sources(tx, &preview.sources).await?;
    authorize_plan(tx, proof, &preview).await?;
    let targets = actionable_targets(&preview);
    for device in &targets {
        validate_target(tx, &preview, device).await?;
    }
    Ok(preview)
}

fn actionable_targets(preview: &Preview) -> Vec<&String> {
    preview.devices.iter().filter(|device| preview.plan.scheduling_open && preview.plan.intents.iter().any(|i| matches!(i, FrozenIntent::Add {device: d, ..} | FrozenIntent::Supersede {device: d, ..} if d == *device))).collect()
}

async fn validate_target(
    tx: &mut PgTransaction<'_>,
    preview: &Preview,
    device: &str,
) -> Result<()> {
    let frozen = preview.configuration.as_ref().ok_or(Error::Malformed)?;
    let expected = frozen
        .devices
        .get(device)
        .ok_or(Reason::StalePlan.at(Some(device), PlanStage::Execute))?;
    let (registration, generation) =
        storage::current_registration(tx, device)
            .await
            .map_err(|error| match error {
                Fault::Request(Error::Conflict) => Reason::StalePlan
                    .at(Some(device), PlanStage::Execute)
                    .into(),
                other => other,
            })?;
    if (registration, generation) != (expected.registration, expected.generation) {
        return Err(Reason::StalePlan
            .at(Some(device), PlanStage::Execute)
            .into());
    }
    let current = evidence(tx, registration, generation, device).await?;
    if current != *expected {
        return Err(Reason::StalePlan
            .at(Some(device), PlanStage::Execute)
            .into());
    }
    let platform =
        rss_mdm_windows_mdm::configuration::Platform::new(&current.os_version, current.edition)
            .map_err(|_| Reason::PlatformUnsupported.at(Some(device), PlanStage::Execute))?;
    let compiled = rss_mdm_windows_mdm::configuration::Firewall::compile(frozen.enabled, &platform)
        .map_err(|_| Reason::PlatformUnsupported.at(Some(device), PlanStage::Execute))?;
    if Sha256::digest(compiled.identity()).as_slice() != frozen.compiled_digest {
        return Err(Reason::StalePlan
            .at(Some(device), PlanStage::Execute)
            .into());
    }

    storage::lock(tx, device).await?;
    let tenant = tx.tenant_id().to_string();
    let name = device.to_owned();
    let owner = tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT policy,version FROM mdm_commands.firewall_owners WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(name).fetch_optional(c).await
    })).await?;
    if let Some(owner) = owner
        && (owner.try_get::<String, _>("policy")? != preview.policy
            || owner.try_get::<i64, _>("version")? as u64 >= frozen.version)
    {
        return Err(Reason::OwnerConflict
            .at(Some(device), PlanStage::Execute)
            .into());
    }
    Ok(())
}

async fn evidence(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    generation: i64,
    device: &str,
) -> Result<Evidence> {
    let tenant = tx.tenant_id().to_string();
    let r=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2::uuid AND generation=$3").bind(tenant).bind(registration.to_string()).bind(generation).fetch_optional(c).await})).await?.ok_or(Reason::CapabilityUnknown.at(Some(device), PlanStage::Execute))?;
    Ok(Evidence {
        registration,
        generation,
        os_version: r.try_get("os_version")?,
        edition: r.try_get::<i32, _>("edition")? as u32,
    })
}

async fn validate_sources(
    tx: &mut PgTransaction<'_>,
    sources: &[crate::management::model::Source],
) -> Result<()> {
    for source in sources {
        let tenant = tx.tenant_id().to_string();
        let revision = source.revision as i64;
        let valid = match &source.reference {
            crate::management::model::Reference::Group(id) => {
                let id = id.to_string();
                let members = source.member_version;
                tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2::uuid AND revision=$3 AND member_version=$4 AND NOT deleted)").bind(tenant).bind(id).bind(revision).bind(members).fetch_one(c).await})).await?
            }
            crate::management::model::Reference::Device(device) => {
                let device = device.clone();
                tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT coalesce(max(generation)=$3,false) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active'").bind(tenant).bind(device).bind(revision).fetch_one(c).await})).await?
            }
        };
        if !valid {
            let device = match &source.reference {
                crate::management::model::Reference::Device(device) => Some(device.as_str()),
                crate::management::model::Reference::Group(_) => None,
            };
            return Err(Reason::StalePlan.at(device, PlanStage::Execute).into());
        }
    }
    Ok(())
}

async fn authorize_plan(
    tx: &mut PgTransaction<'_>,
    proof: &Principal,
    preview: &Preview,
) -> Result<()> {
    let targets: std::collections::BTreeSet<&str> = preview
        .devices
        .iter()
        .map(String::as_str)
        .chain(preview.plan.intents.iter().map(FrozenIntent::device))
        .collect();
    for device in targets {
        storage::authorized(tx, proof, device, Permission::FirewallWrite).await?;
    }
    for intent in &preview.plan.intents {
        if let Some((device, _)) = intent.cancellation(preview) {
            storage::authorized(tx, proof, device, Permission::OperationCancel).await?;
        }
    }
    Ok(())
}
async fn authorize_replay(
    tx: &mut PgTransaction<'_>,
    proof: &Principal,
    response: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let plan = response["plan"]
        .as_str()
        .ok_or(Error::Unavailable(Failure::CommandInvariant))?
        .to_owned();
    let document: Value = tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar("SELECT document FROM mdm_management.previews WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(plan).fetch_one(c).await
    })).await?;
    let preview: Preview = corrupt(serde_json::from_value(document))?;
    authorize_plan(tx, proof, &preview).await
}

async fn load_saved_plan(
    tx: &mut PgTransaction<'_>,
    policy: &str,
    plan: Uuid,
    expected_revision: i64,
) -> Result<Preview> {
    let tenant = tx.tenant_id().to_string();
    let key = policy.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT p.document,r.saved_revision FROM mdm_management.previews p JOIN mdm_management.plan_references r ON(r.tenant_id,r.preview)=(p.tenant_id,p.id) JOIN mdm_policy.aggregates a ON(a.tenant_id,a.id,a.revision)=(r.tenant_id,r.policy,r.saved_revision) JOIN mdm_management.scopes sc ON(sc.tenant_id,sc.id,sc.revision)=(p.tenant_id,p.scope,p.scope_revision) WHERE p.tenant_id=$1::uuid AND p.id=$2::uuid AND r.policy=$3 AND NOT sc.deleted").bind(tenant).bind(plan.to_string()).bind(key).fetch_optional(c).await})).await?.ok_or(Reason::StalePlan.at(None, PlanStage::Execute))?;
    if row.try_get::<i64, _>("saved_revision")? != expected_revision {
        return Err(Reason::StalePlan.at(None, PlanStage::Execute).into());
    }
    let preview: Preview = corrupt(serde_json::from_value(row.try_get("document")?))?;
    if preview.devices.len() > crate::management::configuration::MAX_TARGETS {
        return Err(Error::ConfigurationTargetLimit.into());
    }
    let frozen = preview.configuration.as_ref().ok_or(Error::Malformed)?;
    if frozen.ddf != rss_mdm_windows_mdm::configuration::REVISION || preview.policy != policy {
        return Err(Reason::StalePlan.at(None, PlanStage::Execute).into());
    }
    Ok(preview)
}

async fn replay_execution(
    tx: &mut PgTransaction<'_>,
    proof: &Principal,
    request: Uuid,
    fingerprint: &[u8],
    audit: &Audit,
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let replay = tx
        .with_connection(move |c| {
            Box::pin(async move { storage::read_on(c, &tenant, request).await })
        })
        .await?;
    let Some((old, response)) = replay else {
        return Ok(None);
    };
    if old != fingerprint {
        return Err(Reason::StalePlan.at(None, PlanStage::Execute).into());
    }
    authorize_replay(tx, proof, &response).await?;
    audit.management_result(crate::audit::ManagementResult::Replayed);
    storage::audit(tx, audit, 200).await?;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_plan_deadline_is_future_and_representable() {
        for deadline in [0, 100, i64::MAX] {
            assert!(
                Execute {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    deadline
                }
                .validate_deadline(100)
                .is_err()
            );
        }
        assert!(
            Execute {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                deadline: 101
            }
            .validate_deadline(100)
            .is_ok()
        );
    }
}
