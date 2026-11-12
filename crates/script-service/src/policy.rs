//! Script consumes immutable published input and current Policy/Scope authority.
use crate::{
    Error, FrozenScript, Result, Target, Transactions, runs::Run, stored, transaction::checked,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_inventory::Channel;
use rss_mdm_policy::{Frequency, Policy};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Published {
    Execution {
        action: Box<FrozenScript>,
        frequency: Frequency,
    },
}
pub struct ScriptPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub frozen: FrozenScript,
    pub frequency: Frequency,
    pub active: bool,
    pub policy: Policy,
}
pub async fn read_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ScriptPolicy> {
    service.validate_in(tx)?;
    let version =
        checked(service.policy_reader.version_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    let policy = checked(service.policy_reader.locked_in(tx, version.policy).await?)?
        .ok_or(Error::NotFound)?;
    let Published::Execution { action, frequency } =
        stored(serde_json::from_value(version.frozen))?;
    Ok(ScriptPolicy {
        id,
        owner: policy.id,
        frozen: *action,
        frequency,
        active: policy.state.is_enabled(),
        policy,
    })
}
/// Read the immutable execution material in the assignment's existing tenant snapshot.
pub async fn read_on(
    c: &mut sqlx::PgConnection,
    reader: &rss_mdm_policy_postgres::PolicyReader,
    policy: &rss_mdm_policy::Policy,
) -> Result<ScriptPolicy> {
    let version = checked(reader.version_on(c, policy.version).await?)?.ok_or(Error::NotFound)?;
    if version.policy != policy.id {
        return Err(Error::Conflict.into());
    }
    let Published::Execution { action, frequency } =
        stored(serde_json::from_value(version.frozen))?;
    Ok(ScriptPolicy {
        id: policy.version,
        owner: policy.id,
        frozen: *action,
        frequency,
        active: policy.state.is_enabled(),
        policy: policy.clone(),
    })
}
impl ScriptPolicy {
    pub fn entry_source(&self) -> String {
        format!("scope:{}", self.policy.definition.scope)
    }
    async fn base_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        device: &rss_mdm_agent_wire::DeviceId,
        now: i64,
    ) -> Result<Option<rss_mdm_policy::pages::TaskAdmission>> {
        use rss_mdm_policy::pages::{TaskAdmission as A, TaskAdmissionState as S};
        let schedule = &self.frozen.input.schedule;
        let blocked = if !self.active {
            Some(A::new(S::Paused, None))
        } else if now < schedule.not_before {
            Some(A::new(S::Scheduled, None).not_before(Some(schedule.not_before)))
        } else if now >= schedule.ends_at() {
            Some(A::new(S::ScheduleEnded, None))
        } else if !rss_mdm_registration_service::lifecycle::work_allowed_on(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant.to_string(),
            device,
        )
        .await?
        {
            Some(A::new(S::LifecycleBlocked, None))
        } else {
            None
        };
        Ok(blocked)
    }
    fn scope_entry(
        scope: rss_mdm_scope_service::channels::ScopeAdmission,
    ) -> std::result::Result<i64, rss_mdm_policy::pages::TaskAdmission> {
        use rss_mdm_policy::pages::{TaskAdmission as A, TaskAdmissionState as S};
        match scope {
            rss_mdm_scope_service::channels::ScopeAdmission::Eligible { entry } => Ok(entry),
            rss_mdm_scope_service::channels::ScopeAdmission::Pending => {
                Err(A::new(S::ScopePending, None))
            }
            rss_mdm_scope_service::channels::ScopeAdmission::Excluded => {
                Err(A::new(S::OutsideScope, None))
            }
        }
    }
    /// Consume the Scope owner's qualification already read in this assignment snapshot.
    /// This path never calls Scope's lock-taking execution admission entrypoint.
    pub async fn entry_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        scope: rss_mdm_scope_service::channels::ScopeAdmission,
        device: &rss_mdm_agent_wire::DeviceId,
        now: i64,
    ) -> Result<std::result::Result<i64, rss_mdm_policy::pages::TaskAdmission>> {
        if let Some(reason) = self.base_on(c, tenant, device, now).await? {
            return Ok(Err(reason));
        }
        Ok(Self::scope_entry(scope))
    }
    pub async fn entry_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        now: i64,
    ) -> Result<Option<i64>> {
        crate::storage::lock_device(tx, device).await?;
        let tenant = tx.tenant_id();
        tx.with_connection_context(
            &mut (self, device, service),
            |(policy, device, service), c| {
                Box::pin(async move {
                    Ok(async {
                        if policy.base_on(c, tenant, device, now).await?.is_some() {
                            return Ok(None);
                        }
                        // Preserve the writer's Group/Scope/object fences and reuse its canonical qualification.
                        let scope = service
                            .source
                            .admission_on(
                                c,
                                tenant,
                                policy.policy.definition.scope,
                                rss_mdm_inventory::Channel::Agent,
                                device,
                            )
                            .await?;
                        Ok(Self::scope_entry(scope).ok())
                    }
                    .await)
                })
            },
        )
        .await?
    }
    pub async fn authorized_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        Ok(self.run_admission_in(service, tx, target).await?
            && self
                .entry_in(service, tx, &target.device, now)
                .await?
                .is_some())
    }
    pub async fn run_admission_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        Ok(self.active
            && crate::eligibility::require_in(
                tx,
                service.agent_store.clone(),
                target,
                &self.frozen,
            )
            .await?)
    }
    pub async fn authorized_run_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &Run,
    ) -> Result<bool> {
        if run.resource_id != self.frozen.resource.id || run.policy_version != self.id {
            return Err(Error::Invariant.into());
        }
        if crate::storage::unknown_conflict_in(tx, run).await? {
            return Ok(false);
        }
        if run.state.started_at.is_none() {
            let now = crate::storage::now(tx).await?;
            if self
                .entry_in(service, tx, &run.target.device.clone(), now)
                .await?
                .is_none()
            {
                return Ok(false);
            }

            let source = service.source.clone();
            let tenant = tx.tenant_id();
            let device = run.target.device;
            let evidence = run.source_objects.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .evidence_valid_on(c, tenant, Channel::Agent, &device, &evidence)
                            .await)
                    })
                })
                .await??
            {
                return Ok(false);
            }
        }
        if let Some(invocation) = &run.invocation {
            let wire::TaskAuthorization::SelfService { policy_version, .. } =
                invocation.authorization
            else {
                return Ok(false);
            };
            if policy_version != self.id
                || invocation.pending_scope.is_some()
                || self
                    .frozen
                    .definition
                    .validate_parameters(&serde_json::json!(invocation.parameters))
                    .is_err()
            {
                return Ok(false);
            }
            if let Some(expected) = &invocation.execution_target
                && self
                    .execution_target_in(service, tx, &run.target)
                    .await?
                    .as_ref()
                    != Some(expected)
            {
                return Ok(false);
            }
        }
        self.run_admission_in(service, tx, &run.target).await
    }
    pub async fn execution_target_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<Option<wire::SoftwareExecutionTarget>> {
        let binding =
            crate::agent_facts::agent_binding_in(tx, service.agent_store.clone(), target.device)
                .await?
                .ok_or(Error::Forbidden)?;
        Ok(Some(
            rss_mdm_software_service::preparation::execution::identity_target(
                self.frozen.execution_identity(),
                match self.frozen.input.platform {
                    rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                    rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
                },
                &binding.execution_context,
            )
            .map_err(|_| Error::Forbidden)?,
        ))
    }
    pub async fn task(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &Run,
        attempt: Uuid,
        permit: wire::TaskPermit,
        expiry: i64,
    ) -> Result<wire::TaskPayload> {
        let (authorization, parameters) = if let Some(invocation) = &run.invocation {
            (
                invocation.authorization.clone(),
                invocation.parameters.clone(),
            )
        } else {
            (
                wire::TaskAuthorization::Policy {
                    policy_id: self.owner,
                    policy_version: self.id,
                },
                crate::checked_input(serde_json::from_value(
                    self.frozen.parameters.resolve(&serde_json::json!({}))?,
                ))?,
            )
        };
        let binding = crate::agent_facts::agent_binding_in(
            tx,
            service.agent_store.clone(),
            run.target.device,
        )
        .await?
        .ok_or(Error::Forbidden)?;
        Ok(self.frozen.task(
            stored(Uuid::parse_str(&tx.tenant_id().to_string()))?,
            &run.target,
            run.id,
            attempt,
            permit,
            expiry,
            authorization,
            parameters,
            run.deadline,
            &binding.execution_context,
        )?)
    }
}

pub async fn current_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    checked(reader.locked_in(tx, id).await?)
}

pub async fn admission_in(
    source: &std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    channel: rss_mdm_inventory::Channel,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<rss_mdm_scope_service::channels::ScopeAdmission> {
    let tenant = tx.tenant_id();
    let source = source.clone();
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(source
                    .admission_on(c, tenant, scope, channel, &device)
                    .await)
            })
        })
        .await??)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn published_script_round_trips_and_rejects_other_owner_or_extra_fields() {
        let value = json!({"kind":"execution","frequency":"every_trigger","action":{
            "input":{"platform":"windows","architecture":"x86_64","run_lifetime_seconds":300,"schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}},
            "parameters":{},"resource":{"id":"test.script","version":"1","variant":"default"},
            "definition":{"profile":"power_shell7","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{},"additionalProperties":false},"purpose":{"kind":"action"},"timeoutSeconds":1,"outputBytes":4096,"maxRows":1},
            "collection":null,"resource_digest":vec![1u8;32],"artifact_reference":"artifact","content":{"length":3,"sha256":vec![2u8;32]}
        }});
        let frozen: Published = serde_json::from_value(value).unwrap();
        let stored = serde_json::to_value(frozen).unwrap();
        assert_eq!(stored["kind"], "execution");
        let restored: Published = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), stored);
        let mut invalid = stored.clone();
        invalid["kind"] = json!("agent_collection");
        assert!(serde_json::from_value::<Published>(invalid).is_err());
        let mut invalid = stored;
        invalid["legacy"] = json!(true);
        assert!(serde_json::from_value::<Published>(invalid).is_err());
    }
}
