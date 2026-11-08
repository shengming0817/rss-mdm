//! Collection admission uses frozen definitions and current Policy/Scope facts.
use super::{frozen::Published, model::Target, participants::Admission, service::Transactions};
use crate::{Error, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub struct CollectionPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub frozen: Published,
    pub active: bool,
    pub policy: rss_mdm_policy::Policy,
}
pub async fn read_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<CollectionPolicy> {
    service.validate_in(tx)?;
    let version =
        checked(service.policy_reader.version_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    let policy = checked(service.policy_reader.locked_in(tx, version.policy).await?)?
        .ok_or(Error::NotFound)?;
    Ok(CollectionPolicy {
        id,
        owner: policy.id,
        frozen: stored(serde_json::from_value(version.frozen))?,
        active: policy.state.is_enabled(),
        policy,
    })
}
/// Read the immutable execution material in the assignment's existing tenant snapshot.
pub async fn read_on(
    c: &mut sqlx::PgConnection,
    reader: &rss_mdm_policy_postgres::PolicyReader,
    policy: &rss_mdm_policy::Policy,
) -> Result<CollectionPolicy> {
    let version = checked(reader.version_on(c, policy.version).await?)?.ok_or(Error::NotFound)?;
    if version.policy != policy.id {
        return Err(Error::Conflict.into());
    }
    Ok(CollectionPolicy {
        id: policy.version,
        owner: policy.id,
        frozen: stored(serde_json::from_value(version.frozen))?,
        active: policy.state.is_enabled(),
        policy: policy.clone(),
    })
}
impl CollectionPolicy {
    pub fn entry_source(&self) -> String {
        format!("scope:{}", self.policy.definition.scope)
    }
    async fn base_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        device: &str,
        now: i64,
    ) -> Result<Option<rss_mdm_policy::pages::TaskAdmission>> {
        use rss_mdm_policy::pages::{TaskAdmission as A, TaskAdmissionState as S};
        let schedule = &self.frozen.input().schedule;
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
        scope: Admission,
    ) -> std::result::Result<i64, rss_mdm_policy::pages::TaskAdmission> {
        use rss_mdm_policy::pages::{TaskAdmission as A, TaskAdmissionState as S};
        match scope {
            Admission::Eligible { entry } => Ok(entry),
            Admission::Pending => Err(A::new(S::ScopePending, None)),
            Admission::Excluded => Err(A::new(S::OutsideScope, None)),
        }
    }
    /// Consume the Scope owner's qualification already read in this assignment snapshot.
    /// This path never calls Scope's lock-taking execution admission entrypoint.
    pub async fn entry_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        scope: Admission,
        device: &str,
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
        device: &str,
        now: i64,
    ) -> Result<Option<i64>> {
        super::storage::lock_device(tx, device).await?;
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
                                policy.frozen.channel(),
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
    pub async fn run_admission_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        if !self.active {
            return Ok(false);
        }
        match &self.frozen {
            Published::AgentCollection { action, .. } => {
                if !agent_source_in(tx, target).await? {
                    return Ok(false);
                }
                super::eligibility::check_in(
                    tx,
                    service.agent_store.clone(),
                    target,
                    action.input.platform,
                    action.input.architecture,
                    &action.definition,
                )
                .await
            }
            Published::NativeCollection { action, .. } => {
                let native = service.native.clone();
                let tenant = tx.tenant_id();
                tx.with_connection_context(
                    &mut (target, &action.definition),
                    |(target, template), c| {
                        Box::pin(async move {
                            Ok(native.eligible_on(c, tenant, target, template).await)
                        })
                    },
                )
                .await?
            }
        }
    }
    pub async fn authorized_agent_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &super::model::AgentRun,
    ) -> Result<bool> {
        if run.state.started_at.is_none() {
            let now = super::storage::now(tx).await?;
            if self
                .entry_in(service, tx, &run.target.device, now)
                .await?
                .is_none()
            {
                return Ok(false);
            }

            let source = service.source.clone();
            let tenant = tx.tenant_id();
            let device = run.target.device.clone();
            let evidence = run.source_objects.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .evidence_valid_on(
                                c,
                                tenant,
                                rss_mdm_inventory::Channel::Agent,
                                &device,
                                &evidence,
                            )
                            .await)
                    })
                })
                .await??
            {
                return Ok(false);
            }
        }
        self.run_admission_in(service, tx, &run.target).await
    }
    pub async fn completion_agent_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        Ok(self.active && agent_source_in(tx, target).await?)
    }
}
pub async fn agent_source_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    target: &Target,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_access.report_sources WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND source = 'agent.native' AND enabled)")
        .bind(tenant.to_string()).bind(target.device.clone()).fetch_one(c).await?)
}
pub async fn agent_source_in(tx: &mut PgTransaction<'_>, target: &Target) -> Result<bool> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(&mut (target,), |(target,), c| {
        Box::pin(async move { Ok(agent_source_on(c, tenant, target).await) })
    })
    .await?
}

impl CollectionPolicy {
    pub fn agent(&self) -> Result<&super::frozen::FrozenAgent> {
        match &self.frozen {
            Published::AgentCollection { action, .. } => Ok(action),
            _ => Err(Error::Malformed.into()),
        }
    }
    pub async fn task(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &super::model::AgentRun,
        attempt: Uuid,
        permit: rss_mdm_agent_wire::runtime::TaskPermit,
        expiry: i64,
    ) -> Result<rss_mdm_agent_wire::runtime::TaskPayload> {
        use rss_mdm_agent_wire::runtime as wire;
        let v = self;
        let frozen = self.agent()?;
        let target = &run.target;
        let plan = frozen.definition.spec().plan.clone();
        let binding = super::agent_facts::agent_binding_in(
            tx,
            service.agent_store.clone(),
            target.device.clone(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let execution = checked_input(wire::NativeExecutionBinding::bind(
            &plan,
            &binding.execution_context,
        ))?;
        let spec = wire::CollectionTaskSpec {
            fields: frozen
                .fields
                .iter()
                .map(crate::collection::wire::to_wire_field)
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| Error::Malformed)?,
            mappings: frozen.definition.spec().mappings.clone(),
            wire_version: wire::COLLECTION_TASK_VERSION,
            execution,
            tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
            device_id: target.device.clone(),

            platform: plan.platform(),
            architecture: match frozen.input.architecture {
                rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
            },
            task_id: run.id,
            attempt_id: attempt,
            permit,
            expires_at: expiry,
            deadline: run.deadline,
            resource: frozen.resource.clone(),
            resource_digest: frozen.resource_digest,
            authorization: wire::TaskAuthorization::Policy {
                policy_id: v.owner,
                policy_version: v.id,
            },
            plan_digest: plan.digest(),
            plan,
        };
        checked_input(spec.validate())?;
        Ok(wire::TaskPayload::Collection(Box::new(spec)))
    }
}
