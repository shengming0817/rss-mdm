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
impl CollectionPolicy {
    pub fn entry_source(&self) -> String {
        format!("scope:{}", self.policy.definition.scope)
    }
    pub async fn entry_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<Option<i64>> {
        let input = self.frozen.input();
        if !self.active || now < input.schedule.not_before || now >= input.schedule.ends_at() {
            return Ok(None);
        }
        let source = service.source.clone();
        let tenant = tx.tenant_id();
        let scope = self.policy.definition.scope;
        let channel = self.frozen.channel();
        let device = device.to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(async {
                    if !rss_mdm_registration_service::lifecycle::work_allowed_in(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        &tenant.to_string(),
                        &device,
                    )
                    .await?
                    {
                        return Ok(None);
                    }
                    Ok(
                        match source
                            .admission_on(c, tenant, scope, channel, &device)
                            .await?
                        {
                            Admission::Eligible { entry } => Some(entry),
                            _ => None,
                        },
                    )
                }
                .await)
            })
        })
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
pub async fn agent_source_in(tx: &mut PgTransaction<'_>, target: &Target) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let registration = target.registration;
    Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='agent.native' AND enabled)").bind(tenant).bind(registration).fetch_one(c).await})).await?)
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
            target.registration,
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
            registration_id: target.registration,
            generation: target.generation.try_into().map_err(|_| Error::Malformed)?,
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
