//! Read-only software assignment bridge from authored Policy to the shared Agent Run.
use super::super::action_contract::FrozenSoftwareAction;
use super::*;
use rss_mdm_policy::{SoftwareIntent, SoftwareRollout, SoftwareTarget};
use rss_mdm_software_service::catalog::{Catalog, Error as CatalogError, FrozenSoftware};
use std::collections::BTreeSet;
use std::sync::Arc;

pub struct SoftwareExecutionPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub frozen: FrozenSoftwareAction,
    pub active: bool,
    policy: Policy,
}
pub struct StageCounts {
    pub total: u64,
    pub reported: u64,
    pub waiting_user: u64,
    pub unknown: u64,
    pub waiting_reboot: u64,
    pub failed: u64,
    pub verified: u64,
    pub unsupported_capability: u64,
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAdmissionState {
    Paused,
    OutsideWindow,
    OutsideScope,
    ScopePending,
    OutsideStage,
    Scheduled,
    SuccessGate,
    MissingRegistration,
    AmbiguousRegistration,
    UnsupportedCapability,
    MissingVariant,
    ApprovalWithdrawn,
    PermissionWithdrawn,
    ChannelUnknown,
    AlreadySatisfied,
    OrganizationConflict,
    MissingNativeRights,
    MissingArchitecture,
    Eligible,
}
#[derive(serde::Serialize)]
pub struct TaskAdmission {
    state: TaskAdmissionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<usize>,
}
impl TaskAdmission {
    pub(super) fn new(state: TaskAdmissionState, stage: Option<usize>) -> Self {
        Self { state, stage }
    }
    pub fn is_eligible(&self) -> bool {
        matches!(self.state, TaskAdmissionState::Eligible)
    }
}

pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<SoftwareExecutionPolicy> {
    let (policy, frozen) = storage::version_in(reader, tx, id).await?;
    let Frozen::Software { action } = frozen else {
        return Err(Error::Unsupported.into());
    };
    Ok(SoftwareExecutionPolicy {
        id,
        owner: policy.id,
        active: policy.enabled && policy.version == id,
        frozen: *action,
        policy,
    })
}
impl SoftwareExecutionPolicy {
    pub fn draft(definition: rss_mdm_policy::Definition, frozen: FrozenSoftwareAction) -> Self {
        let id = Uuid::nil();
        Self {
            id,
            owner: id,
            frozen,
            active: true,
            policy: Policy {
                id,
                revision: 0,
                version: id,
                number: 0,
                enabled: true,
                definition,
            },
        }
    }
    pub fn intent(&self) -> SoftwareIntent {
        self.frozen.intent
    }
    fn rollout(&self) -> Result<&SoftwareRollout> {
        match &self.policy.definition.action {
            Action::Software { rollout, .. } => Ok(rollout),
            _ => Err(Error::Malformed.into()),
        }
    }
    pub fn stages(&self) -> Result<&[rss_mdm_policy::SoftwareRolloutStage]> {
        Ok(&self.rollout()?.stages)
    }
    pub fn variant(&self, platform: Platform, architecture: Architecture) -> Option<&str> {
        self.frozen
            .variants
            .get(&SoftwareTarget::new(platform, architecture))
            .map(String::as_str)
    }
    /// Return the first matching stage and the root Scope entry coordinate.
    pub async fn entry_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<Option<(usize, i64)>> {
        if !self.active
            || now < self.frozen.schedule.not_before
            || now >= self.frozen.schedule.ends_at()
        {
            return Ok(None);
        }
        let Some(entry) = storage::eligible_in(tx, &self.policy, device).await? else {
            return Ok(None);
        };
        let stages = &self.rollout()?.stages;
        for (index, stage) in stages.iter().enumerate() {
            let scope = stage.scope;
            let device_name = device.to_owned();
            let admission: Value = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT mdm_planning.scope_admission($1,$2)")
                            .bind(scope)
                            .bind(device_name)
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            match admission["state"].as_str() {
                Some("eligible") => {
                    let (total, verified) = if stage.minimum_verified_percent.is_some() {
                        self.stage_progress_in(tx, index.checked_sub(1).ok_or(Error::Malformed)?)
                            .await?
                    } else {
                        (0, 0)
                    };
                    return Ok(stage.open(now, total, verified).then_some((index, entry)));
                }
                Some("pending") => return Ok(None),
                Some("excluded") => (),
                _ => return Err(Error::Unavailable(crate::Failure::PlanningStorage).into()),
            }
        }
        Ok(None)
    }
    /// One support decision covers the complete exact dependency closure.
    pub async fn supported_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        binding: &crate::execution::channels::AgentBinding,
    ) -> Result<bool> {
        let platform = match binding.platform.as_str() {
            "windows" => Platform::Windows,
            "macos" => Platform::Macos,
            _ => return Ok(false),
        };
        let architecture = match binding.architecture.as_str() {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            _ => return Ok(false),
        };
        let steps = match self
            .execution_steps_in(service, tx, platform, architecture)
            .await
        {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(false),
            Err(crate::transaction::Fault::Request(Error::Unsupported)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.supported_steps_in(service, tx, binding, platform, steps)
            .await
    }
    async fn supported_steps_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        binding: &crate::execution::channels::AgentBinding,
        platform: Platform,
        steps: Vec<FrozenSoftware>,
    ) -> Result<bool> {
        let mut artifact_count = 0usize;
        for (index, selected) in steps.into_iter().enumerate() {
            let variant = selected
                .version()
                .resolve(
                    selected.platform(),
                    selected.architecture(),
                    selected.variant(),
                )
                .map_err(|_| Error::Malformed)?;
            let resource::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Malformed.into());
            };
            let action =
                crate::execution::actions::software_wire::software_action(definition.spec());
            let task_platform = match platform {
                Platform::Windows => rss_mdm_agent_wire::TaskPlatform::Windows,
                Platform::Macos => rss_mdm_agent_wire::TaskPlatform::Macos,
            };
            let export = match crate::execution::actions::software_exports::for_step_in(
                service,
                tx,
                &self.frozen.delivery,
                &selected,
                &action,
            )
            .await
            {
                Ok(export) => export,
                Err(crate::transaction::Fault::Request(Error::Unsupported)) => return Ok(false),
                Err(error) => return Err(error),
            };
            let step = match crate::execution::actions::software_wire::software_step(
                definition.spec(),
                index,
                task_platform,
                &binding.execution_context,
                export,
            ) {
                Ok(step) => step,
                Err(_) => return Ok(false),
            };
            artifact_count += step.artifacts.len();
            if artifact_count > 64
                || step
                    .export
                    .validate_for(
                        &step,
                        Uuid::parse_str(&tx.tenant_id().to_string())
                            .map_err(|_| Error::Malformed)?,
                        &binding.execution_context,
                    )
                    .is_err()
            {
                return Ok(false);
            }
            if action
                .required_profile(task_platform)
                .is_none_or(|required| !binding.capabilities.contains(&required))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Current stage denominator and independently verified results; never infer from publication.
    pub async fn stage_progress_in(
        &self,
        tx: &mut PgTransaction<'_>,
        index: usize,
    ) -> Result<(u64, u64)> {
        let counts = self.counts_in(tx, index, None).await?;
        Ok((counts.total, counts.verified))
    }
    /// Live target denominator with the latest per-device result in this stage.
    pub async fn stage_counts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        index: usize,
        service: &crate::execution::ExecutionService,
    ) -> Result<StageCounts> {
        self.counts_in(tx, index, Some(service)).await
    }
    async fn counts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        index: usize,
        service: Option<&crate::execution::ExecutionService>,
    ) -> Result<StageCounts> {
        let stages = &self.rollout()?.stages;
        let stage = stages.get(index).ok_or(Error::Malformed)?;
        let scope = stage.scope;
        let root = self.policy.definition.scope;
        let earlier: Vec<Uuid> = stages[..index].iter().map(|s| s.scope).collect();
        let tenant = tx.tenant_id().to_string();
        let version = self.id;
        let prefix = format!("software:stage:{}:%", stage.scope);
        let optional = matches!(self.intent(), SoftwareIntent::AvailableInstall);
        let now = crate::execution::storage::now(tx).await?;
        let include_capabilities = service.is_some();
        let (total, reported, waiting_user, unknown, waiting_reboot, failed, verified, targets): (i64, i64, i64, i64, i64, i64, i64, Option<Vec<String>>) = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("WITH targets AS (SELECT r.device FROM mdm_planning.scopes s JOIN mdm_planning.scope_results r ON (r.tenant_id,r.run)=(s.tenant_id,s.resolution) JOIN mdm_planning.scopes root ON root.tenant_id=s.tenant_id AND root.id=$6::uuid AND NOT root.deleted JOIN mdm_planning.scope_results rr ON (rr.tenant_id,rr.run,rr.device)=(root.tenant_id,root.resolution,r.device) AND rr.matched WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND NOT s.deleted AND r.matched AND NOT EXISTS (SELECT 1 FROM mdm_planning.scopes p JOIN mdm_planning.scope_results x ON (x.tenant_id,x.run)=(p.tenant_id,p.resolution) WHERE p.tenant_id=s.tenant_id AND p.id=ANY($3::uuid[]) AND x.device=r.device AND x.matched)) SELECT count(*),count(*) FILTER(WHERE latest.result IS NOT NULL),count(*) FILTER(WHERE $7::boolean AND latest.state->>'execution'='not_started' AND latest.state->>'cancellation'='none' AND latest.state->'delivery'->>'kind' IN ('claimed','received') AND (latest.state->'delivery'->>'leaseUntil')::bigint>$8),count(*) FILTER(WHERE latest.result->>'effect'='unknown' OR latest.state->>'execution'='unknown'),count(*) FILTER(WHERE latest.result->>'effect'='waiting_reboot'),count(*) FILTER(WHERE latest.result->>'effect'='failed'),count(*) FILTER(WHERE latest.result->>'effect'='verified'),array_agg(targets.device) FILTER(WHERE $9::boolean) FROM targets LEFT JOIN LATERAL (SELECT a.state,a.result FROM mdm_commands.action_runs a WHERE a.tenant_id=$1::uuid AND a.policy_version=$4::uuid AND a.device=targets.device AND a.occurrence LIKE $5 ORDER BY a.created_at DESC,a.id DESC LIMIT 1) latest ON true")
                .bind(tenant).bind(scope).bind(earlier).bind(version).bind(prefix).bind(root).bind(optional).bind(now).bind(include_capabilities).fetch_one(c).await
        })).await?;
        let unsupported = if let Some(service) = service {
            let mut supported = std::collections::BTreeSet::new();
            for devices in targets.unwrap_or_default().chunks(128) {
                for target in crate::execution::channels::agent_targets_in(
                    tx,
                    service.agent_store.clone(),
                    devices.to_vec(),
                )
                .await?
                {
                    if self.supported_in(service, tx, &target.binding).await? {
                        supported.insert(target.device);
                    }
                }
            }
            total - i64::try_from(supported.len()).map_err(|_| Error::Malformed)?
        } else {
            0
        };
        Ok(StageCounts {
            total: total.try_into().map_err(|_| Error::Malformed)?,
            reported: reported.try_into().map_err(|_| Error::Malformed)?,
            waiting_user: waiting_user.try_into().map_err(|_| Error::Malformed)?,
            unknown: unknown.try_into().map_err(|_| Error::Malformed)?,
            waiting_reboot: waiting_reboot.try_into().map_err(|_| Error::Malformed)?,
            failed: failed.try_into().map_err(|_| Error::Malformed)?,
            verified: verified.try_into().map_err(|_| Error::Malformed)?,
            unsupported_capability: unsupported.try_into().map_err(|_| Error::Malformed)?,
        })
    }
    fn catalog(&self, service: &crate::execution::ExecutionService) -> Catalog {
        Catalog::new(
            service.runtime.clone(),
            service.tenant,
            Arc::new(crate::software_publication::host::Audit(
                service.audit_store.clone(),
            )),
        )
    }
    /// Resolve exact fixed prerequisites in dependency-first order.
    /// Missing/withdrawn admission is None; storage and integrity failures remain errors.
    pub async fn execution_steps_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<Option<Vec<FrozenSoftware>>> {
        let catalog = self.catalog(service);
        catalog.lock_in(tx).await?;
        let target_platform = match platform {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        };
        let target_architecture = match architecture {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        };
        let mut stack = vec![(
            self.frozen.resource.clone(),
            self.frozen.version.clone(),
            self.frozen.resource_digest,
            false,
            true,
            None,
        )];
        let mut active = BTreeSet::new();
        let mut done = BTreeSet::new();
        let mut ordered = Vec::new();
        while let Some((resource_id, version_id, digest, exit, root, selected)) = stack.pop() {
            let key = (resource_id.clone(), version_id.clone());
            if exit {
                active.remove(&key);
                done.insert(key);
                ordered.push(selected.ok_or(Error::Malformed)?);
                continue;
            }
            if done.contains(&key) {
                continue;
            }
            if !active.insert(key.clone()) || active.len() + done.len() > 256 {
                return Err(Error::Malformed.into());
            }
            let version = match catalog.version_in(tx, &resource_id, &version_id).await {
                Ok(version) => version,
                Err(CatalogError::NotAdmitted | CatalogError::Missing) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if version.digest().bytes() != digest {
                return Err(Error::Conflict.into());
            }
            let variant_key = if root {
                self.variant(platform, architecture)
                    .ok_or(Error::Unsupported)?
                    .to_owned()
            } else {
                let mut matches = version.variants().iter().filter(|v| {
                    v.platform() == target_platform && v.architecture() == target_architecture
                });
                let selected = matches.next().ok_or(Error::Unsupported)?;
                if matches.next().is_some() {
                    return Err(Error::Unsupported.into());
                }
                selected.key().as_str().to_owned()
            };
            let selected = catalog
                .resolve_admitted_in(
                    tx,
                    &resource_id,
                    &version_id,
                    target_platform,
                    target_architecture,
                    &checked_input(resource::Id::new(&variant_key))?,
                )
                .await;
            let selected = match selected {
                Ok(selected) => selected,
                Err(CatalogError::NotAdmitted | CatalogError::Missing) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if root && selected.admission().operation != self.frozen.admission_operation {
                return Ok(None);
            }
            let variant = selected
                .version()
                .resolve(target_platform, target_architecture, selected.variant())
                .map_err(|_| Error::Malformed)?;
            let resource::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Malformed.into());
            };
            let dependencies = if root && matches!(self.intent(), SoftwareIntent::ExplicitUninstall)
            {
                Vec::new()
            } else {
                definition.spec().dependencies.clone()
            };
            stack.push((resource_id, version_id, digest, true, root, Some(selected)));
            for dependency in dependencies.into_iter().rev() {
                stack.push((
                    dependency.resource,
                    dependency.version,
                    dependency.sha256,
                    false,
                    false,
                    None,
                ));
            }
        }
        if ordered.is_empty() || ordered.len() > 32 {
            return Err(Error::Unsupported.into());
        }
        Ok(Some(ordered))
    }
    /// Recheck the original enterprise approval and immutable target bytes in the transaction.
    pub async fn admitted_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<Option<FrozenSoftware>> {
        let Some(key) = self.variant(platform, architecture) else {
            return Ok(None);
        };
        let selected = self
            .catalog(service)
            .resolve_admitted_in(
                tx,
                &self.frozen.resource,
                &self.frozen.version,
                match platform {
                    Platform::Windows => resource::Platform::Windows,
                    Platform::Macos => resource::Platform::MacOS,
                },
                match architecture {
                    Architecture::X86_64 => resource::Architecture::X86_64,
                    Architecture::Aarch64 => resource::Architecture::Aarch64,
                },
                &checked_input(resource::Id::new(key))?,
            )
            .await;
        let selected = match selected {
            Ok(value) => value,
            Err(CatalogError::NotAdmitted | CatalogError::Missing) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if selected.version().digest().bytes() != self.frozen.resource_digest
            || selected.admission().operation != self.frozen.admission_operation
        {
            return Ok(None);
        }
        Ok(Some(selected))
    }
    pub async fn authorized_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        device: &str,
        platform: Platform,
        architecture: Architecture,
        now: i64,
    ) -> Result<bool> {
        if self.entry_in(tx, device, now).await?.is_none() {
            return Ok(false);
        }
        Ok(self
            .admitted_in(service, tx, platform, architecture)
            .await?
            .is_some())
    }
    /// Management uses the same stage, profile and current approval checks as task admission.
    pub async fn management_state_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<TaskAdmission> {
        if !self.active {
            return Ok(TaskAdmission::new(TaskAdmissionState::Paused, None));
        }
        if now < self.frozen.schedule.not_before || now >= self.frozen.schedule.ends_at() {
            return Ok(TaskAdmission::new(TaskAdmissionState::OutsideWindow, None));
        }
        if storage::eligible_in(tx, &self.policy, device)
            .await?
            .is_none()
        {
            return Ok(TaskAdmission::new(TaskAdmissionState::OutsideScope, None));
        }
        let mut stage_index = None;
        for (index, stage) in self.stages()?.iter().enumerate() {
            let scope = stage.scope;
            let name = device.to_owned();
            let state: Value = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT mdm_planning.scope_admission($1,$2)")
                            .bind(scope)
                            .bind(name)
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            match state["state"].as_str() {
                Some("eligible") => {
                    stage_index = Some(index);
                    break;
                }
                Some("pending") => {
                    return Ok(TaskAdmission::new(
                        TaskAdmissionState::ScopePending,
                        Some(index),
                    ));
                }
                Some("excluded") => (),
                _ => return Err(Error::Unavailable(crate::Failure::PlanningStorage).into()),
            }
        }
        let Some(index) = stage_index else {
            return Ok(TaskAdmission::new(TaskAdmissionState::OutsideStage, None));
        };
        let stage = &self.stages()?[index];
        if now < stage.opens_at {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::Scheduled,
                Some(index),
            ));
        }
        if stage.minimum_verified_percent.is_some() {
            let (total, verified) = self
                .stage_progress_in(tx, index.checked_sub(1).ok_or(Error::Malformed)?)
                .await?;
            if !stage.open(now, total, verified) {
                return Ok(TaskAdmission::new(
                    TaskAdmissionState::SuccessGate,
                    Some(index),
                ));
            }
        }
        let registrations = crate::execution::channels::agent_targets_in(
            tx,
            service.agent_store.clone(),
            vec![device.to_owned()],
        )
        .await?;
        if registrations.is_empty() {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::MissingRegistration,
                Some(index),
            ));
        }
        if registrations.len() != 1 {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::AmbiguousRegistration,
                Some(index),
            ));
        }
        let binding = &registrations[0].binding;
        let (platform, architecture) = (&binding.platform, &binding.architecture);
        let platform = match platform.as_str() {
            "windows" => Platform::Windows,
            "macos" => Platform::Macos,
            _ => return Err(Error::Malformed.into()),
        };
        let architecture = match architecture.as_str() {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            _ => return Err(Error::Malformed.into()),
        };
        if self.variant(platform, architecture).is_none() {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::MissingVariant,
                Some(index),
            ));
        }
        if self
            .admitted_in(service, tx, platform, architecture)
            .await?
            .is_none()
        {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::ApprovalWithdrawn,
                Some(index),
            ));
        }
        let steps = match self
            .execution_steps_in(service, tx, platform, architecture)
            .await
        {
            Ok(Some(steps)) => steps,
            Ok(None) => {
                return Ok(TaskAdmission::new(
                    TaskAdmissionState::ApprovalWithdrawn,
                    Some(index),
                ));
            }
            Err(crate::transaction::Fault::Request(Error::Unsupported)) => {
                return Ok(TaskAdmission::new(
                    TaskAdmissionState::UnsupportedCapability,
                    Some(index),
                ));
            }
            Err(error) => return Err(error),
        };
        if !self
            .supported_steps_in(service, tx, binding, platform, steps)
            .await?
        {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::UnsupportedCapability,
                Some(index),
            ));
        }
        Ok(TaskAdmission::new(
            TaskAdmissionState::Eligible,
            Some(index),
        ))
    }
}
