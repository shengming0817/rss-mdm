//! Read-only software assignment bridge from authored Policy to the shared Agent Run.
use super::*;
use crate::action_contract::FrozenSoftwareAction;
use rss_mdm_policy::{SoftwareIntent, SoftwareRollout, SoftwareTarget};
use rss_mdm_software_service::{
    catalog::FrozenSoftware,
    preparation::{Delivery, Selection, Target},
};

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
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
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
        let Some(entry) = storage::eligible_in(source, tx, &self.policy, device).await? else {
            return Ok(None);
        };
        let stages = &self.rollout()?.stages;
        for (index, stage) in stages.iter().enumerate() {
            let scope = stage.scope;
            let admission = storage::admission_in(source, tx, scope, device).await?;
            match admission {
                crate::source_authority::ScopeAdmission::Eligible { .. } => {
                    let (total, verified) = if stage.minimum_verified_percent.is_some() {
                        self.stage_progress_in(tx, index.checked_sub(1).ok_or(Error::Malformed)?)
                            .await?
                    } else {
                        (0, 0)
                    };
                    return Ok(stage.open(now, total, verified).then_some((index, entry)));
                }
                crate::source_authority::ScopeAdmission::Pending => return Ok(None),
                crate::source_authority::ScopeAdmission::Excluded => (),
            }
        }
        Ok(None)
    }
    /// One support decision covers the complete exact dependency closure.
    pub async fn supported_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        binding: &crate::channels::AgentBinding,
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
        match self
            .prepared_in(
                service,
                tx,
                platform,
                architecture,
                &binding.execution_context,
            )
            .await
        {
            Ok(Some(steps)) => Ok(steps.iter().all(|step| {
                step.action
                    .required_profile(task_platform(platform))
                    .is_some_and(|required| binding.capabilities.contains(&required))
            })),
            Ok(None) | Err(crate::transaction::Fault::Request(Error::Unsupported)) => Ok(false),
            Err(e) => Err(e),
        }
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
        service: &crate::ExecutionService,
    ) -> Result<StageCounts> {
        self.counts_in(tx, index, Some(service)).await
    }
    async fn counts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        index: usize,
        service: Option<&crate::ExecutionService>,
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
        let now = crate::storage::now(tx).await?;
        let include_capabilities = service.is_some();
        let (total, reported, waiting_user, unknown, waiting_reboot, failed, verified, targets): (i64, i64, i64, i64, i64, i64, i64, Option<Vec<String>>) = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("WITH targets AS (SELECT r.device FROM mdm_planning.scopes s JOIN mdm_planning.scope_results r ON (r.tenant_id,r.run)=(s.tenant_id,s.resolution) JOIN mdm_planning.scopes root ON root.tenant_id=s.tenant_id AND root.id=$6::uuid AND NOT root.deleted JOIN mdm_planning.scope_results rr ON (rr.tenant_id,rr.run,rr.device)=(root.tenant_id,root.resolution,r.device) AND rr.matched WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND NOT s.deleted AND r.matched AND NOT EXISTS (SELECT 1 FROM mdm_planning.scopes p JOIN mdm_planning.scope_results x ON (x.tenant_id,x.run)=(p.tenant_id,p.resolution) WHERE p.tenant_id=s.tenant_id AND p.id=ANY($3::uuid[]) AND x.device=r.device AND x.matched)) SELECT count(*),count(*) FILTER(WHERE latest.result IS NOT NULL),count(*) FILTER(WHERE $7::boolean AND latest.state->>'execution'='not_started' AND latest.state->>'cancellation'='none' AND latest.state->'delivery'->>'kind' IN ('claimed','received') AND (latest.state->'delivery'->>'leaseUntil')::bigint>$8),count(*) FILTER(WHERE latest.result->>'effect'='unknown' OR latest.state->>'execution'='unknown'),count(*) FILTER(WHERE latest.result->>'effect'='waiting_reboot'),count(*) FILTER(WHERE latest.result->>'effect'='failed'),count(*) FILTER(WHERE latest.result->>'effect'='verified'),array_agg(targets.device) FILTER(WHERE $9::boolean) FROM targets LEFT JOIN LATERAL (SELECT a.state,a.result FROM mdm_commands.action_runs a WHERE a.tenant_id=$1::uuid AND a.policy_version=$4::uuid AND a.device=targets.device AND a.occurrence LIKE $5 ORDER BY a.created_at DESC,a.id DESC LIMIT 1) latest ON true")
                .bind(tenant).bind(scope).bind(earlier).bind(version).bind(prefix).bind(root).bind(optional).bind(now).bind(include_capabilities).fetch_one(c).await
        })).await?;
        let unsupported = if let Some(service) = service {
            let mut supported = std::collections::BTreeSet::new();
            for devices in targets.unwrap_or_default().chunks(128) {
                for target in crate::channels::agent_targets_in(
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
    fn selection(&self, platform: Platform, architecture: Architecture) -> Option<Selection<'_>> {
        Some(Selection {
            resource: &self.frozen.resource,
            version: &self.frozen.version,
            digest: self.frozen.resource_digest,
            admission: self.frozen.admission_operation,
            variant: self.variant(platform, architecture)?,
            uninstall: matches!(self.intent(), SoftwareIntent::ExplicitUninstall),
        })
    }
    pub async fn prepared_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        platform: Platform,
        architecture: Architecture,
        context: &rss_mdm_agent_wire::SoftwareExecutionContext,
    ) -> Result<Option<Vec<rss_mdm_agent_wire::SoftwareTaskStep>>> {
        let Some(selection) = self.selection(platform, architecture) else {
            return Ok(None);
        };
        Ok(service
            .software
            .prepare_in(
                tx,
                &selection,
                target(platform, architecture),
                &delivery(&self.frozen.delivery),
                context,
            )
            .await?)
    }
    pub async fn artifact_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        platform: Platform,
        architecture: Architecture,
        index: usize,
        key: &str,
    ) -> Result<resource::Artifact> {
        let selection = self
            .selection(platform, architecture)
            .ok_or(Error::Forbidden)?;
        service
            .software
            .artifact_in(tx, &selection, target(platform, architecture), index, key)
            .await
            .map_err(|e| match e {
                rss_mdm_software_service::catalog::Error::Missing => Error::NotFound.into(),
                other => crate::transaction::Fault::from(other),
            })?
            .ok_or_else(|| Error::Forbidden.into())
    }
    pub async fn admitted_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<Option<FrozenSoftware>> {
        let Some(selection) = self.selection(platform, architecture) else {
            return Ok(None);
        };
        Ok(service
            .software
            .recheck_in(tx, &selection, target(platform, architecture))
            .await?)
    }
    pub async fn authorized_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        device: &str,
        platform: Platform,
        architecture: Architecture,
        now: i64,
    ) -> Result<bool> {
        if self
            .entry_in(&service.source, tx, device, now)
            .await?
            .is_none()
        {
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
        service: &crate::ExecutionService,
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
        if storage::eligible_in(&service.source, tx, &self.policy, device)
            .await?
            .is_none()
        {
            return Ok(TaskAdmission::new(TaskAdmissionState::OutsideScope, None));
        }
        let mut stage_index = None;
        for (index, stage) in self.stages()?.iter().enumerate() {
            let scope = stage.scope;
            let state = storage::admission_in(&service.source, tx, scope, device).await?;
            match state {
                crate::source_authority::ScopeAdmission::Eligible { .. } => {
                    stage_index = Some(index);
                    break;
                }
                crate::source_authority::ScopeAdmission::Pending => {
                    return Ok(TaskAdmission::new(
                        TaskAdmissionState::ScopePending,
                        Some(index),
                    ));
                }
                crate::source_authority::ScopeAdmission::Excluded => (),
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
        let registrations = crate::channels::agent_targets_in(
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
        if !self.supported_in(service, tx, binding).await? {
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

pub(crate) fn target(platform: Platform, architecture: Architecture) -> Target {
    Target {
        platform: match platform {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        architecture: match architecture {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
    }
}
fn task_platform(platform: Platform) -> rss_mdm_agent_wire::TaskPlatform {
    match platform {
        Platform::Windows => rss_mdm_agent_wire::TaskPlatform::Windows,
        Platform::Macos => rss_mdm_agent_wire::TaskPlatform::Macos,
    }
}
fn delivery(input: &rss_mdm_policy::SoftwareDelivery) -> Delivery<'_> {
    match input {
        rss_mdm_policy::SoftwareDelivery::Direct => Delivery::Direct,
        rss_mdm_policy::SoftwareDelivery::Native { source, ring } => Delivery::Native {
            source,
            ring: match ring {
                rss_mdm_policy::SoftwareDeliveryRing::Test => rss_mdm_software_release::Ring::Test,
                rss_mdm_policy::SoftwareDeliveryRing::Pilot => {
                    rss_mdm_software_release::Ring::Pilot
                }
                rss_mdm_policy::SoftwareDeliveryRing::Production => {
                    rss_mdm_software_release::Ring::Production
                }
            },
        },
    }
}
