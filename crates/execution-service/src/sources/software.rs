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
    pub assignment: SoftwareAssignment,
}
/// Shared assignment data; a draft has no persisted version or authored Policy identity.
#[derive(Clone)]
pub struct SoftwareAssignment {
    pub(crate) retirement: Option<Uuid>,
    pub frozen: FrozenSoftwareAction,
    active: bool,
    scope: Uuid,
    rollout: Option<SoftwareRollout>,
    version: Option<Uuid>,
}
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StageCounts {
    pub(crate) scanned: u64,
    pub ready: bool,
    pub as_of: Option<i64>,
    pub total: u64,
    pub reported: u64,
    pub waiting_user: u64,
    pub unknown: u64,
    pub waiting_reboot: u64,
    pub failed: u64,
    pub verified: u64,
    pub unsupported_capability: u64,
}
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAdmissionState {
    Paused,
    MdmSoftwareDisabled,
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
    AuthorizationWithdrawn,
    PermissionWithdrawn,
    ChannelUnknown,
    ProjectionPending,
    AlreadySatisfied,
    OrganizationConflict,
    MissingNativeRights,
    MissingArchitecture,
    Eligible,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TaskAdmission {
    state: TaskAdmissionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<usize>,
}
impl TaskAdmission {
    pub(crate) fn new(state: TaskAdmissionState, stage: Option<usize>) -> Self {
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
    let rollout = match policy.definition.action {
        Action::Software { rollout, .. } => Some(rollout),
        _ => None,
    };
    Ok(SoftwareExecutionPolicy {
        id,
        owner: policy.id,
        assignment: SoftwareAssignment::persisted(
            policy.definition.scope,
            rollout,
            *action,
            id,
            policy.state.is_enabled(),
        ),
    })
}
impl SoftwareAssignment {
    pub(crate) fn pending_admission(&self, scope: Uuid, rollout: SoftwareRollout) -> Self {
        let mut value = self.clone();
        value.scope = scope;
        value.rollout = Some(rollout);
        value
    }

    pub(crate) fn persisted(
        scope: Uuid,
        rollout: Option<SoftwareRollout>,
        frozen: FrozenSoftwareAction,
        version: Uuid,
        active: bool,
    ) -> Self {
        Self {
            retirement: None,
            scope,
            rollout,
            frozen,
            version: Some(version),
            active,
        }
    }

    pub fn channel(&self) -> rss_mdm_inventory::Channel {
        match self.frozen.channel {
            rss_mdm_policy::SoftwareChannel::Agent => rss_mdm_inventory::Channel::Agent,
            rss_mdm_policy::SoftwareChannel::Mdm => rss_mdm_inventory::Channel::Mdm,
        }
    }
    pub(crate) fn draft(
        scope: Uuid,
        rollout: SoftwareRollout,
        frozen: FrozenSoftwareAction,
    ) -> Self {
        Self {
            retirement: None,
            scope,
            rollout: Some(rollout),
            frozen,
            active: true,
            version: None,
        }
    }
    async fn eligible_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<Option<i64>> {
        if !self.active {
            return Ok(None);
        }
        Ok(
            match storage::admission_in(source, tx, self.scope, self.channel(), device).await? {
                crate::source_authority::ScopeAdmission::Eligible { entry } => Some(entry),
                _ => None,
            },
        )
    }
    pub fn intent(&self) -> SoftwareIntent {
        self.frozen.intent
    }
    pub fn stages(&self) -> &[rss_mdm_policy::SoftwareRolloutStage] {
        self.rollout
            .as_ref()
            .map_or(&[], |rollout| rollout.stages.as_slice())
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
        let assignment = self.clone();
        let source = source.clone();
        let tenant = tx.tenant_id();
        let device = device.to_owned();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(assignment
                        .entry_on(source.as_ref(), c, tenant, &device, now)
                        .await)
                })
            })
            .await??)
    }
    /// Admission and first native write share the same current rollout decision.
    pub(crate) async fn entry_on(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        device: &str,
        now: i64,
    ) -> std::result::Result<Option<(usize, i64)>, Error> {
        if !self.active
            || now < self.frozen.schedule.not_before
            || now >= self.frozen.schedule.ends_at()
        {
            return Ok(None);
        }

        let crate::source_authority::ScopeAdmission::Eligible { entry } = source
            .admission_on(c, tenant, self.scope, self.channel(), device)
            .await?
        else {
            return Ok(None);
        };
        for (index, stage) in self.stages().iter().enumerate() {
            match source
                .admission_on(c, tenant, stage.scope, self.channel(), device)
                .await?
            {
                crate::source_authority::ScopeAdmission::Eligible { .. } => {
                    let counts = if stage.minimum_verified_percent.is_some() {
                        self.counts_on(
                            source,
                            c,
                            tenant,
                            index.checked_sub(1).ok_or(Error::Malformed)?,
                        )
                        .await?
                    } else {
                        StageCounts::default()
                    };
                    return Ok(stage
                        .open(now, counts.total, counts.verified)
                        .then_some((index, entry)));
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
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        binding: &crate::channels::AgentBinding,
    ) -> Result<bool> {
        if self.channel() != rss_mdm_inventory::Channel::Agent {
            return Ok(false);
        }
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
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        index: usize,
    ) -> Result<(u64, u64)> {
        let counts = self.counts_in(source, tx, index).await?;
        Ok((counts.total, counts.verified))
    }
    /// Live target denominator with the latest per-device result in this stage.
    pub async fn stage_counts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        index: usize,
        service: &crate::queries::Admission,
    ) -> Result<StageCounts> {
        self.counts_in(&service.source, tx, index).await
    }
    async fn counts_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        index: usize,
    ) -> Result<StageCounts> {
        let assignment = self.clone();
        let source = source.clone();
        let tenant = tx.tenant_id();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(assignment
                        .counts_on(source.as_ref(), c, tenant, index)
                        .await)
                })
            })
            .await??)
    }
    async fn counts_on(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        index: usize,
    ) -> std::result::Result<StageCounts, Error> {
        let Some(version) = self.version else {
            return Ok(StageCounts::default());
        };
        let Some(input) = self.stats_input_on(source, c, tenant, index).await? else {
            return Ok(StageCounts::default());
        };
        let tenant = tenant.to_string();
        let document = serde_json::to_value(input).map_err(|_| Error::Malformed)?;
        // A new Run in a later stage must not revoke an already satisfied earlier-stage gate.
        // Membership revisions and binding changes still fence the whole cached reduction;
        // result changes fence it only when they affect this generation's actual members.
        let counts:Option<serde_json::Value>=sqlx::query_scalar("SELECT s.counts FROM mdm_commands.software_stage_stats s JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(s.tenant_id,s.version) WHERE s.tenant_id=$1::uuid AND s.version=$2 AND s.stage=$3 AND s.input-'runs'-'results'=$4::jsonb-'runs'-'results' AND (s.input->>'results')::bigint<=($4::jsonb->>'results')::bigint AND s.ready AND NOT EXISTS(SELECT 1 FROM mdm_commands.software_result_changes c JOIN mdm_commands.software_stats_members m ON(m.tenant_id,m.device)=(c.tenant_id,c.device) WHERE c.tenant_id=s.tenant_id AND c.policy=v.policy AND c.revision>(s.input->>'results')::bigint AND m.version=s.version AND m.stage=s.stage AND m.generation=s.generation)").bind(tenant).bind(version).bind(index as i32).bind(document).fetch_optional(c).await.map_err(crate::database::db)?;
        match counts {
            Some(v) => serde_json::from_value(v)
                .map_err(|_| Error::Unavailable(crate::Failure::CommandStorage)),
            None => Ok(StageCounts::default()),
        }
    }
    fn selection(&self, platform: Platform, architecture: Architecture) -> Option<Selection<'_>> {
        Some(Selection {
            resource: &self.frozen.resource,
            version: &self.frozen.version,
            digest: self.frozen.resource_digest,
            variant: self.variant(platform, architecture)?,
            uninstall: matches!(self.intent(), SoftwareIntent::ExplicitUninstall),
        })
    }
    pub async fn prepared_in(
        &self,
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        platform: Platform,
        architecture: Architecture,
        context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Result<Option<Vec<rss_mdm_agent_wire::runtime::SoftwareTaskStep>>> {
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
        service: &crate::queries::Admission,
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
        service: &crate::queries::Admission,
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
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        device: &str,
        platform: Platform,
        architecture: Architecture,
        now: i64,
    ) -> Result<bool> {
        if let Some(retirement) = self.retirement {
            return Ok(
                crate::unmanage::cleanup_allowed_in(tx, retirement, device, None).await?
                    && self
                        .admitted_in(service, tx, platform, architecture)
                        .await?
                        .is_some(),
            );
        }
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
    /// An accepted Run retains its published material; rollout only selects new Runs.
    pub async fn authorized_run_in(
        &self,
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        device: &str,
        platform: Platform,
        architecture: Architecture,
        now: i64,
    ) -> Result<bool> {
        if self.retirement.is_some() {
            return self
                .authorized_in(service, tx, device, platform, architecture, now)
                .await;
        }
        Ok(self.active
            && now >= self.frozen.schedule.not_before
            && now < self.frozen.schedule.ends_at()
            && self
                .admitted_in(service, tx, platform, architecture)
                .await?
                .is_some())
    }
    /// Management uses the same stage, profile and current authority checks as task admission.
    pub async fn management_state_in(
        &self,
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<TaskAdmission> {
        if self.channel() == rss_mdm_inventory::Channel::Mdm
            && !service.software_distribution.mdm_enabled
        {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::MdmSoftwareDisabled,
                None,
            ));
        }
        if !self.active {
            return Ok(TaskAdmission::new(TaskAdmissionState::Paused, None));
        }
        if now < self.frozen.schedule.not_before || now >= self.frozen.schedule.ends_at() {
            return Ok(TaskAdmission::new(TaskAdmissionState::OutsideWindow, None));
        }
        if self
            .eligible_in(&service.source, tx, device)
            .await?
            .is_none()
        {
            return Ok(TaskAdmission::new(TaskAdmissionState::OutsideScope, None));
        }
        let mut stage_index = None;
        for (index, stage) in self.stages().iter().enumerate() {
            let scope = stage.scope;
            let state =
                storage::admission_in(&service.source, tx, scope, self.channel(), device).await?;
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
        let stage = &self.stages()[index];
        if now < stage.opens_at {
            return Ok(TaskAdmission::new(
                TaskAdmissionState::Scheduled,
                Some(index),
            ));
        }
        if stage.minimum_verified_percent.is_some() {
            let (total, verified) = self
                .stage_progress_in(
                    &service.source,
                    tx,
                    index.checked_sub(1).ok_or(Error::Malformed)?,
                )
                .await?;
            if !stage.open(now, total, verified) {
                return Ok(TaskAdmission::new(
                    TaskAdmissionState::SuccessGate,
                    Some(index),
                ));
            }
        }
        if self.channel() == rss_mdm_inventory::Channel::Mdm {
            let state = match crate::native_software::target_admission_in(tx, device).await? {
                crate::native_software::TargetAdmission::Rejected(reason) => reason,
                crate::native_software::TargetAdmission::ProjectionPending(_) => {
                    TaskAdmissionState::ProjectionPending
                }
                crate::native_software::TargetAdmission::Eligible(
                    crate::native_software::NativeTarget {
                        platform,
                        architecture,
                        ..
                    },
                ) => {
                    if self.variant(platform, architecture).is_some()
                        && self
                            .admitted_in(service, tx, platform, architecture)
                            .await?
                            .is_some()
                    {
                        TaskAdmissionState::Eligible
                    } else {
                        TaskAdmissionState::UnsupportedCapability
                    }
                }
            };
            return Ok(TaskAdmission::new(state, Some(index)));
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
                TaskAdmissionState::AuthorizationWithdrawn,
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
fn task_platform(platform: Platform) -> rss_mdm_agent_wire::runtime::TaskPlatform {
    match platform {
        Platform::Windows => rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
        Platform::Macos => rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
    }
}
fn delivery(input: &rss_mdm_policy::SoftwareDelivery) -> Delivery<'_> {
    match input {
        rss_mdm_policy::SoftwareDelivery::Direct => Delivery::Direct,
        rss_mdm_policy::SoftwareDelivery::Native { target } => Delivery::Native { target },
    }
}

mod stats;

/// Reuse the frozen software contract for an accepted device-owned removal.
/// Mutable Policy publication/Scope cannot change the accepted cleanup target.
pub async fn retirement_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    retirement: Uuid,
) -> Result<SoftwareExecutionPolicy> {
    let published = checked(reader.version_in(tx, version).await?)?.ok_or(Error::NotFound)?;
    let Frozen::Software { action } = stored(serde_json::from_value(published.frozen))? else {
        return Err(Error::Malformed.into());
    };
    let mut frozen = *action;
    frozen.intent = SoftwareIntent::ExplicitUninstall;
    let tenant = tx.tenant_id().to_string();
    let (owner,id,lifetime):(Uuid,Uuid,i32)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT policy,version,delivery_seconds FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(retirement).fetch_one(c).await
    })).await?;
    frozen.run_lifetime_seconds = lifetime.try_into().map_err(|_| Error::Malformed)?;
    Ok(SoftwareExecutionPolicy {
        owner,
        id,
        assignment: SoftwareAssignment {
            retirement: Some(retirement),
            frozen,
            active: true,
            scope: Uuid::nil(),
            rollout: None,
            version: Some(version),
        },
    })
}
