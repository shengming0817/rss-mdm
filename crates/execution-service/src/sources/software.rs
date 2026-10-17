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
pub struct SoftwareAssignment {
    pub frozen: FrozenSoftwareAction,
    active: bool,
    scope: Uuid,
    rollout: SoftwareRollout,
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
    let Action::Software { rollout, .. } = policy.definition.action else {
        return Err(Error::Malformed.into());
    };
    Ok(SoftwareExecutionPolicy {
        id,
        owner: policy.id,
        assignment: SoftwareAssignment {
            active: policy.state.is_enabled() && policy.version == id,
            frozen: *action,
            scope: policy.definition.scope,
            rollout,
            version: Some(id),
        },
    })
}
impl SoftwareAssignment {
    pub(crate) fn draft(
        scope: Uuid,
        rollout: SoftwareRollout,
        frozen: FrozenSoftwareAction,
    ) -> Self {
        Self {
            scope,
            rollout,
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
        if let Some(version) = self.version
            && !storage::readable_in(source, tx, version).await?
        {
            return Ok(None);
        }
        if !self.active {
            return Ok(None);
        }
        Ok(
            match storage::admission_in(
                source,
                tx,
                self.scope,
                rss_mdm_inventory::Channel::Agent,
                device,
            )
            .await?
            {
                crate::source_authority::ScopeAdmission::Eligible { entry } => Some(entry),
                _ => None,
            },
        )
    }
    pub fn intent(&self) -> SoftwareIntent {
        self.frozen.intent
    }
    pub fn stages(&self) -> &[rss_mdm_policy::SoftwareRolloutStage] {
        &self.rollout.stages
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
        let Some(entry) = self.eligible_in(source, tx, device).await? else {
            return Ok(None);
        };
        let stages = &self.rollout.stages;
        for (index, stage) in stages.iter().enumerate() {
            let scope = stage.scope;
            let admission =
                storage::admission_in(source, tx, scope, rss_mdm_inventory::Channel::Agent, device)
                    .await?;
            match admission {
                crate::source_authority::ScopeAdmission::Eligible { .. } => {
                    let (total, verified) = if stage.minimum_verified_percent.is_some() {
                        self.stage_progress_in(
                            source,
                            tx,
                            index.checked_sub(1).ok_or(Error::Malformed)?,
                        )
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
        service: &crate::queries::Admission,
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
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        index: usize,
    ) -> Result<(u64, u64)> {
        let counts = self.counts_in(source, tx, index, None).await?;
        Ok((counts.total, counts.verified))
    }
    /// Live target denominator with the latest per-device result in this stage.
    pub async fn stage_counts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        index: usize,
        service: &crate::queries::Admission,
    ) -> Result<StageCounts> {
        self.counts_in(&service.source, tx, index, Some(service))
            .await
    }
    async fn counts_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        index: usize,
        _service: Option<&crate::queries::Admission>,
    ) -> Result<StageCounts> {
        let Some(version) = self.version else {
            return Ok(StageCounts::default());
        };
        let Some(input) = self.stats_input_in(source, tx, index).await? else {
            return Ok(StageCounts::default());
        };
        let tenant = tx.tenant_id().to_string();
        let document = crate::checked_input(serde_json::to_value(input))?;
        // A new Run in a later stage must not revoke an already satisfied earlier-stage gate.
        // Membership revisions and binding changes still fence the whole cached reduction;
        // result changes fence it only when they affect this generation's actual members.
        let counts:Option<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT s.counts FROM mdm_commands.software_stage_stats s JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(s.tenant_id,s.version) WHERE s.tenant_id=$1::uuid AND s.version=$2 AND s.stage=$3 AND s.input-'runs'-'results'=$4::jsonb-'runs'-'results' AND (s.input->>'results')::bigint<=($4::jsonb->>'results')::bigint AND s.ready AND NOT EXISTS(SELECT 1 FROM mdm_commands.software_result_changes c JOIN mdm_commands.software_stats_members m ON(m.tenant_id,m.device)=(c.tenant_id,c.device) WHERE c.tenant_id=s.tenant_id AND c.policy=v.policy AND c.revision>(s.input->>'results')::bigint AND m.version=s.version AND m.stage=s.stage AND m.generation=s.generation)").bind(tenant).bind(version).bind(index as i32).bind(document).fetch_optional(c).await})).await?;
        match counts {
            Some(v) => crate::stored(serde_json::from_value(v)),
            None => Ok(StageCounts::default()),
        }
    }
    fn selection(&self, platform: Platform, architecture: Architecture) -> Option<Selection<'_>> {
        Some(Selection {
            resource: &self.frozen.resource,
            version: &self.frozen.version,
            digest: self.frozen.resource_digest,
            lifecycle: self.frozen.lifecycle_binding,
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
    /// Management uses the same stage, profile and current authority checks as task admission.
    pub async fn management_state_in(
        &self,
        service: &crate::queries::Admission,
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
            let state = storage::admission_in(
                &service.source,
                tx,
                scope,
                rss_mdm_inventory::Channel::Agent,
                device,
            )
            .await?;
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

mod stats;
