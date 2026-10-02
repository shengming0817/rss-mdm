//! Independent Agent policy for the standard MDM enrollment entry.
use super::*;
use crate::Target;
use crate::actions::storage::{TaskIssue, agent_profile_in};
use rss_mdm_agent_wire as wire;

use crate::enrollment::FrozenEnrollment;
pub struct EnrollmentPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub policy: Policy,
    pub frozen: FrozenEnrollment,
}
impl EnrollmentPolicy {
    pub async fn authorized_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        if !self.policy.enabled
            || self.policy.version != self.id
            || now < self.frozen.schedule.not_before
            || now >= self.frozen.schedule.ends_at()
            || storage::eligible_in(&service.source, tx, &self.policy, &target.device)
                .await?
                .is_none()
        {
            return Ok(false);
        }
        let Some(binding) =
            crate::channels::agent_binding_in(tx, service.agent_store.clone(), target.registration)
                .await?
        else {
            return Ok(false);
        };
        if !binding.enrollment() {
            return Ok(false);
        }
        let Some((platform, _)) = agent_profile_in(service, tx, target.registration).await? else {
            return Ok(false);
        };
        if self.frozen.entries.for_platform(platform).is_none() {
            return Ok(false);
        }
        let tenant = tx.tenant_id();
        let registration = target.registration;
        let generation = target.generation;
        let grant = self.frozen.grant.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                let granted = grant.valid(c, Permission::Enrollment, now).await;
                match granted {
                    Ok(false) => return Ok(Ok(false)),
                    Err(e) => return Ok(Err(Error::from(e))),
                    _ => {}
                }
                let state = crate::assets::channel::current_in(
                    c,
                    tenant,
                    registration,
                    generation,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await;
                Ok(state
                    .map(|state| state.as_deref() == Some("unenrolled"))
                    .map_err(Error::from))
            })
        })
        .await?
        .map_err(Into::into)
    }
    pub async fn task(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<wire::TaskPayload> {
        let (platform, architecture) = agent_profile_in(service, tx, target.registration)
            .await?
            .ok_or(Error::Forbidden)?;
        let entry = self
            .frozen
            .entries
            .for_platform(platform)
            .ok_or(Error::Unsupported)?;
        checked_input(
            wire::EnrollmentTaskSpec {
                wire_version: wire::WIRE_VERSION,
                tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                device_id: target.device.clone(),
                platform: match platform {
                    Platform::Windows => wire::TaskPlatform::Windows,
                    Platform::Macos => wire::TaskPlatform::Macos,
                },
                architecture: match architecture {
                    Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                    Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
                },
                registration_id: target.registration,
                generation: target.generation.try_into().map_err(|_| Error::Malformed)?,
                task_id: issue.run,
                attempt_id: issue.attempt,
                permit: issue.permit,
                expires_at: issue.expiry,
                organization: self.frozen.organization,
                entry,
            }
            .try_into(),
        )
    }
}
