//! Registration consumes immutable Enrollment input and current Policy/Scope qualification.
use super::*;
use crate::participants::scope;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_inventory::Channel;
use rss_mdm_policy::{Frequency, Policy};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Published {
    Enrollment { action: Box<FrozenEnrollment> },
}
pub struct EnrollmentPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub policy: Policy,
    pub frozen: FrozenEnrollment,
    pub active: bool,
    pub frequency: Frequency,
}
pub async fn read_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<EnrollmentPolicy> {
    service.validate_in(tx)?;
    let version = transaction::checked(service.policy_reader.version_in(tx, id).await?)?
        .ok_or(Error::NotFound)?;
    let policy = transaction::checked(service.policy_reader.locked_in(tx, version.policy).await?)?
        .ok_or(Error::NotFound)?;
    let Published::Enrollment { action } = stored(serde_json::from_value(version.frozen))?;
    Ok(EnrollmentPolicy {
        id,
        owner: policy.id,
        active: policy.state.is_enabled(),
        policy,
        frozen: *action,
        frequency: Frequency::OncePerVersion,
    })
}
impl EnrollmentPolicy {
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
        let profile = service.profile();

        if !self.active
            || now < self.frozen.schedule.not_before
            || now >= self.frozen.schedule.ends_at()
        {
            return Ok(None);
        }
        let tenant = tx.tenant_id();
        let device = device.to_owned();
        let source = service.source.clone();
        let scope = self.policy.definition.scope;
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(async {
                    if !crate::lifecycle::work_allowed_in(profile, c, &tenant.to_string(), &device)
                        .await?
                    {
                        return Ok(None);
                    }
                    Ok(
                        match source
                            .admission_on(c, tenant, scope, Channel::Agent, &device)
                            .await?
                        {
                            scope::ScopeAdmission::Eligible { entry } => Some(entry),
                            _ => None,
                        },
                    )
                }
                .await)
            })
        })
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
        let profile = service.profile();

        Ok(self.active
            && eligibility::require_in(profile, service, tx, target, &self.frozen).await?)
    }
    pub async fn authorized_run_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &runs::Run,
    ) -> Result<bool> {
        let profile = service.profile();

        if run.policy_version != self.id {
            return Err(Error::Invariant.into());
        }
        if run.state.started_at.is_none() {
            let now = storage::now(tx).await?;
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
            if policy_version != self.id || invocation.pending_scope.is_some() {
                return Ok(false);
            }
        }
        if run.state.started_at.is_some() {
            Ok(self.active
                && eligibility::capable_in(profile, service, tx, &run.target, &self.frozen).await?)
        } else {
            self.run_admission_in(service, tx, &run.target).await
        }
    }
    pub async fn task(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &runs::Run,
        attempt: Uuid,
        permit: wire::TaskPermit,
        expiry: i64,
    ) -> Result<wire::TaskPayload> {
        let profile = service.profile();

        let (platform, architecture) =
            agent_facts::profile_in(profile, service, tx, run.target.registration)
                .await?
                .ok_or(Error::Forbidden)?;
        let entry = self
            .frozen
            .entries
            .for_platform(platform)
            .ok_or(Error::Forbidden)?;
        let authorization = run
            .invocation
            .as_ref()
            .map(|v| v.authorization.clone())
            .unwrap_or(wire::TaskAuthorization::Policy {
                policy_id: self.owner,
                policy_version: self.id,
            });
        checked_input(
            wire::EnrollmentTaskSpec {
                wire_version: wire::WIRE_VERSION,
                tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                device_id: run.target.device.clone(),
                platform: match platform {
                    rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                    rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
                },
                architecture: match architecture {
                    rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                    rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
                },
                registration_id: run.target.registration,
                generation: run
                    .target
                    .generation
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
                task_id: run.id,
                attempt_id: attempt,
                permit,
                expires_at: expiry,
                organization: self.frozen.organization,
                authorization,
                entry,
            }
            .try_into(),
        )
    }
}
pub async fn current_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    transaction::checked(reader.locked_in(tx, id).await?)
}
pub async fn admission_in(
    source: &std::sync::Arc<dyn scope::Sources>,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    channel: Channel,
    device: &str,
) -> Result<scope::ScopeAdmission> {
    let source = source.clone();
    let tenant = tx.tenant_id();
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
