//! Per-account desired effects reuse signed action runs, not a second queue.
pub(crate) mod provisioning;
use crate::{
    actions::storage::{self as runs, Source, TaskIssue},
    *,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_registration_service::{
    Error as AccessError,
    device_access::{self as access, Admission},
};
use sqlx::Row;

impl Admission for ExecutionService {
    fn policies<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        device: &'a str,
        after: Option<Uuid>,
        limit: u16,
    ) -> rss_mdm_registration_service::agent::Pending<
        'a,
        (Vec<wire::AccessPolicyOption>, Option<Uuid>),
    > {
        Box::pin(async move {
            if tenant.to_string() != self.tenant.to_string() {
                return Err(AccessError::Forbidden);
            }
            let mut ids: Vec<Uuid> = sqlx::query_scalar("SELECT p.id FROM mdm_policy.policies p JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1 AND p.state='enabled' AND v.action_kind='device_access' AND ($2::uuid IS NULL OR p.id>$2) ORDER BY p.id LIMIT $3")
                .bind(tenant).bind(after).bind(i64::from(limit)+1).fetch_all(&mut *c).await.map_err(|_| AccessError::Storage)?;
            let more = ids.len() > usize::from(limit);
            ids.truncate(usize::from(limit));
            let after = if more { ids.last().copied() } else { None };
            let mut values = Vec::new();
            for id in ids {
                match self.policy(c, tenant, device, id).await {
                    Ok(p) if p.configuration.enabled && p.configuration.self_enrollment => values
                        .push(wire::AccessPolicyOption {
                            policy: p.policy,
                            version: p.version,
                            configuration: p.configuration,
                        }),
                    Ok(_) | Err(AccessError::Forbidden) => (),
                    Err(e) => return Err(e),
                }
            }
            Ok((values, after))
        })
    }

    fn policy<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        device: &'a str,
        policy: Uuid,
    ) -> rss_mdm_registration_service::agent::Pending<'a, access::PolicySelection> {
        Box::pin(policy_on(
            self.source.clone(),
            self.tenant,
            c,
            tenant,
            device,
            policy,
        ))
    }

    fn binding_session<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        binding: &'a access::Binding,
    ) -> rss_mdm_registration_service::agent::Pending<'a, wire::AccessLocalSession> {
        Box::pin(async move {
            if tenant.to_string() != self.tenant.to_string() || binding.tenant != tenant {
                return Err(AccessError::Forbidden);
            }
            let native = self
                .agent_store
                .binding(c, self.tenant.to_string(), binding.registration)
                .await
                .map_err(|_| AccessError::Storage)?
                .ok_or(AccessError::Forbidden)?;
            let session = native_local_session(native)?;
            if binding.account.as_ref() != Some(&session.account) {
                return Err(AccessError::Forbidden);
            }
            Ok(session)
        })
    }

    fn local_session<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        device: &'a rss_mdm_registration_service::DevicePrincipal,
    ) -> rss_mdm_registration_service::agent::Pending<'a, wire::AccessLocalSession> {
        Box::pin(async move {
            if device.tenant() != self.tenant {
                return Err(AccessError::Forbidden);
            }
            let binding = self
                .agent_store
                .binding(c, self.tenant.to_string(), device.registration())
                .await
                .map_err(|_| AccessError::Storage)?
                .ok_or(AccessError::Forbidden)?;
            native_local_session(binding)
        })
    }
}

fn native_local_session(
    binding: crate::channels::AgentBinding,
) -> std::result::Result<wire::AccessLocalSession, AccessError> {
    if !binding
        .capabilities
        .contains(&wire::Capability::DeviceAccessV1)
    {
        return Err(AccessError::Forbidden);
    }
    let user = binding
        .execution_context
        .interactive_user
        .ok_or(AccessError::Forbidden)?;
    let account = match binding.platform.as_str() {
        "windows" if user.generated_uid.is_none() => wire::AccessAccount::Windows {
            sid: user.identity,
            authority: user.windows_authority.ok_or(AccessError::Forbidden)?,
        },
        "macos" => wire::AccessAccount::Macos {
            generated_uid: Uuid::parse_str(
                user.generated_uid
                    .as_deref()
                    .ok_or(AccessError::Forbidden)?,
            )
            .map_err(|_| AccessError::Forbidden)?,
        },
        _ => return Err(AccessError::Forbidden),
    };
    let value = wire::AccessLocalSession {
        account,
        session_id: user.session_id,
    };
    value.validate().map_err(|_| AccessError::Forbidden)?;
    Ok(value)
}

impl ExecutionService {
    /// Current native runtime baseline for PSSO 1.0 Password and hardening policies.
    /// App/profile installation remains an independent Apple qualification.
    pub async fn platform_sso_supported_on(
        &self,
        c: &mut sqlx::PgConnection,
        registration: Uuid,
    ) -> std::result::Result<bool, AccessError> {
        let Some(binding) = self
            .agent_store
            .binding(c, self.tenant.to_string(), registration)
            .await
            .map_err(|_| AccessError::Storage)?
        else {
            return Ok(false);
        };
        Ok(binding.platform == "macos"
            && binding.architecture == "aarch64"
            && binding
                .capabilities
                .contains(&wire::Capability::DeviceAccessV1)
            && binding.execution_context.os_version >= [26, 4, 0, 0]
            && binding.execution_context.user_helper
            && binding.execution_context.system_broker)
    }
    /// Bootstrap may precede the native integration's Applied receipt. It still requires an
    /// authorized current binding and the exact native local account; never admits a login.
    pub async fn registration_access_binding_on(
        &self,
        c: &mut sqlx::PgConnection,
        device: &rss_mdm_registration_service::DevicePrincipal,
        id: Uuid,
        generation: i64,
    ) -> std::result::Result<access::Binding, AccessError> {
        if device.tenant() != self.tenant {
            return Err(AccessError::Forbidden);
        }
        let tenant = Uuid::parse_str(&self.tenant.to_string()).map_err(|_| AccessError::Corrupt)?;
        let binding = access::storage::locked_in(c, tenant, id).await?;
        if binding.generation != generation
            || binding.state == access::State::Revoked
            || binding.device != device.device()
            || binding.registration != device.registration()
            || binding.registration_generation != device.generation()
            || !binding.configuration.enabled
            || binding.account.is_none()
        {
            return Err(AccessError::Forbidden);
        }
        let local = self.local_session(c, device).await?;
        if binding.account.as_ref() != Some(&local.account) {
            return Err(AccessError::Forbidden);
        }
        let selected = self
            .policy(c, tenant, &binding.device, binding.policy)
            .await?;
        if selected.version != binding.policy_version || !selected.configuration.enabled {
            return Err(AccessError::Forbidden);
        }
        Ok(binding)
    }
    /// Product seam for a platform verifier: keep registration, binding and current Policy/Scope
    /// locks on the Identity caller's connection. Identity still verifies the account/member.
    pub async fn active_access_binding_on(
        &self,
        c: &mut sqlx::PgConnection,
        id: Uuid,
        generation: i64,
    ) -> std::result::Result<access::Binding, AccessError> {
        let tenant = Uuid::parse_str(&self.tenant.to_string()).map_err(|_| AccessError::Corrupt)?;
        let binding = access::storage::require_active_in(c, tenant, id, generation).await?;
        let selected = self
            .policy(c, tenant, &binding.device, binding.policy)
            .await?;
        if selected.version != binding.policy_version || !selected.configuration.enabled {
            return Err(AccessError::Forbidden);
        }
        let selection: serde_json::Value = sqlx::query_scalar(
            "SELECT mdm_commands.active_access_binding($1,$2,floor(extract(epoch FROM clock_timestamp()))::bigint)",
        )
        .bind(id)
        .bind(generation)
        .fetch_one(c)
        .await
        .map_err(|_| AccessError::Storage)?;
        match selection["state"].as_str() {
            Some("eligible") => {
                let current: access::Binding = serde_json::from_value(selection["binding"].clone())
                    .map_err(|_| AccessError::Corrupt)?;
                current.validate().map_err(|_| AccessError::Corrupt)?;
                Ok(current)
            }
            Some("pending") => Err(AccessError::Storage),
            Some("excluded") => Err(AccessError::Forbidden),
            _ => Err(AccessError::Corrupt),
        }
    }
    pub async fn record_access_recovery_use(
        &self,
        device: &crate::device::DevicePrincipal,
        input: &wire::AccessRecoveryUse,
        audit: &RequestAudit,
    ) -> std::result::Result<(), Error> {
        if device.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        input.validate().map_err(|_| Error::Malformed)?;
        audit.operation(
            input.operation_id,
            "device_access_recovery_use",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device.device());
        transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, device, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, device, input, audit) = *ctx;

                    crate::actions::native_recovery::lock_device(tx, device.device()).await?;
                    crate::transaction::prepare_audit_in(&service.audit_store, tx, audit, &[])
                        .await?;
                    let p = device.clone();
                    let value = input.clone();
                    let replay = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(
                                    rss_mdm_recovery_credentials::storage::rss_use_in(
                                        c, &p, &value,
                                    )
                                    .await,
                                )
                            })
                        })
                        .await?
                        .map_err(crate::recovery_credentials::error)?;
                    let bytes = checked_input(serde_json::to_vec(&(device.registration(), input)))?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!(
                            "rss-login-use:{}:{}",
                            device.registration(),
                            input.operation_id
                        ),
                        &bytes,
                        200,
                        "success",
                        None,
                    )?;
                    service.audit_store.append_in(tx, &fact, replay).await?;
                    Ok(())
                })
            },
        )
        .await
    }
}

pub(crate) async fn policy_on(
    source: std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    scope: rss_request_context::TenantId,
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    device: &str,
    policy: Uuid,
) -> std::result::Result<access::PolicySelection, AccessError> {
    if tenant.to_string() != scope.to_string() {
        return Err(AccessError::Forbidden);
    }
    sqlx::query("SELECT mdm_planning.policy_lock($1)")
        .bind(policy)
        .execute(&mut *c)
        .await
        .map_err(|_| AccessError::Storage)?;
    let row=sqlx::query("SELECT p.current_version,p.definition,v.frozen FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1 AND p.id=$2 AND p.state='enabled' AND v.action_kind='device_access'")
                .bind(tenant).bind(policy).fetch_optional(&mut *c).await.map_err(|_|AccessError::Storage)?.ok_or(AccessError::Forbidden)?;
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        row.try_get("definition")
            .map_err(|_| AccessError::Corrupt)?,
    )
    .map_err(|_| AccessError::Corrupt)?;
    let frozen: crate::frozen::Frozen =
        serde_json::from_value(row.try_get("frozen").map_err(|_| AccessError::Corrupt)?)
            .map_err(|_| AccessError::Corrupt)?;
    let crate::frozen::Frozen::DeviceAccess { .. } = frozen else {
        return Err(AccessError::Forbidden);
    };
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| AccessError::Storage)?;
    match source
        .admission_on(
            c,
            scope,
            definition.scope,
            crate::source_authority::Channel::Agent,
            device,
        )
        .await
        .map_err(|_| AccessError::Storage)?
    {
        crate::source_authority::ScopeAdmission::Eligible { .. } => {}
        crate::source_authority::ScopeAdmission::Excluded => return Err(AccessError::Forbidden),
        crate::source_authority::ScopeAdmission::Pending => return Err(AccessError::Storage),
    }
    // Locked and read-only consumers resolve the same current qualification.
    let selection: serde_json::Value =
        sqlx::query_scalar("SELECT mdm_commands.access_policy($1,$2,$3)")
            .bind(policy)
            .bind(device)
            .bind(now)
            .fetch_one(c)
            .await
            .map_err(|_| AccessError::Storage)?;
    match selection["state"].as_str() {
        Some("pending") => Err(AccessError::Storage),
        Some("excluded") => Err(AccessError::Forbidden),
        Some("eligible") => Ok(access::PolicySelection {
            policy,
            version: serde_json::from_value(selection["version"].clone())
                .map_err(|_| AccessError::Corrupt)?,
            configuration: serde_json::from_value(selection["configuration"].clone())
                .map_err(|_| AccessError::Corrupt)?,
        }),
        _ => Err(AccessError::Corrupt),
    }
}

pub struct Plan {
    pub owner: Uuid,
    pub delivery: Uuid,
    pub binding: access::Binding,
}
/// Capability eligibility is shared by preview, Offer and Start/recovery admission.
pub(crate) fn capable(
    binding: &crate::channels::AgentBinding,
    configuration: &wire::AccessWindowsConfiguration,
) -> bool {
    binding
        .capabilities
        .contains(&wire::Capability::DeviceAccessV1)
        && matches!(
            (binding.platform.as_str(), binding.architecture.as_str()),
            ("windows", "x86_64") | ("macos", "aarch64")
        )
        && (binding.platform != "windows"
            || (!matches!(configuration, wire::AccessWindowsConfiguration::Disabled)
                && (!matches!(configuration, wire::AccessWindowsConfiguration::Whfb)
                    || binding
                        .capabilities
                        .contains(&wire::Capability::DeviceAccessWhfbV1))))
}
impl Plan {
    pub async fn allowed_in(
        &self,
        service: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        if self.binding.device != target.device
            || self.binding.registration != target.registration
            || self.binding.registration_generation != target.generation
        {
            return Ok(false);
        }
        let native =
            crate::channels::agent_binding_in(tx, service.agent_store.clone(), target.registration)
                .await?;
        if !native
            .as_ref()
            .is_some_and(|b| capable(b, &self.binding.configuration.windows))
        {
            return Ok(false);
        }
        let expected = self.binding.clone();
        let tenant = self.binding.tenant;
        tx.with_connection(move |c| {
            Box::pin(async move {
                let current = match access::storage::locked_in(c, tenant, expected.id).await {
                    Ok(b) => b,
                    Err(AccessError::Forbidden | AccessError::Conflict | AccessError::NotFound) => {
                        return Ok(Ok(false));
                    }
                    Err(_) => {
                        return Err(sqlx::Error::Protocol(
                            "device access authority unavailable".into(),
                        ));
                    }
                };
                if current
                    .definition_digest()
                    .map_err(|_| sqlx::Error::Protocol("device access definition".into()))?
                    != expected
                        .definition_digest()
                        .map_err(|_| sqlx::Error::Protocol("device access definition".into()))?
                {
                    return Ok(Ok(false));
                }
                // An already accepted unlink is deliverable after scope exit; it cannot grant access.
                if current.state == access::State::Revoked {
                    return Ok(Ok(true));
                }
                let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies WHERE tenant_id=$1 AND id=$2 AND state='enabled')")
                    .bind(tenant).bind(current.policy).fetch_one(c).await?;
                Ok(Ok(enabled))
            })
        })
        .await?
    }
    pub async fn task(
        &self,
        service: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<wire::TaskPayload> {
        if issue.run != self.delivery || !self.allowed_in(service, tx, target).await? {
            return Err(Error::Forbidden.into());
        }
        let (_, architecture) = runs::agent_profile_in(service, tx, target.registration)
            .await?
            .ok_or(Error::Forbidden)?;
        let run = runs::load_run(tx, issue.run).await?;
        let b = &self.binding;
        let action = if b.state == access::State::Revoked {
            wire::AccessAction::Unbind {
                disposition: b.account_disposition,
                account: b.account.clone().ok_or(Error::Conflict)?,
            }
        } else {
            match &b.intent {
                access::AccountIntent::Existing { account } => wire::AccessAction::Apply {
                    account: account.clone(),
                    configuration: b.configuration.clone(),
                },
                access::AccountIntent::Create { platform: _, name } => match &b.account {
                    Some(account) => wire::AccessAction::Apply {
                        account: account.clone(),
                        configuration: b.configuration.clone(),
                    },
                    None => wire::AccessAction::Create {
                        name: name.clone(),
                        configuration: b.configuration.clone(),
                    },
                },
            }
        };
        let spec = wire::AccessTaskSpec {
            wire_version: wire::WIRE_VERSION,
            tenant_id: b.tenant,
            device_id: b.device.clone(),
            registration_id: b.registration,
            generation: b.registration_generation as u64,
            platform: b.intent.platform(),
            architecture: match architecture {
                rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
            },
            task_id: issue.run,
            attempt_id: issue.attempt,
            permit: issue.permit,
            expires_at: issue.expiry,
            deadline: run.deadline,
            binding_id: b.id,
            instance_id: b.person.instance,
            principal_id: b.person.principal,
            binding_generation: b.generation,
            factor_generation: b.factor_generation,
            revision: b.revision,
            definition_digest: b.definition_digest().map_err(Error::from)?,
            action,
            windows: provisioning::plan(service, tx, b).await?,
            authorization: wire::TaskAuthorization::Policy {
                policy_id: b.policy,
                policy_version: b.policy_version,
            },
        };
        checked_input(spec.validate())?;
        Ok(wire::TaskPayload::DeviceAccess(Box::new(spec)))
    }
}

pub async fn load(tx: &mut PgTransaction<'_>, delivery: Uuid) -> Result<Plan> {
    let tenant = tx.tenant_id().to_string();
    let value:serde_json::Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT access_binding FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 AND source_kind='device_access'").bind(tenant).bind(delivery).fetch_one(c).await})).await?;
    let binding: access::Binding = stored(serde_json::from_value(value))?;
    stored(binding.validate())?;
    Ok(Plan {
        owner: binding.policy,
        delivery,
        binding,
    })
}

/// Reconcile bounded account revisions when the authenticated Agent polls existing tasks.
pub(crate) async fn prepare_reconciliation_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    device: &crate::device::DevicePrincipal,
) -> Result<PreparedReconciliation> {
    // Retirement needs this poll to carry its accepted cleanup/unmanage work.
    // Keep the existing lifecycle lock and propagate storage faults unchanged.
    let tenant_name = tx.tenant_id().to_string();
    let device_name = device.device().to_owned();
    let work_allowed = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                    c,
                    &tenant_name,
                    &device_name,
                )
                .await)
            })
        })
        .await??;
    if !work_allowed {
        return Ok(PreparedReconciliation {
            bindings: Vec::new(),
            partitions: Vec::new(),
        });
    }
    let tenant = stored(Uuid::parse_str(&tx.tenant_id().to_string()))?;
    let name = device.device().to_owned();
    let registration = device.registration();
    let documents:Vec<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move{
        sqlx::query_scalar("SELECT document FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND device=$2 AND registration=$3 ORDER BY id LIMIT 128").bind(tenant).bind(name).bind(registration).fetch_all(c).await
    })).await?;
    let mut bindings = Vec::new();
    let mut partitions = Vec::new();
    for document in documents {
        let source = service.source.clone();
        let scope = service.tenant;
        let previous: access::Binding = stored(serde_json::from_value(document))?;
        let binding = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let binding = access::storage::locked_in(c, tenant, previous.id)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("access binding unavailable".into()))?;
                    if binding.state != access::State::Revoked {
                        match policy_on(source, scope, c, tenant, &binding.device, binding.policy)
                            .await
                        {
                            Ok(_) | Err(AccessError::Forbidden) => (),
                            Err(_) => {
                                return Err(sqlx::Error::Protocol(
                                    "access policy unavailable".into(),
                                ));
                            }
                        }
                    }
                    Ok(binding)
                })
            })
            .await?;
        let delivery = Uuid::new_v4();
        partitions.push(rss_mdm_audit_integration::source_partition(
            tx.tenant_id(),
            "mdm",
            &delivery.to_string(),
        )?);
        bindings.push((binding, delivery));
    }
    Ok(PreparedReconciliation {
        bindings,
        partitions,
    })
}
pub(crate) struct PreparedReconciliation {
    bindings: Vec<(access::Binding, Uuid)>,
    pub(crate) partitions: Vec<rss_transactional_messaging::message::PartitionIdentity>,
}
/// Apply exactly the bounded bindings prepared before the caller's partition declaration.
pub(crate) async fn reconcile_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    prepared: PreparedReconciliation,
    now: i64,
    audit: &RequestAudit,
) -> Result<()> {
    let tenant = stored(Uuid::parse_str(&tx.tenant_id().to_string()))?;
    for (previous, delivery) in prepared.bindings {
        let source = service.source.clone();
        let scope = service.tenant;
        let id = previous.id;
        let previous_revision = previous.revision;
        let binding = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let mut b = access::storage::locked_in(c, tenant, previous.id)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("access binding unavailable".into()))?;
                    let expected = b.revision;
                    if b.state != access::State::Revoked {
                        match policy_on(source, scope, c, tenant, &b.device, b.policy).await {
                            Ok(p) => {
                                if b.intent.platform() == wire::TaskPlatform::Windows
                                    && std::mem::discriminant(&p.configuration.windows)
                                        != std::mem::discriminant(&b.configuration.windows)
                                {
                                    b.generation =
                                        b.generation.checked_add(1).ok_or_else(|| {
                                            sqlx::Error::Protocol(
                                                "access generation exhausted".into(),
                                            )
                                        })?;
                                    b.revision = b.revision.checked_add(1).ok_or_else(|| {
                                        sqlx::Error::Protocol("access revision exhausted".into())
                                    })?;
                                    b.state = access::State::Revoked;
                                    b.configuration.enabled = false;
                                } else if p.version != b.policy_version
                                    || p.configuration != b.configuration
                                {
                                    b.revision = b.revision.checked_add(1).ok_or_else(|| {
                                        sqlx::Error::Protocol("access revision exhausted".into())
                                    })?;
                                    b.policy_version = p.version;
                                    b.configuration = p.configuration;
                                    b.state = access::State::Pending;
                                }
                            }
                            Err(AccessError::Forbidden) => {
                                b.revision = b.revision.checked_add(1).ok_or_else(|| {
                                    sqlx::Error::Protocol("access revision exhausted".into())
                                })?;
                                b.generation = b.generation.checked_add(1).ok_or_else(|| {
                                    sqlx::Error::Protocol("access generation exhausted".into())
                                })?;
                                b.state = access::State::Revoked;
                                b.configuration.enabled = false;
                            }
                            Err(_) => {
                                return Err(sqlx::Error::Protocol(
                                    "access policy unavailable".into(),
                                ));
                            }
                        }
                    }
                    if b.revision != expected {
                        access::storage::save_in(c, &b, expected)
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("access binding write failed".into())
                            })?;
                    }
                    Ok(b)
                })
            })
            .await?;
        if binding.revision != previous_revision {
            let bytes = checked_input(serde_json::to_vec(&(
                binding.id,
                binding.generation,
                binding.revision,
                binding.policy_version,
                binding.state,
            )))?;
            let fact = rss_mdm_audit_integration::Fact::business(
                audit,
                &format!("device-access:{id}:revision:{}", binding.revision),
                &bytes,
                200,
                "success",
                None,
            )?;
            service.audit_store.append_in(tx, &fact, false).await?;
        }
        if binding.applied_revision == Some(binding.revision)
            || (binding.state == access::State::Revoked && binding.account.is_none())
        {
            continue;
        }
        let target = Target {
            device: binding.device.clone(),
            registration: binding.registration,
            generation: binding.registration_generation,
        };
        let t = tenant;
        let outstanding:bool=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1 AND source_kind='device_access' AND access_binding->>'id'=$2 AND state->>'execution' IN ('running','unknown','waiting_reboot'))").bind(t).bind(id.to_string()).fetch_one(c).await
        })).await?;
        if outstanding {
            continue;
        }
        // Only a delivery that never obtained Start can be replaced after expiry.
        // Started and uncertain attempts remain the authoritative recovery coordinate.
        let revision = binding.revision;
        let renewal: Option<i64> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT CASE WHEN count(*)=count(*) FILTER(WHERE deadline<=$4 AND state->>'execution'='not_started' AND state->>'startedAt' IS NULL) THEN count(*) ELSE NULL END FROM mdm_commands.action_runs WHERE tenant_id=$1 AND source_kind='device_access' AND access_binding->>'id'=$2 AND (access_binding->>'revision')::bigint=$3")
                .bind(tenant).bind(id.to_string()).bind(revision).bind(now).fetch_one(c).await
        })).await?;
        let Some(renewal) = renewal else {
            continue;
        };
        let occurrence = format!(
            "device-access:{}:{}:{renewal}",
            binding.id, binding.revision
        );
        if !crate::actions::production::occurrence_available_in(
            tx,
            binding.policy_version,
            &target,
            &occurrence,
            now,
        )
        .await?
        {
            continue;
        }
        crate::actions::production::queue_run_in(
            service,
            tx,
            crate::actions::production::RunInput {
                source: Source::DeviceAccess {
                    version: binding.policy_version,
                    delivery,
                },
                target: &target,
                id: delivery,
                occurrence,
                available: now,
                deadline: now + 604800,
                now,
                triggered_at: None,
            },
        )
        .await?;
        let document = checked_input(serde_json::to_value(&binding))?;
        tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("UPDATE mdm_commands.action_runs SET access_binding=$3 WHERE tenant_id=$1 AND id=$2 AND access_binding IS NULL").bind(tenant).bind(delivery).bind(document).execute(c).await?;Ok(())
        })).await?;
    }
    Ok(())
}

pub async fn finish_in(
    tx: &mut PgTransaction<'_>,
    run: &runs::Run,
    input: &wire::TaskEventRequest,
    value: &wire::AccessResult,
    project: bool,
) -> Result<()> {
    let plan = load(tx, run.id).await?;
    if value.binding_id != plan.binding.id
        || value.binding_generation != plan.binding.generation
        || value.revision != plan.binding.revision
        || value.definition_digest != plan.binding.definition_digest().map_err(Error::from)?
    {
        return Err(Error::Conflict.into());
    }
    value
        .validate_for(plan.binding.intent.platform())
        .map_err(|_| Error::Malformed)?;
    if matches!(value.effect, wire::AccessEffect::WhfbRetired { .. })
        && plan.binding.state != access::State::Revoked
    {
        return Err(Error::Conflict.into());
    }
    provisioning::finish(tx, run, input.attempt_id(), value, project).await?;
    let tenant = plan.binding.tenant;
    let value = value.clone();
    let run = run.id;
    let attempt = input.attempt_id();
    let event = input.operation_id();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let applied =
                    access::storage::result_in(c, tenant, run, attempt, event, &value, project)
                        .await?;
                if applied && matches!(value.effect, wire::AccessEffect::Unbound { .. }) {
                    rss_mdm_recovery_credentials::storage::access_unbound_in(
                        c,
                        tenant,
                        value.binding_id,
                        value.binding_generation,
                        value.revision,
                    )
                    .await
                    .map_err(crate::recovery_credentials::error)?;
                }
                Ok::<_, Error>(applied)
            }
            .await;
            Ok(result)
        })
    })
    .await??;
    Ok(())
}

pub async fn received_in(tx: &mut PgTransaction<'_>, run: &runs::Run) -> Result<()> {
    let plan = load(tx, run.id).await?;
    let b = plan.binding;
    let digest = b.definition_digest().map_err(Error::from)?;
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(
                access::storage::received_in(c, b.tenant, b.id, b.generation, b.revision, digest)
                    .await,
            )
        })
    })
    .await??;
    Ok(())
}
