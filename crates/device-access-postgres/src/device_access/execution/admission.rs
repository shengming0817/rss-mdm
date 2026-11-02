//! Per-account desired effects reuse signed action runs, not a second queue.
use super::provisioning;
use super::{
    storage::{self as runs, TaskIssue},
    *,
};
use crate::{
    Error as AccessError,
    device_access::{self as access},
};
use rss_mdm_agent_wire::runtime as wire;

pub(crate) fn native_local_session(
    binding: agent_facts::Binding,
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

pub(crate) async fn policy_on(
    scope: rss_request_context::TenantId,
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    device: &str,
    policy: Uuid,
) -> std::result::Result<rss_mdm_device_access::PolicySelection, AccessError> {
    if tenant.to_string() != scope.to_string() {
        return Err(AccessError::Forbidden);
    }
    sqlx::query("SELECT rss_da.lock_policy($1)")
        .bind(policy)
        .execute(&mut *c)
        .await
        .map_err(|_| AccessError::Storage)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| AccessError::Storage)?;
    policy_read_on(c, device, policy, now).await
}

// The writer takes its business locks above; snapshot discovery only evaluates the same SQL facts.
async fn policy_read_on(
    c: &mut sqlx::PgConnection,
    device: &str,
    policy: Uuid,
    now: i64,
) -> std::result::Result<rss_mdm_device_access::PolicySelection, AccessError> {
    let selection: serde_json::Value = sqlx::query_scalar("SELECT rss_da.access_policy($1,$2,$3)")
        .bind(policy)
        .bind(device)
        .bind(now)
        .fetch_one(c)
        .await
        .map_err(|_| AccessError::Storage)?;
    match selection["state"].as_str() {
        Some("pending") => Err(AccessError::Storage),
        Some("excluded") => Err(AccessError::Forbidden),
        Some("eligible") => Ok(rss_mdm_device_access::PolicySelection {
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
pub fn capable(
    binding: &agent_facts::Binding,
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
    pub(crate) async fn allowed_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        let mut context = (&self.binding, target);
        let matched = tx
            .with_connection_context(&mut context, |(b, target), c| {
                Box::pin(async move {
                    Ok(crate::delivery::for_binding_on(c, b).await.map(|a| {
                        a.is_some_and(|a| {
                            a.device == target.device
                                && a.registration == target.registration
                                && a.generation == target.generation
                        })
                    }))
                })
            })
            .await??;
        if !matched {
            return Ok(false);
        }
        let native =
            agent_facts::agent_binding_in(tx, service.agent_store.clone(), target.registration)
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
                if current.state == rss_mdm_device_access::State::Revoked {
                    return Ok(Ok(true));
                }
                let enabled: bool = sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)=$1::text AND rss_da.access_policy($2,$3,floor(extract(epoch FROM clock_timestamp()))::bigint)->>'version'=$4")
                    .bind(tenant).bind(current.policy).bind(&current.device).bind(current.policy_version.to_string()).fetch_one(c).await?;
                Ok(Ok(enabled))
            })
        })
        .await?
    }
    pub(crate) async fn task(
        &self,
        service: &Transactions,
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
        let action = if b.state == rss_mdm_device_access::State::Revoked {
            wire::AccessAction::Unbind {
                disposition: b.account_disposition,
                account: b.account.clone().ok_or(Error::Conflict)?,
            }
        } else {
            match &b.intent {
                rss_mdm_device_access::AccountIntent::Existing { account } => {
                    wire::AccessAction::Apply {
                        account: account.clone(),
                        configuration: b.configuration.clone(),
                    }
                }
                rss_mdm_device_access::AccountIntent::Create { platform: _, name } => {
                    match &b.account {
                        Some(account) => wire::AccessAction::Apply {
                            account: account.clone(),
                            configuration: b.configuration.clone(),
                        },
                        None => wire::AccessAction::Create {
                            name: name.clone(),
                            configuration: b.configuration.clone(),
                        },
                    }
                }
            }
        };
        let spec = wire::AccessTaskSpec {
            wire_version: wire::WIRE_VERSION,
            tenant_id: b.tenant,
            device_id: target.device.clone(),
            registration_id: target.registration,
            generation: u64::try_from(target.generation).map_err(|_| Error::Invariant)?,
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
    let value:serde_json::Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT access_binding FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(delivery).fetch_one(c).await})).await?;
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
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    device: &rss_mdm_registration_service::DevicePrincipal,
) -> Result<PreparedReconciliation> {
    prepare_target_reconciliation_in(
        service,
        tx,
        &Target {
            device: device.device().to_owned(),
            registration: device.registration(),
            generation: device.generation(),
        },
        None,
    )
    .await
}

pub(crate) async fn prepare_target_reconciliation_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    policy: Option<Uuid>,
) -> Result<PreparedReconciliation> {
    // Retirement needs this poll to carry its accepted cleanup/unmanage work.
    // Keep the existing lifecycle lock and propagate storage faults unchanged.
    let tenant_name = tx.tenant_id().to_string();
    let device_name = target.device.clone();
    let work_allowed = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
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
            blocked: true,
        });
    }
    let tenant = stored(Uuid::parse_str(&tx.tenant_id().to_string()))?;
    let name = target.device.clone();
    let registration = target.registration;
    let generation = target.generation;
    let documents:Vec<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move{
        sqlx::query_scalar("SELECT b.document FROM rss_da.bindings b JOIN rss_da.agent_delivery d ON(d.tenant_id,d.da_registration,d.da_generation)=(b.tenant_id,b.registration,b.registration_generation) WHERE b.tenant_id=$1 AND d.agent_device=$2 AND d.agent_registration=$3 AND ($4::uuid IS NULL OR b.document->>'policy'=$4::text) AND d.agent_generation=$5 AND d.enabled ORDER BY b.id LIMIT 128").bind(tenant).bind(name).bind(registration).bind(policy).bind(generation).fetch_all(c).await
    })).await?;
    let mut bindings = Vec::new();
    for document in documents {
        let scope = service.tenant;
        let previous: access::Binding = stored(serde_json::from_value(document))?;
        let binding = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let binding = access::storage::locked_in(c, tenant, previous.id)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("access binding unavailable".into()))?;
                    if binding.state != rss_mdm_device_access::State::Revoked {
                        match policy_on(scope, c, tenant, &binding.device, binding.policy).await {
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

        bindings.push((binding, delivery));
    }
    Ok(PreparedReconciliation {
        bindings,
        blocked: false,
    })
}
pub(crate) struct PreparedReconciliation {
    blocked: bool,
    bindings: Vec<(access::Binding, Uuid)>,
}
pub(crate) struct Reconciliation {
    pub operations: Vec<Uuid>,
    pub blocked: bool,
}
/// Apply exactly the bounded bindings prepared before the caller's partition declaration.
pub(crate) async fn reconcile_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    prepared: PreparedReconciliation,
    now: i64,
    origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    audit: &RequestAudit,
) -> Result<Reconciliation> {
    let tenant = stored(Uuid::parse_str(&tx.tenant_id().to_string()))?;
    let mut outcome = Reconciliation {
        operations: Vec::new(),
        blocked: prepared.blocked,
    };
    for (previous, delivery) in prepared.bindings {
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
                    if b.state != rss_mdm_device_access::State::Revoked {
                        match policy_on(scope, c, tenant, &b.device, b.policy).await {
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
                                    b.state = rss_mdm_device_access::State::Revoked;
                                    b.configuration.enabled = false;
                                } else if p.version != b.policy_version
                                    || p.configuration != b.configuration
                                {
                                    b.revision = b.revision.checked_add(1).ok_or_else(|| {
                                        sqlx::Error::Protocol("access revision exhausted".into())
                                    })?;
                                    b.policy_version = p.version;
                                    b.configuration = p.configuration;
                                    b.state = rss_mdm_device_access::State::Pending;
                                }
                            }
                            Err(AccessError::Forbidden) => {
                                b.revision = b.revision.checked_add(1).ok_or_else(|| {
                                    sqlx::Error::Protocol("access revision exhausted".into())
                                })?;
                                b.generation = b.generation.checked_add(1).ok_or_else(|| {
                                    sqlx::Error::Protocol("access generation exhausted".into())
                                })?;
                                b.state = rss_mdm_device_access::State::Revoked;
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
            let fact = rss_mdm_audit_integration::Fact::business(
                audit,
                &format!("device-access:{id}:revision:{}", binding.revision),
                200,
                "success",
                None,
            )?;
            service.audit_store.append_in(tx, &fact).await?;
        }
        if binding.applied_revision == Some(binding.revision)
            || (binding.state == rss_mdm_device_access::State::Revoked && binding.account.is_none())
        {
            continue;
        }
        let target = tx
            .with_connection_context(&mut &binding, |b, c| {
                Box::pin(async move { Ok(crate::delivery::for_binding_on(c, b).await) })
            })
            .await??;
        let Some(agent) = target else {
            outcome.blocked = true;
            continue;
        };
        let target = Target {
            device: agent.device,
            registration: agent.registration,
            generation: agent.generation,
        };
        let t = tenant;
        let outstanding:bool=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rss_da.access_runs WHERE tenant_id=$1 AND access_binding->>'id'=$2 AND state->>'execution' IN ('running','unknown','waiting_reboot'))").bind(t).bind(id.to_string()).fetch_one(c).await
        })).await?;
        if outstanding {
            match current_binding_run_in(tx, &binding).await? {
                Some(id) => outcome.operations.push(id),
                None => outcome.blocked = true,
            }
            continue;
        }
        // Only a delivery that never obtained Start can be replaced after expiry.
        // Started and uncertain attempts remain the authoritative recovery coordinate.
        let revision = binding.revision;
        let renewal: Option<i64> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT CASE WHEN count(*)=count(*) FILTER(WHERE deadline<=$4 AND state->>'execution'='not_started' AND state->>'startedAt' IS NULL) THEN count(*) ELSE NULL END FROM rss_da.access_runs WHERE tenant_id=$1 AND access_binding->>'id'=$2 AND (access_binding->>'revision')::bigint=$3")
                .bind(tenant).bind(id.to_string()).bind(revision).bind(now).fetch_one(c).await
        })).await?;
        let Some(renewal) = renewal else {
            if let Some(id) = current_binding_run_in(tx, &binding).await? {
                outcome.operations.push(id);
            }
            continue;
        };
        let occurrence = format!(
            "device-access:{}:{}:{renewal}",
            binding.id, binding.revision
        );
        if !production::occurrence_available_in(
            service,
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
        production::queue_run_in(
            service,
            tx,
            &binding,
            delivery,
            occurrence,
            now,
            now + 604800,
            origin,
        )
        .await?;
        outcome.operations.push(delivery);
    }
    Ok(outcome)
}

async fn current_binding_run_in(
    tx: &mut PgTransaction<'_>,
    binding: &access::Binding,
) -> Result<Option<Uuid>> {
    let tenant = tx.tenant_id().to_string();
    let binding = binding.clone();
    Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT id FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND access_binding->>'id'=$2 AND (access_binding->>'revision')::bigint=$3 AND policy_version=$4 ORDER BY created_at DESC,id DESC LIMIT 1").bind(tenant).bind(binding.id.to_string()).bind(binding.revision).bind(binding.policy_version).fetch_optional(c).await})).await?)
}

pub(crate) async fn finish_in(
    service: &Transactions,
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
        && plan.binding.state != rss_mdm_device_access::State::Revoked
    {
        return Err(Error::Conflict.into());
    }
    let observed_binding = plan.binding.clone();
    let current_report = if project {
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(access::storage::locked_observation_in(
                    c,
                    observed_binding.tenant,
                    observed_binding.id,
                )
                .await
                .map(|current| {
                    current.generation == observed_binding.generation
                        && current.revision == observed_binding.revision
                }))
            })
        })
        .await?
        .map_err(Error::from)?
    } else {
        false
    };
    if current_report
        && let wire::AccessEffect::Applied { mac: Some(mac), .. } = &value.effect
        && let Some(facts) = &mac.platform_sso
    {
        let valid = tx
            .with_connection_context(
                &mut (service, &plan.binding, facts),
                |(service, binding, facts), c| {
                    Box::pin(async move {
                        Ok(service
                            .platform
                            .platform_sso_observation(c, binding, facts)
                            .await)
                    })
                },
            )
            .await??;
        if !valid {
            return Err(Error::Conflict.into());
        }
    }
    provisioning::finish(service, tx, run, input.attempt_id(), value, project).await?;
    let tenant = plan.binding.tenant;
    let value = value.clone();
    let run = run.id;
    let attempt = input.attempt_id();
    let event = input.operation_id();
    let recovery = service.recovery.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let applied =
                    access::storage::result_in(c, tenant, run, attempt, event, &value, project)
                        .await?;
                if applied && matches!(value.effect, wire::AccessEffect::Unbound { .. }) {
                    recovery
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .unbound(
                            c,
                            tenant,
                            value.binding_id,
                            value.binding_generation,
                            value.revision,
                        )
                        .await?;
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
