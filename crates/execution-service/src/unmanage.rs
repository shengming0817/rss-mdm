//! Accepted device retirement uses the existing command/action execution owners.
use crate::actions::storage::{TaskIssue, agent_profile_in};
use crate::{Error, ExecutionService, Result, Target, checked_input};
use rss_mdm_agent_wire::runtime as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub struct RetirementPlan {
    pub owner: Uuid,
    pub version: Uuid,
    pub lifetime: u32,
}
impl RetirementPlan {
    pub async fn allowed_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        execution: Option<Uuid>,
    ) -> Result<bool> {
        let tenant = tx.tenant_id().to_string();
        let device = target.device.clone();
        let registration = target.registration;
        let generation = target.generation;
        let version = self.version;
        Ok(tx.with_connection(move|c|Box::pin(async move {
            rss_mdm_registration_service::lifecycle::lock_device_in(c,&tenant,&device).await.map_err(Error::from).map_err(|_|sqlx::Error::Protocol("retirement fence".into()))?;
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirements o JOIN mdm_devices.retirement_channels t ON(t.tenant_id,t.operation)=(o.tenant_id,o.id) JOIN mdm_access.devices d ON(d.tenant_id,d.id,d.retirement)=(t.tenant_id,t.device,t.operation) JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(t.tenant_id,t.registration,t.generation) WHERE t.tenant_id=$1::uuid AND t.device=$2 AND t.registration=$3 AND t.generation=$4 AND o.version=$5 AND t.channel='agent' AND t.stage='unenroll' AND r.state='active' AND ($6::uuid IS NULL OR t.execution=$6))")
                .bind(tenant).bind(device).bind(registration).bind(generation).bind(version).bind(execution).fetch_one(c).await
        })).await?)
    }
    pub async fn task(
        &self,
        service: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<wire::TaskPayload> {
        if !self.allowed_in(tx, target, Some(issue.run)).await? {
            return Err(Error::Forbidden.into());
        }
        let (platform, architecture) = agent_profile_in(service, tx, target.registration)
            .await?
            .ok_or(Error::Forbidden)?;
        let tenant = tx.tenant_id().to_string();
        let run = issue.run;
        let registration = target.registration;
        let retirement:Uuid=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT operation FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND registration=$2 AND execution=$3 AND stage='unenroll'")
                .bind(tenant).bind(registration).bind(run).fetch_one(c).await
        })).await?;
        let run = crate::actions::storage::load_run(tx, issue.run).await?;
        let spec = wire::UnmanageTaskSpec {
            wire_version: wire::WIRE_VERSION,
            tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
            device_id: target.device.clone(),
            registration_id: target.registration,
            generation: target.generation.try_into().map_err(|_| Error::Malformed)?,
            retirement_id: retirement,
            task_id: issue.run,
            attempt_id: issue.attempt,
            permit: issue.permit,
            expires_at: issue.expiry,
            deadline: run.deadline,
            platform: match platform {
                rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
            },
            architecture: match architecture {
                rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
            },
            authorization: wire::TaskAuthorization::Policy {
                policy_id: self.owner,
                policy_version: self.version,
            },
        };
        checked_input(spec.signing_bytes("validation"))?;
        Ok(wire::TaskPayload::Unmanage(Box::new(spec)))
    }
}

pub async fn wake_in(tx: &mut PgTransaction<'_>, operation: Uuid) -> Result<()> {
    let target = rss_reconcile::Target::new(
        crate::recovery_scope(tx.tenant_id()),
        format!("retirement:{operation}"),
    )
    .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    Ok(())
}
pub fn operation(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("retirement:")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub async fn active_in(tx: &mut PgTransaction<'_>, operation: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move{
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 AND stage IN('cleanup','unenroll'))")
            .bind(tenant).bind(operation).fetch_one(c).await
    })).await?)
}
pub async fn wake_device_in(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let id: Option<Uuid> = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT retirement FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
                )
                .bind(tenant)
                .bind(device)
                .fetch_optional(c)
                .await
                .map(Option::flatten)
            })
        })
        .await?;
    if let Some(id) = id {
        wake_in(tx, id).await?;
    }
    Ok(())
}

impl ExecutionService {
    pub async fn advance_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<bool> {
        use crate::actions::state::Execution;
        use rss_mdm_device_service::lifecycle::{self as owner, Stage};
        let tenant = tx.tenant_id();
        let original = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(owner::read_in(c, tenant, id).await.map_err(Error::from)) },
                )
            })
            .await??;
        let t = tenant.to_string();
        let instance = self.instance.clone();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(crate::authorization::lock_on(c, &t, &instance).await) })
        })
        .await??;
        crate::transaction::lock(tx).await?;
        let devices = original
            .channels
            .iter()
            .map(|c| c.device.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for device in &devices {
            crate::storage::lock(tx, device).await?;
        }
        for device in devices {
            let t = tenant.to_string();
            tx.with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_registration_service::lifecycle::lock_device_in(c, &t, &device)
                            .await,
                    )
                })
            })
            .await??;
        }
        let original = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(owner::read_in(c, tenant, id).await.map_err(Error::from)) },
                )
            })
            .await??;
        for channel in &original.channels {
            if matches!(channel.stage, Stage::Complete | Stage::Revoke) {
                continue;
            }
            let tenant_name = tenant.to_string();
            let registration = channel.registration;
            let active:bool=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query_scalar("SELECT state='active' FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(tenant_name).bind(registration).fetch_one(c).await
            })).await?;
            if !active {
                continue;
            }
            if channel.stage == Stage::Cleanup {
                let t = tenant.to_string();
                let facts = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            let mut facts = Vec::new();
                            crate::retire_in(c, &mut facts, &t, registration)
                                .await
                                .map(|()| facts)
                                .map_err(|e| sqlx::Error::Protocol(e.to_string()))
                        })
                    })
                    .await?;
                for fact in facts {
                    self.audit_store
                        .append_in(tx, &fact, false)
                        .await
                        .map_err(Error::from)?;
                }
                if channel.channel == rss_mdm_inventory::Channel::Mdm {
                    let t = tenant.to_string();
                    let device = channel.device.clone();
                    tx.with_connection(move|c|Box::pin(async move{
                        sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(t).bind(device).execute(c).await?;Ok(())
                    })).await?;
                    self.reconcile_configuration(tx, &channel.device, audit)
                        .await?;
                }
                let t = tenant.to_string();
                let device = channel.device.clone();
                let remaining:bool=tx.with_connection(move|c|Box::pin(async move{
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2) OR EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration IN(SELECT registration FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$3) AND state->>'execution' IN('running','waiting_reboot','unknown')) OR EXISTS(SELECT 1 FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.registration IN(SELECT registration FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$3) AND (d.terminal_at IS NULL OR (d.status<>'applied' AND (EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')))))")
                        .bind(t).bind(device).bind(id).fetch_one(c).await
                })).await?;
                if remaining {
                    let t = tenant.to_string();
                    let device = channel.device.clone();
                    let blocker:Option<(i32,Option<Uuid>)>=tx.with_connection(move|c|Box::pin(async move{
                        sqlx::query_as("SELECT priority,execution FROM (SELECT 0 AS priority,r.id AS execution FROM mdm_commands.action_runs r WHERE r.tenant_id=$1::uuid AND r.registration IN(SELECT registration FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$3) AND r.state->>'execution'='unknown' UNION ALL SELECT 0,o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.registration IN(SELECT registration FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$3) AND d.terminal_at IS NOT NULL AND d.status<>'applied' AND (EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')) UNION ALL SELECT 1,c.operation FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.device=$2 AND d.diagnosis IN('configuration_conflict','native_group_conflict','removal_blocked_by_shared_unit')) blockers ORDER BY priority,execution LIMIT 1")
                            .bind(t).bind(device).bind(id).fetch_optional(c).await
                    })).await?;
                    let observation = match blocker {
                        Some((0, execution)) => owner::Observation::CleanupBlocked {
                            reason: "cleanup_execution_unconfirmed",
                            execution,
                            unknown: true,
                        },
                        Some((_, execution)) => owner::Observation::CleanupBlocked {
                            reason: "configuration_removal_blocked",
                            execution,
                            unknown: false,
                        },
                        None => owner::Observation::CleanupWaiting { execution: None },
                    };
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(owner::observe_in(c, tenant, id, registration, observation)
                                .await
                                .map_err(Error::from))
                        })
                    })
                    .await??;
                    continue;
                }
                if channel.channel == rss_mdm_inventory::Channel::Agent
                    && !self.cleanup_software_retirement_in(tx, id, channel).await?
                {
                    continue;
                }
                // The primary channel performs unenrollment after all child cleanup.
                // Child credentials are revoked by the registration owner's cascade.
                if channel.parent_registration.is_some() {
                    continue;
                }
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(owner::observe_in(
                            c,
                            tenant,
                            id,
                            registration,
                            owner::Observation::CleanupReady,
                        )
                        .await
                        .map_err(Error::from))
                    })
                })
                .await??;
                continue;
            }
            if let Some(execution) = channel.execution {
                if channel.channel == rss_mdm_inventory::Channel::Agent {
                    let run = crate::actions::storage::load_run(tx, execution).await?;
                    let observation = match run.state.execution {
                        Execution::Succeeded => owner::Observation::Uninstalled,
                        Execution::Failed => owner::Observation::UnenrollmentBlocked {
                            reason: "agent_uninstall_failed",
                        },
                        Execution::Unknown => owner::Observation::UnenrollmentUnknown {
                            reason: "agent_uninstall_unconfirmed",
                        },
                        _ => continue,
                    };
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(owner::observe_in(c, tenant, id, registration, observation)
                                .await
                                .map_err(Error::from))
                        })
                    })
                    .await??;
                } else {
                    let t = tenant.to_string();
                    let status: String = tx.with_connection(move |c| Box::pin(async move {
                        sqlx::query_scalar("SELECT d.status FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.id=$2")
                            .bind(t).bind(execution).fetch_one(c).await
                    })).await?;
                    let reason = match status.as_str() {
                        "applied" => Some("native_departure_unconfirmed"),
                        "rejected" | "cancelled" | "superseded" => {
                            Some("native_unenrollment_failed")
                        }
                        "timed_out" => Some("native_unenrollment_unconfirmed"),
                        _ => None,
                    };
                    if let Some(reason) = reason {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(owner::observe_in(
                                    c,
                                    tenant,
                                    id,
                                    registration,
                                    owner::Observation::UnenrollmentUnknown { reason },
                                )
                                .await
                                .map_err(Error::from))
                            })
                        })
                        .await??;
                    }
                }
                continue;
            }
            if channel.channel == rss_mdm_inventory::Channel::Agent {
                let binding =
                    crate::channels::agent_binding_in(tx, self.agent_store.clone(), registration)
                        .await?;
                if !binding
                    .is_some_and(|b| b.capabilities.contains(&wire::Capability::DeviceUnmanageV1))
                {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(owner::observe_in(
                                c,
                                tenant,
                                id,
                                registration,
                                owner::Observation::UnenrollmentBlocked {
                                    reason: "agent_unmanage_capability_required",
                                },
                            )
                            .await
                            .map_err(Error::from))
                        })
                    })
                    .await??;
                    continue;
                }
                let execution = Uuid::new_v4();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(
                            owner::prepare_unenrollment_in(c, tenant, id, registration, execution)
                                .await
                                .map_err(Error::from),
                        )
                    })
                })
                .await??;
                let now = crate::storage::now(tx).await?;
                let t = tenant.to_string();
                let lifetime:i32=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT delivery_seconds FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2").bind(t).bind(id).fetch_one(c).await})).await?;
                let target = Target {
                    device: channel.device.clone(),
                    registration,
                    generation: channel.generation,
                };
                crate::actions::production::queue_run_in(
                    self,
                    tx,
                    crate::actions::production::RunInput {
                        source: crate::actions::storage::Source::Policy {
                            version: original.version,
                        },
                        target: &target,
                        id: execution,
                        occurrence: format!("retirement:{id}:{registration}"),
                        available: now,
                        deadline: now + i64::from(lifetime),
                        now,
                        triggered_at: None,
                    },
                )
                .await?;
            } else {
                let t = tenant.to_string();
                let source:Option<(Uuid,String)>=tx.with_connection(move|c|Box::pin(async move{
                    sqlx::query_as("SELECT r.request_id,q.source FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2")
                        .bind(t).bind(registration).fetch_optional(c).await
                })).await?;
                if let Some((enrollment, source)) = source
                    && source == "mdm.apple"
                {
                    let task = crate::Task::Macos {
                        request: rss_mdm_apple_mdm::native::request::Request::RemoveProfile {
                            identifier: format!("com.rss-mdm.enrollment.{enrollment}"),
                            uuid: enrollment,
                        },
                    };
                    self.queue_unenrollment_in(tx, &original, channel, task, audit)
                        .await?;
                }
            }
        }
        let current = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(owner::read_in(c, tenant, id).await.map_err(Error::from)) },
                )
            })
            .await??;
        let before = checked_input(serde_json::to_value(&original.channels))?;
        let after = checked_input(serde_json::to_value(&current.channels))?;
        if before != after {
            let bytes = checked_input(serde_json::to_vec(&(id, &before, &after)))?;
            let event = crate::transaction::fingerprint(&(id, &before, &after))?;
            let fact = rss_mdm_audit_integration::Fact::business(
                audit,
                &format!(
                    "retirement:{id}:{}",
                    crate::transaction::fingerprint(&event)?
                        .iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<String>()
                ),
                &bytes,
                200,
                "success",
                None,
            )?;
            self.audit_store
                .append_in(tx, &fact, false)
                .await
                .map_err(Error::from)?;
        }
        Ok(false)
    }
    async fn queue_unenrollment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &rss_mdm_device_service::lifecycle::Retirement,
        channel: &rss_mdm_device_service::lifecycle::ChannelResult,
        task: crate::Task,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<()> {
        use rss_mdm_device_service::lifecycle as owner;
        let tenant = tx.tenant_id();
        let id = operation.id;
        let registration = channel.registration;
        let execution = Uuid::new_v4();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    owner::prepare_unenrollment_in(c, tenant, id, registration, execution)
                        .await
                        .map_err(Error::from),
                )
            })
        })
        .await??;
        let t = tenant.to_string();
        let lifetime: i32 = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT delivery_seconds FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2")
                .bind(t).bind(id).fetch_one(c).await
        })).await?;
        let input = crate::Create {
            operation_id: execution,
            input_version: operation.version.to_string(),
            target: crate::NativeTarget::Device,
            task,
            deadline: crate::storage::now(tx).await? + i64::from(lifetime),
        };
        let authority = crate::authority::ExecutionAuthority::Retirement {
            tenant: tenant.to_string(),
            retirement: id,
            version: operation.version,
            device: channel.device.clone(),
            registration,
            execution,
            required: input.task.permissions()?,
        };
        let fingerprint = crate::transaction::fingerprint(&(id, &input))?;
        self.queue_authorized_in(tx, &channel.device, &input, authority, fingerprint, audit)
            .await?;
        Ok(())
    }
}

impl ExecutionService {
    pub async fn queue_windows_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &crate::device::DevicePrincipal,
        request: rss_mdm_windows_mdm::native::Request,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<()> {
        let tenant = tx.tenant_id();
        let t = tenant.to_string();
        let registration = p.registration();
        let id:Option<Uuid>=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT operation FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND registration=$2 AND stage='unenroll' AND execution IS NULL")
                .bind(t).bind(registration).fetch_optional(c).await
        })).await?;
        let Some(id) = id else {
            return Ok(());
        };
        let operation = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_device_service::lifecycle::read_in(c, tenant, id)
                        .await
                        .map_err(Error::from))
                })
            })
            .await??;
        let channel = operation
            .channels
            .iter()
            .find(|r| r.registration == registration)
            .ok_or(Error::Conflict)?;
        self.queue_unenrollment_in(
            tx,
            &operation,
            channel,
            crate::Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl { request },
            },
            audit,
        )
        .await
    }
}

pub async fn native_departure_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
    confirmed: bool,
) -> std::result::Result<(), Error> {
    rss_mdm_device_service::lifecycle::native_departure_in(c, tenant, registration, confirmed)
        .await
        .map_err(Error::from)
}

pub async fn cleanup_allowed_in(
    tx: &mut PgTransaction<'_>,
    retirement: Uuid,
    device: &str,
    execution: Option<Uuid>,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move{
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_channels t JOIN mdm_access.devices d ON(d.tenant_id,d.id,d.retirement)=(t.tenant_id,t.device,t.operation) JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(t.tenant_id,t.registration,t.generation) WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.device=$3 AND t.stage='cleanup' AND r.state='active' AND ($4::uuid IS NULL OR EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.operation,w.registration,w.execution)=(t.tenant_id,t.operation,t.registration,$4))))")
            .bind(tenant).bind(retirement).bind(device).bind(execution).fetch_one(c).await
    })).await?)
}

impl ExecutionService {
    async fn cleanup_software_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        retirement: Uuid,
        channel: &rss_mdm_device_service::lifecycle::ChannelResult,
    ) -> Result<bool> {
        use crate::actions::{production, state::Execution, storage as runs};
        use rss_mdm_device_service::lifecycle as owner;
        use sha2::{Digest, Sha256};
        use sqlx::Row;
        let tenant = tx.tenant_id();
        let t = tenant.to_string();
        let registration = channel.registration;
        let rows=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("SELECT DISTINCT ON(software_effect->'resource',software_effect->'target') id,policy_version,software_effect,result FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND software_effect IS NOT NULL AND result->>'effect' IN('verified','failed') ORDER BY software_effect->'resource',software_effect->'target',(result->>'effectObservedAt')::bigint DESC NULLS LAST,created_at DESC,id DESC LIMIT 129")
                .bind(t).bind(registration).fetch_all(c).await
        })).await?;
        if rows.len() > 128 {
            return self
                .block_retirement_cleanup(tx, retirement, registration, "software_cleanup_limit")
                .await;
        }
        let target = Target {
            device: channel.device.clone(),
            registration,
            generation: channel.generation,
        };
        let mut complete = true;
        for row in rows {
            let effect: serde_json::Value = row.try_get("software_effect")?;
            let result: serde_json::Value = row.try_get("result")?;
            if result["effect"] != "verified" {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration,
                        "software_effect_unconfirmed",
                    )
                    .await;
            }
            if effect["intent"] == "uninstall" {
                continue;
            }
            let original: Uuid = row.try_get("id")?;
            let version: Uuid = row.try_get("policy_version")?;
            let hash = Sha256::digest(checked_input(serde_json::to_vec(&(
                tenant.to_string(),
                retirement,
                original,
            )))?);
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&hash[..16]);
            let id = Uuid::from_bytes(bytes);
            let t = tenant.to_string();
            let exists:bool=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2)").bind(t).bind(id).fetch_one(c).await
            })).await?;
            if exists {
                let run = runs::load_run(tx, id).await?;
                if run.state.execution == Execution::Succeeded
                    && run
                        .result
                        .as_ref()
                        .is_some_and(|v| v["effect"] == "verified")
                {
                    continue;
                }
                if matches!(run.state.execution, Execution::Failed | Execution::Unknown) {
                    return self
                        .block_retirement_cleanup(
                            tx,
                            retirement,
                            registration,
                            "software_removal_unconfirmed",
                        )
                        .await;
                }
                complete = false;
                continue;
            }
            let software = crate::sources::software::retirement_in(
                &self.policy_reader,
                tx,
                version,
                retirement,
            )
            .await?;
            let Some(binding) =
                crate::channels::agent_binding_in(tx, self.agent_store.clone(), registration)
                    .await?
            else {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration,
                        "agent_binding_unavailable",
                    )
                    .await;
            };
            if !software
                .assignment
                .supported_in(&self.admission(), tx, &binding)
                .await?
            {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration,
                        "software_removal_unsupported",
                    )
                    .await;
            }
            let Some((platform, architecture)) = agent_profile_in(self, tx, registration).await?
            else {
                return Err(Error::Conflict.into());
            };
            let steps = software
                .assignment
                .prepared_in(
                    &self.admission(),
                    tx,
                    platform,
                    architecture,
                    &binding.execution_context,
                )
                .await?
                .ok_or(Error::Unsupported)?;
            if steps.iter().any(|s| !s.action.behavior.supports_removal()) {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration,
                        "software_removal_unsupported",
                    )
                    .await;
            }
            let effect = crate::actions::software::effect_key(&software, &target, &steps)?;
            tx.with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        owner::authorize_execution_in(c, tenant, retirement, registration, id)
                            .await
                            .map_err(Error::from),
                    )
                })
            })
            .await??;
            let now = crate::storage::now(tx).await?;
            production::queue_run_in(
                self,
                tx,
                production::RunInput {
                    source: runs::Source::RetirementSoftware {
                        version,
                        retirement,
                    },
                    target: &target,
                    id,
                    occurrence: format!("retirement:{retirement}:{original}"),
                    available: now,
                    deadline: now + i64::from(software.assignment.frozen.run_lifetime_seconds),
                    now,
                    triggered_at: None,
                },
            )
            .await?;
            crate::actions::software::persist_effect_in(tx, id, &effect).await?;
            complete = false;
        }
        Ok(complete)
    }
    async fn block_retirement_cleanup(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        registration: Uuid,
        reason: &'static str,
    ) -> Result<bool> {
        use rss_mdm_device_service::lifecycle as owner;
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(owner::observe_in(
                    c,
                    tenant,
                    id,
                    registration,
                    owner::Observation::CleanupBlocked {
                        reason,
                        execution: None,
                        unknown: false,
                    },
                )
                .await
                .map_err(Error::from))
            })
        })
        .await??;
        Ok(false)
    }
}
