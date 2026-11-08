//! Accepted device retirement uses the existing command/action execution owners.
use crate::control::actions::storage::{TaskIssue, agent_profile_in};
use crate::control::{Error, Result, Service, Target, checked_input};
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
        let version = self.version;
        Ok(tx.with_connection(move|c|Box::pin(async move {
            rss_mdm_registration_service::lifecycle::lock_device_in(rss_mdm_install_support::StorageProfile::Mdm, c,&tenant,&device).await.map_err(Error::from).map_err(|_|sqlx::Error::Protocol("retirement fence".into()))?;
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_devices.retirements AS o INNER JOIN mdm_devices.retirement_channels AS t ON (t.tenant_id, t.operation) = (o.tenant_id, o.id) INNER JOIN mdm_access.devices AS d ON (d.tenant_id, d.id, d.retirement) = (t.tenant_id, t.device, t.operation) INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (t.tenant_id, t.device) WHERE t.tenant_id = CAST($1 AS uuid) AND t.device = $2 AND o.version = $3 AND t.channel = 'agent' AND t.stage = 'unenroll' AND r.state = 'active' AND (CAST($4 AS uuid) IS NULL OR t.execution = $4))")
                .bind(tenant).bind(device).bind(version).bind(execution).fetch_one(c).await
        })).await?)
    }
    pub(crate) async fn task(
        &self,
        service: &crate::control::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<wire::TaskPayload> {
        if !self.allowed_in(tx, target, Some(issue.run)).await? {
            return Err(Error::Forbidden.into());
        }
        let (platform, architecture) = agent_profile_in(service, tx, target.device.clone())
            .await?
            .ok_or(Error::Forbidden)?;
        let tenant = tx.tenant_id().to_string();
        let run = issue.run;
        let registration = target.device.clone();
        let retirement:Uuid=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT operation FROM mdm_devices.retirement_channels WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND execution = $3 AND stage = 'unenroll'")
                .bind(tenant).bind(&registration).bind(run).fetch_one(c).await
        })).await?;
        let run = crate::control::actions::storage::load_run(tx, issue.run).await?;
        let spec = wire::UnmanageTaskSpec {
            wire_version: wire::WIRE_VERSION,
            tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
            device_id: target.device.clone(),

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

pub async fn wake_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    operation: Uuid,
) -> Result<()> {
    let target = rss_reconcile::Target::new(
        crate::control::recovery_scope(tx.tenant_id()),
        format!("retirement:{operation}"),
    )
    .map_err(|_| Error::Malformed)?;
    reconcile
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(target.scope().tenant()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::CommandRecovery)
        .await?;
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
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 AND stage<>'complete')")
            .bind(tenant).bind(operation).fetch_one(c).await
    })).await?)
}
pub async fn wake_device_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
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
        wake_in(reconcile, tx, id).await?;
    }
    Ok(())
}

pub(crate) struct PreparedRetirement {
    id: Uuid,
    original: crate::lifecycle::Retirement,
    executions: std::collections::BTreeMap<String, Uuid>,
}

impl Service {
    pub(crate) async fn prepare_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<PreparedRetirement> {
        use crate::lifecycle::{self as owner};
        let tenant = tx.tenant_id();
        let original = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(owner::read_in(c, tenant, id).await.map_err(Error::from)) },
                )
            })
            .await??;
        let t = tenant.to_string();
        let instance = self.transactions.instance.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(crate::control::authorization::lock_shared_on(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &t,
                    &instance,
                )
                .await)
            })
        })
        .await??;
        let devices = original
            .channels
            .iter()
            .map(|c| c.device.clone())
            .collect::<std::collections::BTreeSet<_>>();
        crate::control::storage::lock_devices(tx, &devices.into_iter().collect::<Vec<_>>()).await?;
        let original = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(owner::read_in(c, tenant, id).await.map_err(Error::from)) },
                )
            })
            .await??;
        let mut executions = std::collections::BTreeMap::new();

        for channel in &original.channels {
            if channel.channel == rss_mdm_inventory::Channel::Agent {
                let execution = Uuid::new_v4();

                executions.insert(channel.device.clone(), execution);
            }
        }
        Ok(PreparedRetirement {
            id,
            original,
            executions,
        })
    }
    pub(crate) async fn advance_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        prepared: PreparedRetirement,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<bool> {
        use crate::lifecycle::{self as owner, Stage};
        use rss_mdm_task_state::Execution;
        let tenant = tx.tenant_id();
        let PreparedRetirement {
            id,
            original,
            mut executions,
            ..
        } = prepared;
        // Aggregate every related registration before any primary channel can leave cleanup.
        let tasks = if original.channels.iter().any(|c| c.stage == Stage::Cleanup) {
            let registrations = original
                .channels
                .iter()
                .map(|c| c.device.clone())
                .collect::<Vec<_>>();
            let progress = self
                .transactions
                .task_cleanup
                .advance_in(tx, &registrations)
                .await?;
            self.transactions
                .audit_store
                .append_batch_in(tx, &progress.facts)
                .await
                .map_err(Error::from)?;
            progress
        } else {
            crate::control::task_cleanup::Progress::default()
        };
        let mut cleanup = None;
        for channel in &original.channels {
            if matches!(channel.stage, Stage::Complete | Stage::Revoke) {
                continue;
            }
            let tenant_name = tenant.to_string();
            let registration = channel.device.clone();
            let value = registration.clone();
            let active:bool=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query_scalar("SELECT state = 'active' FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2")
                    .bind(tenant_name).bind(&value).fetch_one(c).await
            })).await?;
            if !active {
                continue;
            }
            if channel.stage == Stage::Cleanup {
                let t = tenant.to_string();
                let value = registration.clone();
                let facts = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            let mut facts = Vec::new();
                            crate::control::retire_in(c, &mut facts, &t, value)
                                .await
                                .map(|()| facts)
                                .map_err(|e| sqlx::Error::Protocol(e.to_string()))
                        })
                    })
                    .await?;
                self.transactions
                    .audit_store
                    .append_batch_in(tx, &facts)
                    .await
                    .map_err(Error::from)?;
                let configuration = if channel.channel == rss_mdm_inventory::Channel::Mdm {
                    self.transactions
                        .configuration_cleanup
                        .advance_in(tx, id, &channel.device, audit)
                        .await?
                } else {
                    crate::control::configuration_cleanup::Progress {
                        pending: false,
                        blocker: None,
                    }
                };

                if channel.channel == rss_mdm_inventory::Channel::Mdm
                    && !self
                        .transactions
                        .task_cleanup
                        .installations_removed_in(
                            tx,
                            id,
                            &Target {
                                device: channel.device.clone(),
                            },
                        )
                        .await?
                {
                    continue;
                }
                let (remaining, blocker) = match cleanup {
                    Some(progress) => progress,
                    None => {
                        let progress = self.cleanup_progress_in(tx, id).await?;
                        cleanup = Some(progress);
                        progress
                    }
                };
                if remaining || configuration.pending || tasks.pending {
                    let blocker = blocker
                        .into_iter()
                        .chain(configuration.blocker)
                        .chain(tasks.unknown.map(|id| (0, Some(id))))
                        .min_by_key(|v| (v.0, v.1));
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
                    && !self
                        .transactions
                        .task_cleanup
                        .remove_software_in(
                            tx,
                            id,
                            &Target {
                                device: channel.device.clone(),
                            },
                        )
                        .await?
                {
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
                    let run = crate::control::actions::storage::load_run(tx, execution).await?;
                    let now = crate::control::storage::now(tx).await?;
                    let observation = match run.state.execution {
                        Execution::NotStarted if delivery_ended(&run.state, now) => {
                            owner::Observation::UnenrollmentBlocked {
                                reason: "agent_uninstall_not_started",
                            }
                        }
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
                        sqlx::query_scalar("SELECT d.status FROM mdm_devices.control_operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.id=$2")
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
                let binding = crate::control::agent_facts::agent_binding_in(
                    tx,
                    self.transactions.agent_store.clone(),
                    registration.clone(),
                )
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
                let execution = executions.remove(&registration).ok_or(Error::Conflict)?;
                let value = registration.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(
                            owner::prepare_unenrollment_in(c, tenant, id, value, execution)
                                .await
                                .map_err(Error::from),
                        )
                    })
                })
                .await??;
                let now = crate::control::storage::now(tx).await?;
                let t = tenant.to_string();
                let lifetime:i32=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT delivery_seconds FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2").bind(t).bind(id).fetch_one(c).await})).await?;
                let target = Target {
                    device: channel.device.clone(),
                };
                crate::control::actions::production::queue_run_in(
                    &self.transactions,
                    tx,
                    crate::control::actions::production::RunInput {
                        origin: original.origin,

                        source: crate::control::actions::storage::Source::Policy {
                            version: original.version,
                        },
                        target: &target,
                        id: execution,
                        occurrence: format!("retirement:{id}:{registration}"),
                        available: now,
                        deadline: now + i64::from(lifetime),
                        now,
                    },
                )
                .await?;
            } else {
                let t = tenant.to_string();
                let source:Option<(Uuid,String)>=tx.with_connection(move|c|Box::pin(async move{
                    sqlx::query_as("SELECT r.request_id, q.source FROM mdm_access.devices AS r INNER JOIN mdm_access.requests AS q ON (q.tenant_id, q.id) = (r.tenant_id, r.request_id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2")
                        .bind(t).bind(&registration).fetch_optional(c).await
                })).await?;
                if let Some((enrollment, source)) = source
                    && source == "mdm.apple"
                {
                    let task = crate::control::Task::Macos {
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
        let participant = self.transactions.retirement.clone();
        let facts = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        owner::settle_retirement_in(c, tenant, id, participant.as_ref())
                            .await
                            .map_err(Error::from),
                    )
                })
            })
            .await??;
        for fact in facts {
            self.transactions
                .audit_store
                .append_in(tx, &fact)
                .await
                .map_err(Error::from)?;
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
            let event = crate::control::transaction::fingerprint(&(id, &before, &after))?;
            let fact = rss_mdm_audit_integration::Fact::business(
                audit,
                rss_mdm_audit_integration::operation::OperationOwner::Retirement,
                &format!(
                    "retirement:{id}:{}",
                    crate::control::transaction::fingerprint(&event)?
                        .iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<String>()
                ),
                200,
                "success",
                None,
            )?;
            self.transactions
                .audit_store
                .append_in(tx, &fact)
                .await
                .map_err(Error::from)?;
        }
        Ok(false)
    }
    async fn queue_unenrollment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &crate::lifecycle::Retirement,
        channel: &crate::lifecycle::ChannelResult,
        task: crate::control::Task,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<()> {
        use crate::lifecycle as owner;
        let tenant = tx.tenant_id();
        let id = operation.id;
        let registration = channel.device.clone();
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
        let input = crate::control::Create {
            operation_id: execution,
            input_version: operation.version.to_string(),
            target: crate::control::NativeTarget::Device,
            task,
            deadline: crate::control::storage::now(tx).await? + i64::from(lifetime),
        };
        let authority = crate::control::authority::Authority::Retirement {
            origin: operation.origin,
            tenant: tenant.to_string(),
            retirement: id,
            version: operation.version,
            device: channel.device.clone(),

            execution,
            required: input.task.permissions()?,
        };
        let fingerprint = crate::control::transaction::fingerprint(&(id, &input))?;
        self.transactions
            .queue_authorized_in(tx, &channel.device, &input, authority, fingerprint, audit)
            .await?;
        Ok(())
    }
}

impl Service {
    pub async fn queue_windows_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &crate::control::device::DevicePrincipal,
        request: rss_mdm_windows_mdm::native::Request,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<()> {
        let tenant = tx.tenant_id();
        let t = tenant.to_string();
        let registration = p.device().to_owned();
        let value = registration.clone();
        let id:Option<Uuid>=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT operation FROM mdm_devices.retirement_channels WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND stage = 'unenroll' AND execution IS NULL")
                .bind(t).bind(&value).fetch_optional(c).await
        })).await?;
        let Some(id) = id else {
            return Ok(());
        };
        let operation = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(crate::lifecycle::read_in(c, tenant, id)
                        .await
                        .map_err(Error::from))
                })
            })
            .await??;
        let channel = operation
            .channels
            .iter()
            .find(|r| r.device == registration)
            .ok_or(Error::Conflict)?;
        self.queue_unenrollment_in(
            tx,
            &operation,
            channel,
            crate::control::Task::Windows {
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
    registration: String,
    confirmed: bool,
) -> std::result::Result<(), Error> {
    crate::lifecycle::native_departure_in(c, tenant, registration, confirmed)
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
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_devices.retirement_channels AS t INNER JOIN mdm_access.devices AS d ON (d.tenant_id, d.id, d.retirement) = (t.tenant_id, t.device, t.operation) INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (t.tenant_id, t.device) WHERE t.tenant_id = CAST($1 AS uuid) AND t.operation = $2 AND t.device = $3 AND t.stage = 'cleanup' AND r.state = 'active' AND (CAST($4 AS uuid) IS NULL OR EXISTS (SELECT 1 FROM mdm_devices.retirement_work AS w WHERE (w.tenant_id, w.operation, w.device, w.execution) = (t.tenant_id, t.operation, t.device, $4))))")
            .bind(tenant).bind(retirement).bind(device).bind(execution).fetch_one(c).await
    })).await?)
}

impl Service {}

// An expired or cancelled unstarted task cannot be delivered by the execution owner.

fn delivery_ended(state: &rss_mdm_task_state::RunState, now: i64) -> bool {
    state.execution == rss_mdm_task_state::Execution::NotStarted
        && (state.cancellation != rss_mdm_task_state::Cancellation::None || now >= state.deadline)
}

impl Service {
    async fn cleanup_progress_in(
        &self,
        tx: &mut PgTransaction<'_>,
        retirement: Uuid,
    ) -> Result<(bool, Option<(i32, Option<Uuid>)>)> {
        let tenant = tx.tenant_id();
        let (pending, unknown) = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as::<_, (bool, Option<Uuid>)>("SELECT EXISTS (SELECT 1 FROM mdm_devices.unmanage_runs AS u INNER JOIN mdm_devices.retirement_channels AS r ON (r.tenant_id, r.device) = (u.tenant_id, u.device) WHERE r.tenant_id = CAST($1 AS uuid) AND r.operation = $2 AND u.state ->> 'execution' IN ('running', 'waiting_reboot', 'unknown')) OR EXISTS (SELECT 1 FROM mdm_devices.control_operations AS o INNER JOIN mdm_devices.retirement_channels AS r ON (r.tenant_id, r.device) = (o.tenant_id, o.device) INNER JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE r.tenant_id = CAST($1 AS uuid) AND r.operation = $2 AND d.terminal_at IS NULL), (SELECT u.id FROM mdm_devices.unmanage_runs AS u INNER JOIN mdm_devices.retirement_channels AS r ON (r.tenant_id, r.device) = (u.tenant_id, u.device) WHERE r.tenant_id = CAST($1 AS uuid) AND r.operation = $2 AND u.state ->> 'execution' = 'unknown' ORDER BY u.id LIMIT 1)").bind(tenant.to_string()).bind(retirement).fetch_one(c).await
        })).await?;
        if pending {
            return Ok((true, unknown.map(|id| (0, Some(id)))));
        }
        // Acceptance fences new controls. Terminal RSS commands absorb late events;
        // device/claim locks prevent a skipped, unsent terminal command being dispatched.
        // Persist only checked history, on the same fenced transaction as retirement.
        // ref: sqlx-core 0.9.0 query_as.rs (fetch_all requires an explicit result bound).
        const PAGE: usize = 64;
        let mut ids: Vec<Uuid> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT o.id FROM mdm_devices.control_operations AS o INNER JOIN mdm_devices.retirement_channels AS r ON (r.tenant_id, r.device) = (o.tenant_id, o.device) INNER JOIN mdm_devices.retirements AS t ON (t.tenant_id, t.id) = (r.tenant_id, r.operation) INNER JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE r.tenant_id = CAST($1 AS uuid) AND r.operation = $2 AND d.terminal_at IS NOT NULL AND d.status <> 'applied' AND (t.cleanup_after IS NULL OR o.id > t.cleanup_after) ORDER BY o.id LIMIT 65").bind(tenant.to_string()).bind(retirement).fetch_all(c).await
        })).await?;
        let more = ids.len() > PAGE;
        ids.truncate(PAGE);
        if ids.is_empty() {
            return Ok((false, None));
        }
        let after = *ids.last().ok_or(Error::Conflict)?;
        let windows = self.transactions.windows_results.clone();
        let apple = self.transactions.apple_results.clone();
        let blocker = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let result = async {
                        let mut sent = windows.sent(c, tenant, ids.clone()).await?;
                        sent.extend(apple.sent(c, tenant, ids).await?);
                        Ok::<_, Error>(sent.into_iter().next())
                    }
                    .await;
                    Ok(result)
                })
            })
            .await??;
        if let Some(id) = blocker {
            return Ok((true, Some((0, Some(id)))));
        }
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_devices.retirements SET cleanup_after=$3 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant.to_string()).bind(retirement).bind(after).execute(c).await
        })).await?;
        Ok((more, None))
    }
}
