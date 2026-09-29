//! Fixed Agent installation shares native reconciliation and command authority.
use super::*;
use crate::planning::policies::{
    self, Frozen,
    agent_install::{Identity, Package},
};
use rss_mdm_inventory::ReportSource;
use rss_mdm_policy::{Architecture, Platform, SoftwareTarget, schedule::Trigger};
use sqlx::Row;

impl ExecutionService {
    pub async fn reconcile_agent_install_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.settle_agent_install_in(tx, device).await?;
        let Some((policy, version, package, deadline)) =
            self.agent_install_candidate_in(tx, device).await?
        else {
            return Ok(());
        };
        let input = Create {
            operation_id: Uuid::new_v4(),
            deadline,
            task: Task::AgentInstall {
                package: Box::new(package),
            },
        };
        let approval = authority::ExecutionAuthority::AgentInstall {
            tenant: tx.tenant_id().to_string(),
            policy,
            version,
            device: device.into(),
            operation: input.operation_id,
        };
        let now = storage::now(tx).await?;
        let check = approval.clone();
        if !tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(check
                        .valid(c, crate::authorization::Permission::SoftwareDeploy, now)
                        .await)
                })
            })
            .await??
        {
            return Ok(());
        }
        let fact_audit = audit.transaction_copy();
        fact_audit.identify_service("agent-install-policy");
        fact_audit.operation(input.operation_id, "command_accept");
        fact_audit.target(device);
        let result = self
            .queue_authorized_in(
                tx,
                device,
                &input,
                approval,
                crate::transaction::fingerprint(&(device, &input, policy, version))?,
                &fact_audit,
            )
            .await;
        fact_audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result?;
        let target = service::target(tx.tenant_id(), device);
        rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await?;
        Ok(())
    }
    async fn agent_install_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<Option<(Uuid, Uuid, Package, i64)>> {
        if self.agent_installation.packages.is_empty() {
            return Ok(None);
        }
        let (registration, generation) = match storage::current_registration(tx, device).await {
            Ok(v) => v,
            Err(Fault::Request(Error::Conflict)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let tenant = tx.tenant_id();
        let source=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT source FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND enabled AND source IN ('mdm.windows','mdm.apple')").bind(tenant.to_string()).bind(registration).fetch_optional(c).await})).await?;
        let (source, platform) = match source.as_deref() {
            Some("mdm.windows") => (ReportSource::MdmWindows, Platform::Windows),
            Some("mdm.apple") => (ReportSource::MdmApple, Platform::Macos),
            _ => return Ok(None),
        };
        let tenant = tx.tenant_id();
        let fact = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(crate::assets::channel::detail_in(
                        c,
                        tenant,
                        registration,
                        generation,
                        source,
                    )
                    .await)
                })
            })
            .await??;
        let Some(fact) = fact.filter(|f| f.state == "absent") else {
            return Ok(None);
        };
        let Some(evidence) = fact.evidence else {
            return Ok(None);
        };
        let architecture = match evidence.architecture.as_deref() {
            Some("x86_64") => Architecture::X86_64,
            Some("aarch64") => Architecture::Aarch64,
            _ => return Ok(None),
        };
        let target = SoftwareTarget::new(platform, architecture);
        let Some(pin) = self.agent_installation.packages.get(&target) else {
            return Ok(None);
        };
        let identity = match &pin.identity {
            Identity::Windows { product, .. } => product.to_string(),
            Identity::Macos { bundle, .. } => bundle.clone(),
        };
        if evidence.identity != identity {
            return Ok(None);
        }
        // One installation per source registration, shared across overlapping policies and revisions.
        // Repeated inventory and unknown delivery never create another installer execution.
        let tenant = tx.tenant_id().to_string();
        let old=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND registration=$2 AND registration_generation=$3 AND request->'task'->>'kind'='agent_install')").bind(tenant).bind(registration).bind(generation).fetch_one(c).await})).await?;
        if old {
            return Ok(None);
        }
        let now = storage::now(tx).await?;
        let mut candidate = None;
        let mut digest = None;
        let mut after = Uuid::nil();
        loop {
            let tenant = tx.tenant_id().to_string();
            let name = device.to_owned();
            let rows=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT p.id,p.current_version,mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state' AS admission FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.id>$3 AND p.definition->'action'->>'kind'='ensure_agent_installed' AND mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded' ORDER BY p.id LIMIT 64").bind(tenant).bind(name).bind(after).fetch_all(c).await})).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let id: Uuid = row.try_get("id")?;
                after = id;
                let version: Uuid = row.try_get("current_version")?;
                let (_, Frozen::AgentInstall { action }) =
                    policies::storage::version_in(&self.policy_reader, tx, version).await?
                else {
                    return Err(Error::Malformed.into());
                };
                let Some(package) = action.packages.get(&target) else {
                    continue;
                };
                if package.identity != pin.identity
                    || package.artifact.sha256 != pin.sha256
                    || package.version != pin.version
                {
                    return Ok(None);
                }
                let fingerprint = crate::transaction::fingerprint(package)?;
                if digest.as_ref().is_some_and(|old| old != &fingerprint) {
                    return Ok(None);
                }
                digest = Some(fingerprint);
                if row.try_get::<String, _>("admission")? != "eligible" {
                    return Ok(None);
                }
                if now < action.schedule.not_before || now >= action.schedule.ends_at() {
                    continue;
                }
                let identity = format!("{registration}:{version}");
                let mut trigger_deadline = i64::MAX;
                let occurrence = match action.schedule.trigger {
                    Trigger::Manual => {
                        let tenant = tx.tenant_id().to_string();
                        let at=tx.with_connection(move|c|Box::pin(async move{sqlx::query_as::<_,(i64,i64)>("SELECT created_at,deadline FROM mdm_policy.triggers WHERE tenant_id=$1::uuid AND version=$2 AND deadline>$3 ORDER BY created_at,id LIMIT 1").bind(tenant).bind(version).bind(now).fetch_optional(c).await})).await?;
                        if let Some((at, end)) = at {
                            trigger_deadline = end;
                            action.schedule.occurrence(at, identity.as_bytes())?
                        } else {
                            None
                        }
                    }
                    Trigger::Registration | Trigger::CheckIn { .. } => action.schedule.occurrence(
                        fact.received_at.max(action.schedule.not_before),
                        identity.as_bytes(),
                    )?,
                    _ => action.schedule.due(-1, now, identity.as_bytes())?,
                };
                let Some(occurrence) = occurrence.filter(|o| {
                    o.available_at <= now
                        && o.window_end.is_none_or(|end| now < end)
                        && !action.schedule.missed(o.available_at, now)
                }) else {
                    continue;
                };
                let deadline = now
                    .checked_add(i64::from(action.run_lifetime_seconds))
                    .ok_or(Error::Malformed)?
                    .min(action.schedule.ends_at())
                    .min(occurrence.window_end.unwrap_or(i64::MAX))
                    .min(trigger_deadline);
                if deadline > now && candidate.is_none() {
                    candidate = Some((id, version, package.clone(), deadline));
                }
            }
        }
        Ok(candidate)
    }
}
impl ExecutionService {
    /// Opaque operation locates a fixed public package; it carries no enrollment authority.
    pub async fn installation_content(
        &self,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_content_service::Verified, Error> {
        let artifact = self.installation_artifact(id, audit).await?;
        let verified = self
            .content
            .as_ref()
            .ok_or(Error::Unsupported)?
            .verify(&artifact)
            .await?;
        if !verified.matches(&self.installation_artifact(id, audit).await?) {
            return Err(Error::Conflict);
        }
        Ok(verified)
    }
    async fn installation_artifact(
        &self,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_resource::Artifact, Error> {
        audit.require_request_settlement();
        audit.identify_service("native-package-download");
        audit.operation(id, "agent_content");
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, id),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, id) = *ctx;
                    let tenant = s.tenant.to_string();
                    let instance = s.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    crate::transaction::lock(tx).await?;
                    let op = storage::load(tx, id).await?;
                    storage::lock(tx, &op.device).await?;
                    let Task::AgentInstall { package } = &op.request.task else {
                        return Err(Error::NotFound.into());
                    };
                    let now = storage::now(tx).await?;
                    let status = s.required_command(tx, &op).await?.status();
                    if now >= op.request.deadline
                        || !matches!(
                            status,
                            dc::Status::Published | dc::Status::Received | dc::Status::Applied
                        )
                        || storage::current_registration(tx, &op.device).await?
                            != (op.registration, op.registration_generation)
                        || !storage::approval_valid(tx, &op, now).await?
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let tenant = s.tenant.to_string();
                    if !tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(policies::agent_install::dispatched_on(c, &tenant, id).await)
                            })
                        })
                        .await??
                    {
                        return Err(Error::Forbidden.into());
                    }
                    package
                        .artifact
                        .artifact()
                        .map_err(|_| Error::Malformed.into())
                })
            },
            crate::transaction::TransactionOwner::Execution,
        )
        .await
    }
}
impl ExecutionService {
    async fn settle_agent_install_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<()> {
        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let ids=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.registration_generation) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND r.state='active' AND o.request->'task'->>'kind'='agent_install' AND d.status IN('published','received') ORDER BY o.id LIMIT 64").bind(tenant).bind(name).fetch_all(c).await})).await?;
        for id in ids {
            let op = storage::load(tx, id).await?;
            let now = storage::now(tx).await?;
            if now >= op.request.deadline || !storage::approval_valid(tx, &op, now).await? {
                continue;
            }
            let observation = installation_observation(
                tx,
                self.apple_store.clone(),
                self.agent_store.clone(),
                &op,
            )
            .await?;
            let event = match observation["installation"].as_str() {
                Some("installed") => dc::DeviceEvent::Reported(
                    op.request.digest(&self.tenant.to_string(), &op.device)?,
                ),
                Some("failed") => dc::DeviceEvent::Rejected,
                _ => continue,
            };
            let report = dc::DeviceReport {
                scope: op.scope,
                command_id: op.command_id()?,
                coordinate: op.coordinate,
                event,
            };
            if matches!(report.event, dc::DeviceEvent::Reported(_))
                && self.required_command(tx, &op).await?.status() == dc::Status::Published
                && self
                    .store
                    .report(
                        tx,
                        &dc::DeviceReport {
                            scope: op.scope,
                            command_id: op.command_id()?,
                            coordinate: op.coordinate,
                            event: dc::DeviceEvent::Received,
                        },
                    )
                    .await?
                    .outcome
                    == dc::Outcome::OutOfOrder
            {
                return Err(Error::Conflict.into());
            }
            if self.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
                return Err(Error::Conflict.into());
            }
        }
        Ok(())
    }
}
pub async fn installation_observation(
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn channels::AppleStore>,
    agent: Arc<dyn channels::Agent>,
    op: &storage::Operation,
) -> Result<serde_json::Value> {
    let Task::AgentInstall { package } = &op.request.task else {
        return Err(Error::Malformed.into());
    };
    let tenant = tx.tenant_id();
    let registration = op.registration;
    let generation = op.registration_generation;
    let source = op.request.task.source();
    let operation = op.id;
    let current = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    crate::assets::channel::detail_in(c, tenant, registration, generation, source)
                        .await,
                )
            })
        })
        .await??;
    let mut installation = "unknown";
    let mut delivery = "unknown";
    let mut observed_at = None;
    let sent = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(policies::agent_install::dispatched_on(c, &tenant.to_string(), operation).await)
            })
        })
        .await??;
    let mut after_dispatch = false;
    if let Some(fact) = &current
        && let Identity::Windows { product, publisher } = &package.identity
    {
        let snapshot = fact.snapshot;
        let product = product.to_string();
        let publisher = publisher.clone();
        let query=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,serde_json::Value>("SELECT q.channel_state FROM mdm_windows.collections q JOIN mdm_commands.attempts a ON a.tenant_id=q.tenant_id AND a.operation=$2 AND a.phase='execute' WHERE q.tenant_id=$1::uuid AND q.id=$3 AND q.registration=$4 AND q.first_command>a.command AND q.channel_state->>'product'=$5 AND q.channel_state->>'publisher'=$6").bind(tenant.to_string()).bind(operation).bind(snapshot).bind(registration).bind(product).bind(publisher).fetch_optional(c).await
        })).await?;
        after_dispatch = sent && query.is_some();
        if after_dispatch {
            observed_at = Some(fact.received_at);
            if fact.state == "absent" {
                installation = "absent";
            }
            if let Some(query) = query
                && query["statuses"][0] == 200
                && let Some(status) = query["values"][0].as_str()
            {
                use rss_mdm_windows_mdm::agent_install::{Progress, progress};
                installation = match progress(status) {
                    Progress::Installing => "installing",
                    Progress::UserRequired => "user_required",
                    Progress::Failed => "failed",
                    _ => "unknown",
                };
            }
        }
    }
    if after_dispatch
        && let Some(fact) = &current
        && fact.state == "installed"
        && fact.evidence.as_ref().is_some_and(|e| {
            e.version.as_deref() == Some(package.version.as_str())
                && match &package.identity {
                    Identity::Windows { product, publisher } => {
                        e.identity == product.to_string() && e.publisher.as_ref() == Some(publisher)
                    }
                    Identity::Macos { bundle, .. } => e.identity == *bundle,
                }
        })
    {
        installation = "installed";
    }
    if matches!(package.identity, Identity::Macos { .. }) {
        let rows = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(apple.observations(c, tenant.to_string(), operation).await) },
                )
            })
            .await?
            .map_err(Error::from)?;
        for row in rows {
            if row.phase == "execute" {
                delivery = match row.state.as_str() {
                    "acknowledged" => "acknowledged",
                    "error" => "rejected",
                    "not_now" => "deferred",
                    _ => "unknown",
                };
            } else if row.phase == "observe"
                && let Some(bytes) = row.response
                && let Identity::Macos { bundle, .. } = &package.identity
            {
                let d = rss_mdm_apple_mdm::protocol::decode(&bytes).map_err(Error::from)?;
                observed_at = row.received_at;
                installation = match if row.state == "acknowledged" {
                    rss_mdm_apple_mdm::agent_install::presence(&d, bundle)
                } else {
                    Err(rss_mdm_apple_mdm::Error::Malformed)
                } {
                    Ok(rss_mdm_apple_mdm::agent_install::Presence::Installed { version })
                        if version == package.version =>
                    {
                        "installed"
                    }
                    Ok(rss_mdm_apple_mdm::agent_install::Presence::Installing) => "installing",
                    Ok(rss_mdm_apple_mdm::agent_install::Presence::Absent) => "absent",
                    _ => "unknown",
                };
            }
        }
    } else {
        let status=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Option<i32>>("SELECT status FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND (phase='execute' OR(phase='prepare' AND status>=400)) AND receipt_accepted ORDER BY ordinal DESC LIMIT 1").bind(tenant.to_string()).bind(operation).fetch_optional(c).await})).await?.flatten();
        delivery = match status {
            Some(200 | 202) => "acknowledged",
            Some(n) if n >= 400 => "rejected",
            _ => "unknown",
        };
    }
    let bound=tx.with_connection(move|c|Box::pin(async move{sqlx::query_as::<_,(Uuid,String,String)>("SELECT r.id,r.device,r.state FROM mdm_access.requests e JOIN mdm_access.registrations r ON(r.tenant_id,r.request_id)=(e.tenant_id,e.id) WHERE e.tenant_id=$1::uuid AND e.authority_kind='managed_installation' AND e.issuance_operation=$2").bind(tenant.to_string()).bind(operation).fetch_optional(c).await})).await?;
    let registered = if let Some((id, device, state)) = bound {
        let profile = channels::agent_binding_in(tx, agent, id).await?;
        serde_json::json!({"deviceId":device,"registrationId":id,"state":state,"capabilities":profile.map(|p|p.capabilities)})
    } else {
        serde_json::Value::Null
    };
    Ok(
        serde_json::json!({"protocol":source.as_str(),"delivery":delivery,"installation":installation,"agentRegistration":registered,"observedAt":observed_at}),
    )
}
