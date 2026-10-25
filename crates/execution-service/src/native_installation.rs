//! Fixed Agent installation shares native reconciliation and command authority.
use super::*;
use crate::sources as policies;
use crate::{
    agent_install::{Identity, Package},
    frozen::Frozen,
};
use rss_mdm_inventory::ReportSource;
use rss_mdm_policy::{Architecture, Platform, SoftwareTarget, schedule::Trigger};

impl ExecutionService {
    pub async fn reconcile_agent_install_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.recover_bootstrap_in(tx, device, audit).await?;
        self.cleanup_bootstrap_in(tx, device, audit).await?;
        self.settle_agent_install_in(tx, device).await?;
        let Some((policy, version, package, deadline)) =
            self.agent_install_candidate_in(tx, device).await?
        else {
            return Ok(());
        };
        let tenant = tx.tenant_id();
        let download_origin = tx.with_connection(move |c| Box::pin(async move {
            Ok(rss_mdm_registration_service::agent::connections::installation_configuration_on(c, &tenant.to_string()).await
                .map(|v| v.configuration.preferred_origin).map_err(Error::from))
        })).await??;
        let operation_id = Uuid::new_v4();
        let input = Create {
            operation_id,
            deadline,
            input_version: version.to_string(),
            target: NativeTarget::Device,
            task: package.native_task(operation_id, &download_origin)?,
        };
        let authority = authority::ExecutionAuthority::AgentInstall {
            stage: authority::AgentInstallStage::Install,
            source_objects: vec![],
            required: input.task.permissions()?,
            package: Box::new(package),
            download_origin,
            tenant: tx.tenant_id().to_string(),
            policy,
            version,
            device: device.into(),
            operation: input.operation_id,
        };
        let now = storage::now(tx).await?;
        let check = authority.clone();
        let protection = self.protection.clone();
        let source = self.source.clone();
        if !tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(check
                        .valid(
                            source.as_ref(),
                            c,
                            &protection,
                            &[crate::authorization::Permission::SoftwareDeploy],
                            now,
                        )
                        .await)
                })
            })
            .await??
        {
            return Ok(());
        }
        let fact_audit = audit.transaction_copy();
        fact_audit.identify_service("agent-install-policy");
        fact_audit.operation(
            input.operation_id,
            "command_accept",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        fact_audit.target_device(device);
        let result = self
            .queue_authorized_in(
                tx,
                device,
                &input,
                authority,
                crate::protection::fingerprint(
                    &self.protection,
                    self.tenant,
                    device,
                    "agent-install-command/v1",
                    &(&input, policy, version),
                )?,
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
        self.queue_bootstrap_in(tx, device, operation_id, audit)
            .await?;
        let target = service::target(tx.tenant_id(), device);
        self.reconcile_messaging
            .wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
            .await?;
        Ok(())
    }
    async fn agent_install_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<Option<(Uuid, Uuid, Package, i64)>> {
        let (registration, generation) = match storage::current_registration(
            tx,
            device,
            rss_mdm_registration_service::Purpose::Primary,
        )
        .await
        {
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
        // One installation per source registration, shared across overlapping policies and revisions.
        // Repeated inventory and unknown delivery never create another installer execution.
        let tenant = tx.tenant_id().to_string();
        let old=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND registration=$2 AND registration_generation=$3 AND authority->>'kind'='agent_install')").bind(tenant).bind(registration).bind(generation).fetch_one(c).await})).await?;
        if old {
            return Ok(None);
        }
        let now = storage::now(tx).await?;
        let mut candidate = None;
        let mut digest = None;
        let mut after = Uuid::nil();
        loop {
            let tenant = tx.tenant_id();
            let name = device.to_owned();
            let source = self.source.clone();
            let rows = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .candidates_on(
                                c,
                                tenant,
                                &name,
                                crate::source_authority::CandidateKind::AgentInstall,
                                after,
                            )
                            .await)
                    })
                })
                .await??;
            let more = rows.has_more;
            after = rows.scanned_after;

            for row in rows.items {
                let id = row.policy;

                let version = row.version;
                let (_, Frozen::AgentInstall { action }) =
                    policies::storage::version_in(&self.policy_reader, tx, version).await?
                else {
                    return Err(Error::Malformed.into());
                };
                let Some(package) = action.packages.get(&target) else {
                    continue;
                };
                if !evidence.matches(&package.detection_identity()) {
                    return Ok(None);
                }
                let fingerprint = crate::transaction::fingerprint(package)?;
                if digest.as_ref().is_some_and(|old| old != &fingerprint) {
                    return Ok(None);
                }
                digest = Some(fingerprint);
                if !matches!(
                    row.admission,
                    crate::source_authority::ScopeAdmission::Eligible { .. }
                ) {
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
            if !more {
                break;
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
        audit.identify_service("native-package-download");
        audit.operation(
            id,
            "agent_content",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        crate::transaction::inspect(&self.runtime, self.tenant, (self, id), |ctx, tx| {
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
                let op = storage::load(tx, &s.protection, id).await?;
                storage::lock(tx, &op.device).await?;
                let Some(package) = op.authority.agent_package() else {
                    return Err(Error::NotFound.into());
                };
                let now = s.installation_authorization_time(storage::now(tx).await?);
                let status = s.required_command(tx, &op).await?.status();
                if now >= op.request.deadline
                    || !matches!(
                        status,
                        dc::Status::Published | dc::Status::Received | dc::Status::Applied
                    )
                    || storage::current_registration(
                        tx,
                        &op.device,
                        rss_mdm_registration_service::Purpose::Primary,
                    )
                    .await?
                        != (op.registration, op.registration_generation)
                    || !storage::authority_valid(&s.source, &s.protection, tx, &op, now).await?
                {
                    return Err(Error::Forbidden.into());
                }
                let tenant = s.tenant.to_string();
                if !tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::agent_install::dispatched_on(c, &tenant, id).await)
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
        })
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
        let ids=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.registration_generation) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND r.state='active' AND o.authority->>'kind'='agent_install' AND o.authority->>'stage'='install' AND d.status IN('published','received') ORDER BY o.id LIMIT 64").bind(tenant).bind(name).fetch_all(c).await})).await?;
        for id in ids {
            let op = storage::load(tx, &self.protection, id).await?;
            let now = storage::now(tx).await?;
            if now >= op.request.deadline
                || !storage::authority_valid(&self.source, &self.protection, tx, &op, now).await?
            {
                continue;
            }
            let observation = installation_observation(
                tx,
                self.apple_results.clone(),
                self.agent_store.clone(),
                &op,
            )
            .await?;
            let event = match observation["installation"].as_str() {
                Some("installed") => dc::DeviceEvent::Reported(op.request.digest(
                    &self.protection,
                    self.tenant,
                    &op.device,
                )?),
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
    apple: Arc<dyn channels::AppleResults>,
    agent: Arc<dyn channels::Agent>,
    op: &storage::Operation,
) -> Result<serde_json::Value> {
    installation_observations(tx, apple, agent, &[op])
        .await?
        .remove(&op.id)
        .ok_or(Error::Conflict.into())
}
pub(crate) async fn installation_observations(
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn channels::AppleResults>,
    agent: Arc<dyn channels::Agent>,
    ops: &[&storage::Operation],
) -> Result<std::collections::BTreeMap<Uuid, serde_json::Value>> {
    use sqlx::Row;
    if ops.is_empty() {
        return Ok(Default::default());
    }
    if ops.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let tenant = tx.tenant_id();
    let targets = ops
        .iter()
        .map(|op| {
            (
                op.registration,
                op.registration_generation,
                op.request.task.source(),
            )
        })
        .collect::<Vec<_>>();
    let current = tx
        .with_connection(move |c| {
            Box::pin(
                async move { Ok(crate::assets::channel::details_in(c, tenant, &targets).await) },
            )
        })
        .await??;
    let inputs=ops.iter().map(|op|serde_json::json!({"operation":op.id,"snapshot":current.get(&(op.registration,op.registration_generation,op.request.task.source().as_str().to_owned())).map(|f|f.snapshot)})).collect::<Vec<_>>();
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(INSTALLATION_PAGE)
                    .bind(tenant.to_string())
                    .bind(serde_json::json!(inputs))
                    .fetch_all(c)
                    .await
            })
        })
        .await?;
    rss_mdm_query_postgres::observe_rows("execution.installation", &rows)?;
    let mut metadata = std::collections::BTreeMap::new();
    let mut registrations = Vec::new();
    for row in rows {
        if !row.try_get::<bool, _>("within_budget")? {
            return Err(Error::Conflict.into());
        }
        if let Some(operation) = row.try_get::<Option<Uuid>, _>("operation")? {
            if let Some(id) = row.try_get::<Option<Uuid>, _>("agent_registration")? {
                registrations.push(id);
            }
            metadata.insert(operation, row);
        }
    }
    let profiles = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(agent.bindings(c, tenant.to_string(), registrations).await) })
        })
        .await?
        .map_err(Error::from)?;
    let requests = ops
        .iter()
        .filter_map(|op| match &op.request.task {
            Task::Macos { request } => Some((op.id, request.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut apple = if requests.is_empty() {
        Default::default()
    } else {
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(apple
                    .evidence_page(c, tenant.to_string(), requests, false)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?
    };
    let mut output = std::collections::BTreeMap::new();
    for op in ops {
        let row = metadata.remove(&op.id).ok_or(Error::Conflict)?;
        let agent_id: Option<Uuid> = row.try_get("agent_registration")?;
        let bound = agent_id
            .map(|id| {
                Ok::<_, sqlx::Error>((
                    id,
                    row.try_get::<String, _>("agent_device")?,
                    row.try_get::<String, _>("agent_state")?,
                ))
            })
            .transpose()?;
        let profile = agent_id.and_then(|id| profiles.get(&id).map(|p| p.capabilities.clone()));
        let rows = match apple.remove(&op.id) {
            Some(channels::AppleEvidence::Observations(rows)) => rows,
            None => Vec::new(),
            _ => return Err(Error::Malformed.into()),
        };
        let facts = InstallationFacts {
            current: current
                .get(&(
                    op.registration,
                    op.registration_generation,
                    op.request.task.source().as_str().to_owned(),
                ))
                .cloned(),
            sent: row.try_get("sent")?,
            query: row.try_get("channel_state")?,
            status: row.try_get("delivery_status")?,
            bound,
            bootstrap: row.try_get("bootstrap")?,
            profile,
            rows,
        };
        output.insert(op.id, installation_from_facts(op, facts)?);
    }
    Ok(output)
}
struct InstallationFacts {
    current: Option<crate::assets::channel::Current>,
    sent: bool,
    query: Option<serde_json::Value>,
    status: Option<i32>,
    bound: Option<(Uuid, String, String)>,
    bootstrap: Option<serde_json::Value>,
    profile: Option<Vec<rss_mdm_agent_wire::runtime::Capability>>,
    rows: Vec<rss_mdm_apple_mdm::native::evidence::Observation>,
}
fn installation_from_facts(
    op: &storage::Operation,
    facts: InstallationFacts,
) -> Result<serde_json::Value> {
    let InstallationFacts {
        current,
        sent,
        query,
        status,
        bound,
        bootstrap,
        profile,
        rows,
    } = facts;
    let Some(package) = op.authority.agent_package() else {
        return Err(Error::Malformed.into());
    };
    let source = op.request.task.source();
    let mut installation = "unknown";
    let mut delivery = "unknown";
    let mut observed_at = None;
    if let Some(fact) = &current
        && matches!(
            package.identity,
            Identity::WindowsMsi { .. } | Identity::WindowsMsix { .. }
        )
    {
        let after_dispatch = sent && query.is_some();
        if after_dispatch {
            observed_at = Some(fact.received_at);
            if fact.state == "absent"
                && fact
                    .evidence
                    .as_ref()
                    .is_some_and(|e| e.matches(&package.detection_identity()))
            {
                installation = "absent";
            }
            if let Some(query) = query {
                let key = package.detection_identity();
                if let Some(probe) = query["probes"].as_array().and_then(|items| {
                    items.iter().find(|p| {
                        p["identity"]["product"].as_str() == Some(key.as_str())
                            || p["identity"]["family"].as_str() == Some(key.as_str())
                    })
                }) && let Some(offset) = probe["offset"]
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    && query["statuses"][offset] == 200
                    && let Some(status) = query["values"][offset].as_str()
                {
                    installation = match &package.identity {
                        Identity::WindowsMsix { .. } => match status {
                            "0" => "pending",
                            "1" => "installing",
                            "2" => "failed",
                            _ => "unknown",
                        },
                        _ => match rss_mdm_windows_mdm::software::progress(status) {
                            rss_mdm_windows_mdm::software::Progress::Installing => "installing",
                            rss_mdm_windows_mdm::software::Progress::UserRequired => {
                                "user_required"
                            }
                            rss_mdm_windows_mdm::software::Progress::Failed => "failed",
                            _ => "unknown",
                        },
                    };
                }
            }
            if let Some(e) = &fact.evidence
                && e.identity == package.detection_identity()
            {
                match &package.identity {
                    Identity::WindowsMsi { publisher, .. }
                        if fact.state == "installed"
                            && publisher
                                .as_ref()
                                .is_none_or(|p| e.publisher.as_ref() == Some(p))
                            && e.version.as_deref() == Some(package.version.as_str()) =>
                    {
                        installation = "installed"
                    }
                    Identity::WindowsMsix { identity, .. }
                        if e.provisioned
                            && e.publisher.as_ref() == Some(&identity.publisher)
                            && e.version.as_deref()
                                == Some(
                                    identity
                                        .version
                                        .iter()
                                        .map(u16::to_string)
                                        .collect::<Vec<_>>()
                                        .join(".")
                                        .as_str(),
                                ) =>
                    {
                        installation = "provisioned"
                    }
                    _ => (),
                }
            }
        }
    }
    if matches!(package.identity, Identity::Macos { .. }) {
        use rss_mdm_apple_mdm::native::evidence::{Phase, ReceiptState};
        for row in rows {
            if row.phase == Phase::Execute {
                delivery = match row.state {
                    ReceiptState::Acknowledged => "acknowledged",
                    ReceiptState::Error => "rejected",
                    ReceiptState::NotNow => "deferred",
                    _ => "unknown",
                };
            } else if row.phase == Phase::Observe {
                observed_at = row.received_at;
                installation = match row.application {
                    Some(rss_mdm_apple_mdm::software::Presence::Installing) => "installing",
                    Some(rss_mdm_apple_mdm::software::Presence::Absent) => "absent",
                    _ => "unknown",
                };
            }
        }
    } else {
        delivery = match status {
            Some(200 | 202) => "acknowledged",
            Some(n) if n >= 400 => "rejected",
            _ => "unknown",
        };
    }
    let registered = if let Some((id, device, state)) = bound {
        serde_json::json!({"deviceId":device,"registrationId":id,"state":state,"capabilities":profile})
    } else {
        serde_json::Value::Null
    };
    Ok(
        serde_json::json!({"protocol":source.as_str(),"delivery":delivery,"installation":installation,"agentRegistration":registered,"bootstrap":bootstrap,"observedAt":observed_at}),
    )
}

const INSTALLATION_PAGE: &str = r#"
WITH selected AS MATERIALIZED (
 SELECT o.id AS operation,
 EXISTS(SELECT FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND a.phase='execute') OR EXISTS(SELECT FROM mdm_apple.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND a.phase='execute' AND a.state<>'pending') AS sent,
 (SELECT q.channel_state FROM mdm_windows.collections q JOIN mdm_commands.attempts a ON a.tenant_id=q.tenant_id AND a.operation=o.id AND a.phase='execute' JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE q.tenant_id=o.tenant_id AND q.id=x.snapshot AND q.registration=o.registration AND q.first_command>i.command LIMIT 1) AS channel_state,
 (SELECT i.status FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND (a.phase='execute' OR(a.phase='prepare' AND i.status>=400)) AND i.receipt_accepted ORDER BY a.ordinal DESC,i.command DESC LIMIT 1) AS delivery_status,
 r.id AS agent_registration,r.device AS agent_device,r.state AS agent_state,
 (SELECT jsonb_build_object('state',state,'delivery',delivery,'cleanup',cleanup,'cleanupComplete',cleanup_complete,'cleanupRetryAt',cleanup_retry_at,'deadline',deadline) FROM mdm_access.agent_bootstraps WHERE tenant_id=o.tenant_id AND installation=o.id AND active) AS bootstrap
 FROM jsonb_to_recordset($2::jsonb) x(operation uuid,snapshot uuid) JOIN mdm_commands.operations o ON o.tenant_id=$1::uuid AND o.id=x.operation
 LEFT JOIN LATERAL(SELECT r.id,r.device,r.state FROM mdm_access.agent_grants e JOIN mdm_access.registrations r ON(r.tenant_id,r.agent_grant_id)=(e.tenant_id,e.id) WHERE e.tenant_id=o.tenant_id AND e.source='native' AND e.native_authority->>'installation'=o.id::text ORDER BY r.id LIMIT 1) r ON true
), budget AS (SELECT coalesce(sum(pg_column_size(selected)),0)<=16777216 AS ok FROM selected)
SELECT selected.*,budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok
"#;
