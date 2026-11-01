//! Fixed Agent installation shares native reconciliation and command authority.
use super::*;
use crate::deployment::agent_facts;
use crate::deployment::frozen::Published;
use crate::deployment::sources as policies;
use crate::installation::package::{Identity, Package};
use rss_mdm_inventory::ReportSource;
use rss_mdm_policy::{Architecture, Platform, SoftwareTarget, schedule::Trigger};
use rss_mdm_registration_service::installation::queries::{
    AgentRegistration, BootstrapObservation, installations_on,
};

impl SoftwareService {
    /// Opaque operation locates a fixed public package; it carries no enrollment authority.
    pub async fn installation_artifact(
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
        crate::deployment::transaction::inspect(
            &self.transactions.runtime,
            self.transactions.tenant,
            (self, id),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, id) = *ctx;
                    let tenant = s.transactions.tenant.to_string();
                    let instance = s.transactions.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::deployment::authorization::lock_shared_on(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                &tenant,
                                &instance,
                            )
                            .await)
                        })
                    })
                    .await??;
                    let op = storage::load(tx, &s.transactions.protection, id).await?;
                    storage::lock_device(tx, &op.device).await?;
                    let Some(package) = op.authority.agent_package() else {
                        return Err(Error::NotFound.into());
                    };
                    let now = s
                        .transactions
                        .installation_authorization_time(storage::now(tx).await?);
                    let status = s.transactions.required_command(tx, &op).await?.status();
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
                        || !storage::authority_decision(
                            &s.transactions.source,
                            &s.transactions.lifecycle,
                            &s.transactions.protection,
                            tx,
                            &op,
                            now,
                        )
                        .await?
                        .is_authorized()
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let tenant = s.transactions.tenant.to_string();
                    if !tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(
                                    crate::deployment::agent_install::dispatched_on(c, &tenant, id)
                                        .await,
                                )
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
        )
        .await
    }
}
pub async fn installation_observation(
    inventory: Arc<dyn crate::deployment::inventory::Inventory>,
    tx: &mut PgTransaction<'_>,
    windows: Arc<dyn crate::deployment::windows_results::Store>,
    apple: Arc<dyn apple_facts::AppleResults>,
    agent: Arc<dyn agent_facts::Store>,
    op: &storage::Operation,
) -> Result<serde_json::Value> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(
        &mut (windows, apple, agent, op, inventory),
        move |args, c| {
            Box::pin(async move {
                Ok(installation_observation_on(
                    args.4.clone(),
                    c,
                    tenant,
                    args.0.clone(),
                    args.1.clone(),
                    args.2.clone(),
                    args.3,
                    true,
                )
                .await)
            })
        },
    )
    .await?
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
)]
pub async fn installation_observation_on(
    inventory: Arc<dyn crate::deployment::inventory::Inventory>,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    windows: Arc<dyn crate::deployment::windows_results::Store>,
    apple: Arc<dyn apple_facts::AppleResults>,
    agent: Arc<dyn agent_facts::Store>,
    op: &storage::Operation,
    lock: bool,
) -> Result<serde_json::Value> {
    installation_observations_on(inventory, c, tenant, windows, apple, agent, &[op], lock)
        .await?
        .remove(&op.id)
        .ok_or(Error::Conflict.into())
}
#[expect(
    clippy::too_many_arguments,
    reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
)]
pub(crate) async fn installation_observations_on(
    inventory: Arc<dyn crate::deployment::inventory::Inventory>,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    windows: Arc<dyn crate::deployment::windows_results::Store>,
    apple: Arc<dyn apple_facts::AppleResults>,
    agent: Arc<dyn agent_facts::Store>,
    ops: &[&storage::Operation],
    lock: bool,
) -> Result<std::collections::BTreeMap<Uuid, serde_json::Value>> {
    use sqlx::Row;
    if ops.is_empty() {
        return Ok(Default::default());
    }
    if ops.len() > 1000 {
        return Err(Error::Malformed.into());
    }
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
    let current = inventory.details_on(c, tenant, &targets, lock).await?;
    let requests = ops
        .iter()
        .filter(|op| matches!(op.request.task, Task::Windows { .. }))
        .map(|op| crate::deployment::windows_results::InstallationRead {
            id: op.id,
            registration: op.registration,
            generation: op.registration_generation,
            snapshot: current
                .get(&(
                    op.registration,
                    op.registration_generation,
                    op.request.task.source().as_str().to_owned(),
                ))
                .and_then(|f| match f {
                    rss_mdm_inventory::channel::Observation::Ready(f) => Some(f.snapshot),
                    _ => None,
                }),
        })
        .collect();
    let mut windows = windows.installations(c, tenant, requests).await?;
    let rows = {
        let c = &mut *c;
        sqlx::query(INSTALLATION_PAGE)
            .bind(tenant.to_string())
            .bind(ops.iter().map(|op| op.id).collect::<Vec<_>>())
            .fetch_all(c)
            .await
    }?;
    rss_mdm_query_postgres::observe_rows("software.installation", &rows)?;
    let mut metadata = std::collections::BTreeMap::new();
    for row in rows {
        if !row.try_get::<bool, _>("within_budget")? {
            return Err(Error::Conflict.into());
        }
        if let Some(operation) = row.try_get::<Option<Uuid>, _>("operation")? {
            metadata.insert(operation, row);
        }
    }
    let mut observations =
        installations_on(c, tenant, &ops.iter().map(|op| op.id).collect::<Vec<_>>()).await?;
    let registrations = observations
        .values()
        .filter_map(|v| v.registration.as_ref().map(|r| r.id))
        .collect();
    let profiles = agent.bindings(c, tenant.to_string(), registrations).await?;
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
        apple
            .evidence_page(c, tenant.to_string(), requests, false)
            .await?
    };
    let mut output = std::collections::BTreeMap::new();
    for op in ops {
        let row = metadata.remove(&op.id).ok_or(Error::Conflict)?;
        let observation = observations.remove(&op.id).ok_or(Error::Conflict)?;
        let bound = observation.registration;
        let agent_id = bound.as_ref().map(|r| r.id);
        let profile = agent_id.and_then(|id| profiles.get(&id).map(|p| p.capabilities.clone()));
        let rows = match apple.remove(&op.id) {
            Some(apple_facts::AppleEvidence::Observations(rows)) => rows,
            None => Vec::new(),
            _ => return Err(Error::Malformed.into()),
        };
        let windows = windows.remove(&op.id).unwrap_or_default();
        let facts = InstallationFacts {
            current: current
                .get(&(
                    op.registration,
                    op.registration_generation,
                    op.request.task.source().as_str().to_owned(),
                ))
                .and_then(|fact| match fact {
                    rss_mdm_inventory::channel::Observation::Ready(fact) => Some(fact.clone()),
                    rss_mdm_inventory::channel::Observation::ProjectionPending { .. }
                    | rss_mdm_inventory::channel::Observation::Unavailable => None,
                }),
            sent: row.try_get("sent")?,
            query: windows.channel_state,
            delivery: windows.delivery,
            bound,
            bootstrap: observation.bootstrap,
            profile,
            rows,
        };
        output.insert(op.id, installation_from_facts(op, facts)?);
    }
    Ok(output)
}
struct InstallationFacts {
    current: Option<rss_mdm_inventory::channel::Current>,
    sent: bool,
    query: Option<serde_json::Value>,
    delivery: crate::deployment::windows_results::InstallationDelivery,
    bound: Option<AgentRegistration>,
    bootstrap: Option<BootstrapObservation>,
    profile: Option<Vec<rss_mdm_agent_wire::runtime::Capability>>,
    rows: Vec<rss_mdm_apple_mdm::native::evidence::Observation>,
}
#[expect(
    clippy::cognitive_complexity,
    reason = "delivery, bootstrap, observed installation and Agent registration remain distinct facts"
)]
fn installation_from_facts(
    op: &storage::Operation,
    facts: InstallationFacts,
) -> Result<serde_json::Value> {
    let InstallationFacts {
        current,
        sent,
        query,
        delivery: windows_delivery,
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
        delivery = match windows_delivery {
            crate::deployment::windows_results::InstallationDelivery::Acknowledged => {
                "acknowledged"
            }
            crate::deployment::windows_results::InstallationDelivery::Rejected => "rejected",
            crate::deployment::windows_results::InstallationDelivery::Unknown => "unknown",
        };
    }
    let registered = if let Some(registration) = bound {
        serde_json::json!({"deviceId":registration.device,"registrationId":registration.id,"state":registration.state,"capabilities":profile})
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
 EXISTS(SELECT FROM mdm_windows.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND a.phase='execute') OR EXISTS(SELECT FROM mdm_apple.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND a.phase='execute' AND a.state<>'pending') AS sent
 FROM mdm_software_deployment.operations o
 WHERE o.tenant_id=$1::uuid AND o.id=ANY($2)
), budget AS (SELECT coalesce(sum(pg_column_size(selected)),0)<=16777216 AS ok FROM selected)
SELECT selected.*,budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok
"#;

impl crate::deployment::transactions::Transactions {
    pub async fn reconcile_agent_install_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.reconcile_agent_install_trigger_in(tx, device, audit, None)
            .await
            .map(|_| ())
    }
    pub(crate) async fn reconcile_agent_install_trigger_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
        event: Option<(
            Uuid,
            i64,
            rss_mdm_audit_integration::activity::ActivityOrigin,
        )>,
    ) -> Result<Option<Uuid>> {
        self.bootstrap
            .recover_bootstrap_in(tx, device, audit)
            .await?;
        self.bootstrap
            .cleanup_bootstrap_in(tx, device, audit)
            .await?;
        self.settle_agent_install_in(tx, device).await?;
        let Some((policy, version, package, deadline, reuse_identity)) = self
            .agent_install_candidate_in(tx, device, event.map(|(id, deadline, _)| (id, deadline)))
            .await?
        else {
            return Ok(None);
        };
        let tenant = tx.tenant_id();
        let download_origin = tx.with_connection(move |c| Box::pin(async move {
            Ok(rss_mdm_registration_service::agent::connections::installation_configuration_on(rss_mdm_install_support::StorageProfile::Mdm, c, &tenant.to_string()).await
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
        let authority = authority::Authority::AgentInstall {
            origin: event.map_or(
                rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                |(_, _, origin)| origin,
            ),

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
        let lifecycle = self.lifecycle.clone();
        if !tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(check
                        .valid(
                            source.as_ref(),
                            lifecycle.as_ref(),
                            c,
                            &protection,
                            &[crate::deployment::authorization::Permission::SoftwareDeploy],
                            now,
                        )
                        .await)
                })
            })
            .await??
        {
            return Ok(None);
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
                crate::deployment::protection::fingerprint(
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
        if !reuse_identity {
            self.bootstrap
                .queue_bootstrap_in(tx, operation_id, audit)
                .await?;
        }
        Ok(Some(operation_id))
    }
    #[expect(
        clippy::cognitive_complexity,
        reason = "candidate admission preserves current native evidence and original installation exclusion"
    )]
    pub(crate) async fn agent_install_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        event: Option<(Uuid, i64)>,
    ) -> Result<Option<(Uuid, Uuid, Package, i64, bool)>> {
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
        let Some((rss_mdm_inventory::channel::Observation::Ready(fact), platform)) = self
            .agent_install_fact_in(tx, registration, generation)
            .await?
        else {
            return Ok(None);
        };
        let Some(evidence) = &fact.evidence else {
            return Ok(None);
        };
        let architecture = match evidence.architecture.as_deref() {
            Some("x86_64") => Architecture::X86_64,
            Some("aarch64") => Architecture::Aarch64,
            _ => return Ok(None),
        };
        let target = SoftwareTarget::new(platform, architecture);
        let now = storage::now(tx).await?;
        let tenant = tx.tenant_id().to_string();
        let contact = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_registration_service::installation::queries::native_contact_on(
                            c,
                            &tenant,
                            registration,
                            generation,
                        )
                        .await,
                    )
                })
            })
            .await??;
        let mut candidate = None;
        let mut digest = None;
        let mut after = Uuid::nil();
        loop {
            let tenant = tx.tenant_id();
            let name = device.to_owned();
            let source = self.source.clone();
            let _lifecycle = self.lifecycle.clone();
            let rows = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(crate::deployment::sources::candidates::PolicyCandidates {
                            objects: source.clone(),
                        }
                        .candidates_on(
                            c,
                            tenant,
                            &name,
                            crate::deployment::sources::candidates::CandidateKind::AgentInstall,
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
                let (_, Published::AgentInstall { action }) =
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
                use crate::deployment::agent_install::recovery::{self, Gate, Signal};
                if !matches!(
                    recovery::signal(&fact, package, &contact, now),
                    Signal::Absent | Signal::Unresponsive
                ) {
                    continue;
                }
                let tenant = tx.tenant_id().to_string();
                let snapshot = fact.snapshot;
                let last_contact = contact.last;
                let gate = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(recovery::gate_on(
                                c,
                                &tenant,
                                (registration, generation, version),
                                snapshot,
                                last_contact,
                                now,
                            )
                            .await)
                        })
                    })
                    .await??;
                if gate != Gate::Ready {
                    continue;
                }
                let fingerprint = crate::deployment::transaction::fingerprint(package)?;
                if digest.as_ref().is_some_and(|old| old != &fingerprint) {
                    return Ok(None);
                }
                digest = Some(fingerprint);
                if !matches!(
                    row.admission,
                    crate::deployment::scope::ScopeAdmission::Eligible { .. }
                ) {
                    return Ok(None);
                }
                if now < action.schedule.not_before || now >= action.schedule.ends_at() {
                    continue;
                }
                let identity = format!("{registration}:{version}");
                let mut trigger_deadline = i64::MAX;
                let occurrence = if event.is_some_and(|(policy, _)| policy == id) {
                    trigger_deadline = event.map_or(i64::MAX, |(_, end)| end);
                    action.schedule.occurrence(now, identity.as_bytes())?
                } else {
                    match action.schedule.trigger {
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
                        Trigger::Registration | Trigger::CheckIn { .. } => {
                            action.schedule.occurrence(
                                fact.received_at.max(action.schedule.not_before),
                                identity.as_bytes(),
                            )?
                        }
                        _ => action.schedule.due(-1, now, identity.as_bytes())?,
                    }
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
                if deadline > now
                    && candidate.is_none()
                    && event.is_none_or(|(policy, _)| policy == id)
                {
                    candidate = Some((id, version, package.clone(), deadline, contact.active == 1));
                }
            }
            if !more {
                break;
            }
        }
        Ok(candidate)
    }
    pub(crate) async fn settle_agent_install_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<()> {
        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let ids=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_software_deployment.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.registration_generation) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND r.state='active' AND o.authority->>'kind'='agent_install' AND d.status IN('published','received') ORDER BY o.id LIMIT 64").bind(tenant).bind(name).fetch_all(c).await})).await?;
        for id in ids {
            let op = storage::load(tx, &self.protection, id).await?;
            let now = storage::now(tx).await?;
            if now >= op.request.deadline
                || !storage::authority_decision(
                    &self.source,
                    &self.lifecycle,
                    &self.protection,
                    tx,
                    &op,
                    now,
                )
                .await?
                .is_authorized()
            {
                continue;
            }
            let observation = installation_observation(
                self.inventory.clone(),
                tx,
                self.windows_results.clone(),
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
    pub(crate) async fn agent_install_fact_in(
        &self,
        tx: &mut PgTransaction<'_>,
        registration: Uuid,
        generation: i64,
    ) -> Result<Option<(rss_mdm_inventory::channel::Observation, Platform)>> {
        let tenant = tx.tenant_id();
        let inventory = self.inventory.clone();
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
                    Ok(inventory
                        .detail_on(c, tenant, registration, generation, source)
                        .await)
                })
            })
            .await??;
        Ok(Some((fact, platform)))
    }
    pub(crate) async fn agent_install_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::Policy,
        target: &crate::deployment::Target,
        deadline: i64,
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        audit: &RequestAudit,
    ) -> Result<rss_mdm_agent_wire::runtime::PolicyEventDecision> {
        use rss_mdm_agent_wire::runtime::{
            PolicyEventDecision as Decision, PolicyEventOperation as Operation,
        };
        if let Some((rss_mdm_inventory::channel::Observation::Ready(fact), platform)) = self
            .agent_install_fact_in(tx, target.registration, target.generation)
            .await?
        {
            let (_, Published::AgentInstall { action }) =
                policies::storage::version_in(&self.policy_reader, tx, policy.version).await?
            else {
                return Err(Error::Malformed.into());
            };
            let architecture = fact
                .evidence
                .as_ref()
                .and_then(|e| e.architecture.as_deref())
                .and_then(|v| match v {
                    "aarch64" => Some(Architecture::Aarch64),
                    "x86_64" => Some(Architecture::X86_64),
                    _ => None,
                });
            if let Some(package) = architecture.and_then(|architecture| {
                action
                    .packages
                    .get(&SoftwareTarget::new(platform, architecture))
            }) {
                let tenant = tx.tenant_id().to_string();
                let registration = target.registration;
                let generation = target.generation;
                let contact = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(rss_mdm_registration_service::installation::queries::native_contact_on(
                                c,
                                &tenant,
                                registration,
                                generation,
                            )
                            .await)
                        })
                    })
                    .await??;
                if crate::deployment::agent_install::recovery::signal(
                    &fact,
                    package,
                    &contact,
                    storage::now(tx).await?,
                ) == crate::deployment::agent_install::recovery::Signal::Healthy
                {
                    return Ok(Decision::NoChange {
                        reason: "agent_installed".into(),
                    });
                }
            }
        }
        let tenant = tx.tenant_id().to_string();
        let t = target.clone();
        let existing:Option<Uuid>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT o.id FROM mdm_software_deployment.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND o.registration=$3 AND o.registration_generation=$4 AND o.authority->>'kind'='agent_install' AND d.terminal_at IS NULL AND d.deadline>floor(extract(epoch FROM clock_timestamp())*1000000)::bigint ORDER BY d.queued_at DESC,o.id DESC LIMIT 1").bind(tenant).bind(t.device).bind(t.registration).bind(t.generation).fetch_optional(c).await})).await?;
        if let Some(id) = existing {
            let operation = storage::load(tx, &self.protection, id).await?;
            let authority::Authority::AgentInstall { package, .. } = operation.authority else {
                return Err(Error::Malformed.into());
            };
            let (_, Published::AgentInstall { action }) =
                policies::storage::version_in(&self.policy_reader, tx, policy.version).await?
            else {
                return Err(Error::Malformed.into());
            };
            let digest = crate::deployment::transaction::fingerprint(&package)?;
            let mut same = false;
            for candidate in action.packages.values() {
                same |= crate::deployment::transaction::fingerprint(candidate)? == digest;
            }
            return Ok(if same {
                Decision::Accepted {
                    operations: vec![Operation::Native { id }],
                }
            } else {
                crate::deployment::policy_events::rejected("installation_conflict")
            });
        }
        match self
            .reconcile_agent_install_trigger_in(
                tx,
                &target.device,
                audit,
                Some((policy.id, deadline, origin)),
            )
            .await?
        {
            Some(id) => Ok(Decision::Accepted {
                operations: vec![Operation::Native { id }],
            }),
            None => Ok(crate::deployment::policy_events::rejected(
                "installation_not_eligible",
            )),
        }
    }
}

impl SoftwareService {
    /// Release and target are immutable under this operation; bytes must retain the exact coordinates.
    pub async fn revalidate_installation_download(
        &self,
        id: Uuid,
        expected: &rss_mdm_resource::Artifact,
        audit: &RequestAudit,
    ) -> std::result::Result<(), Error> {
        if &self.installation_artifact(id, audit).await? != expected {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
