//! Native deployment admission; software identities belong to Software.
use crate::deployment::native::Package;
use crate::deployment::{Error, Result, Target};
use rss_mdm_policy::{Architecture, Platform};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub struct NativeTarget {
    pub target: Target,
    pub platform: Platform,
    pub architecture: Architecture,
}

pub enum TargetAdmission {
    Eligible(NativeTarget),
    ProjectionPending(NativeTarget),
    Rejected(rss_mdm_policy::pages::TaskAdmissionState),
}

pub async fn target_admission_in(
    facts: std::sync::Arc<dyn crate::deployment::inventory::Inventory>,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<TargetAdmission> {
    let tenant = tx.tenant_id();
    let device = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(target_admission_on(facts.as_ref(), c, tenant, &device).await) })
    })
    .await?
}
pub async fn target_admission_on(
    facts: &dyn crate::deployment::inventory::Inventory,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
) -> Result<TargetAdmission> {
    use rss_mdm_policy::pages::TaskAdmissionState as State;
    let device = device.to_owned();

    let rows = sqlx::query_as::<_, (String,String)>("SELECT r.id, s.source FROM mdm_access.devices AS r INNER JOIN mdm_access.report_sources AS s ON (s.tenant_id, s.device) = (r.tenant_id, r.id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.channel = 'mdm' AND r.state = 'active' AND s.enabled AND s.source IN ('mdm.windows', 'mdm.apple')").bind(tenant.to_string()).bind(&device).fetch_all(&mut *c).await?;
    if rows.is_empty() {
        return Ok(TargetAdmission::Rejected(State::MissingRegistration));
    }
    if rows.len() > 1 {
        return Ok(TargetAdmission::Rejected(State::AmbiguousRegistration));
    }
    let (registration, source) = &rows[0];
    let (report, platform) = if source == "mdm.windows" {
        (
            rss_mdm_inventory::ReportSource::MdmWindows,
            Platform::Windows,
        )
    } else {
        (rss_mdm_inventory::ReportSource::MdmApple, Platform::Macos)
    };
    if platform==Platform::Macos && !sqlx::query_scalar::<_,bool>("SELECT access_rights & 4096 = 4096 FROM mdm_apple.devices WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state = 'active'").bind(tenant.to_string()).bind(&registration).fetch_optional(&mut *c).await?.unwrap_or(false) { return Ok(TargetAdmission::Rejected(State::MissingNativeRights)); }
    let fact = facts
        .detail_on(c, tenant, registration.clone(), report)
        .await?;
    let (evidence, pending) = match fact {
        rss_mdm_inventory::channel::Observation::Ready(fact) => (fact.evidence, false),
        rss_mdm_inventory::channel::Observation::ProjectionPending { evidence } => (evidence, true),
        rss_mdm_inventory::channel::Observation::Unavailable => {
            return Ok(TargetAdmission::Rejected(State::ChannelUnknown));
        }
    };
    let architecture = match evidence.and_then(|e| e.architecture).as_deref() {
        Some("x86_64") => Architecture::X86_64,
        Some("aarch64") => Architecture::Aarch64,
        _ => return Ok(TargetAdmission::Rejected(State::MissingArchitecture)),
    };
    let target = NativeTarget {
        target: Target { device },
        platform,
        architecture,
    };
    Ok(if pending {
        TargetAdmission::ProjectionPending(target)
    } else {
        TargetAdmission::Eligible(target)
    })
}

pub async fn dispatch_authority_on(
    source: &dyn crate::deployment::scope::Sources,
    c: &mut sqlx::PgConnection,
    authority: &crate::deployment::authority::Authority,
) -> std::result::Result<bool, Error> {
    use sqlx::Row;
    let crate::deployment::authority::Authority::Software {
        tenant,
        version,
        device,
        operation,
        ..
    } = authority
    else {
        return Ok(false);
    };
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
    let row = sqlx::query("SELECT v.frozen, p.definition, r.source_objects, r.state, p.state = 'enabled' AS live, CAST(p.definition ->> 'scope' AS uuid) AS scope, CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint) AS now FROM mdm_software_deployment.action_runs AS r INNER JOIN mdm_policy.versions AS v ON (v.tenant_id, v.id) = (r.tenant_id, r.policy_version) INNER JOIN mdm_policy.policies AS p ON (p.tenant_id, p.id) = (v.tenant_id, v.policy) INNER JOIN mdm_access.devices AS reg ON (reg.tenant_id, reg.id) = (r.tenant_id, r.device) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.policy_version = $3 AND r.device = $4 AND reg.state = 'active'").bind(tenant).bind(operation).bind(version).bind(device).fetch_optional(&mut *c).await.map_err(crate::deployment::database::db)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let crate::deployment::frozen::Published::Software { action } = serde_json::from_value(
        row.try_get("frozen")
            .map_err(crate::deployment::database::db)?,
    )
    .map_err(|_| Error::Malformed)?
    else {
        return Ok(false);
    };
    if action.channel != rss_mdm_policy::SoftwareChannel::Mdm {
        return Ok(false);
    }
    if !authorities_on(c, tenant_id, &[(0, authority.clone())], true)
        .await?
        .get(&0)
        .copied()
        .unwrap_or(false)
    {
        return Ok(false);
    }
    let now: i64 = row
        .try_get("now")
        .map_err(crate::deployment::database::db)?;
    if !crate::deployment::agent_install::dispatched_on(c, tenant, *operation).await? {
        let state: rss_mdm_task_state::RunState = serde_json::from_value(
            row.try_get("state")
                .map_err(crate::deployment::database::db)?,
        )
        .map_err(|_| Error::Malformed)?;
        if state.cancellation != rss_mdm_task_state::Cancellation::None {
            return Ok(false);
        }
        if !row
            .try_get::<bool, _>("live")
            .map_err(crate::deployment::database::db)?
            || now < action.schedule.not_before
            || now >= action.schedule.ends_at()
        {
            return Ok(false);
        }
        let evidence: Vec<crate::deployment::scope::DeviceObject> = serde_json::from_value(
            row.try_get("source_objects")
                .map_err(crate::deployment::database::db)?,
        )
        .map_err(|_| Error::Malformed)?;
        return Ok(source
            .evidence_valid_on(
                c,
                tenant_id,
                rss_mdm_inventory::Channel::Mdm,
                device,
                &evidence,
            )
            .await?);
    }
    Ok(true)
}

use crate::deployment::{SoftwareService, storage};
use rss_device_command as dc;
use rss_mdm_audit_integration::RequestAudit;
impl SoftwareService {
    pub async fn software_installation_artifact(
        &self,
        id: Uuid,
        token: &str,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_resource::Artifact, Error> {
        audit.identify_service("native-package-download");
        audit.operation(
            id,
            "software_content",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        crate::deployment::transaction::inspect(
            &self.transactions.runtime,
            self.transactions.tenant,
            (self, id, token),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, id, token) = *ctx;
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
                    let crate::deployment::authority::Authority::Software { version, .. } =
                        &op.authority
                    else {
                        return Err(Error::NotFound.into());
                    };
                    let (_, frozen) = crate::deployment::sources::storage::version_in(
                        &s.transactions.policy_reader,
                        tx,
                        *version,
                    )
                    .await?;
                    let crate::deployment::frozen::Published::Software { action } = frozen else {
                        return Err(Error::NotFound.into());
                    };
                    let actual =
                        serde_json::to_value(&op.request.task).map_err(|_| Error::Malformed)?;
                    let package = action
                        .native_packages
                        .values()
                        .find(|package| {
                            package
                                .task(id, &s.transactions.protection, s.transactions.tenant)
                                .ok()
                                .and_then(|task| serde_json::to_value(task).ok())
                                .as_ref()
                                == Some(&actual)
                        })
                        .ok_or(Error::Forbidden)?;
                    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(Error::Forbidden.into());
                    }
                    let tag = (0..64)
                        .step_by(2)
                        .map(|i| {
                            u8::from_str_radix(&token[i..i + 2], 16).map_err(|_| Error::Forbidden)
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    s.transactions
                        .protection
                        .verify_mac(
                            &serde_json::to_vec(&package.artifact).map_err(|_| Error::Malformed)?,
                            &crate::deployment::protection::aad(
                                s.transactions.tenant,
                                "software.download",
                                &id,
                            )?,
                            &tag,
                        )
                        .map_err(|_| Error::Forbidden)?;
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
                            != op.device.clone()
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

pub async fn package_on(
    protection: &rss_mdm_native_protection::Protector,
    c: &mut sqlx::PgConnection,
    authority: &crate::deployment::authority::Authority,
    task: &crate::deployment::Task,
) -> std::result::Result<Option<Package>, Error> {
    let crate::deployment::authority::Authority::Software {
        tenant,
        version,
        operation,
        ..
    } = authority
    else {
        return Ok(None);
    };
    let value = sqlx::query_scalar(
        "SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(version)
    .fetch_one(c)
    .await
    .map_err(crate::deployment::database::db)?;
    let crate::deployment::frozen::Published::Software { action } =
        serde_json::from_value(value).map_err(|_| Error::Malformed)?
    else {
        return Err(Error::Malformed);
    };
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
    let task = serde_json::to_value(task).map_err(|_| Error::Malformed)?;
    Ok(action.native_packages.into_values().find(|p| {
        p.task(*operation, protection, tenant_id)
            .ok()
            .and_then(|t| serde_json::to_value(t).ok())
            .as_ref()
            == Some(&task)
    }))
}

/// Shared selected-software authority facts for dispatch and directory reads.
pub(crate) async fn authorities_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    requests: &[(usize, crate::deployment::authority::Authority)],
    lock: bool,
) -> std::result::Result<std::collections::BTreeMap<usize, bool>, Error> {
    use sqlx::Row;
    use std::collections::BTreeMap;
    let inputs = requests
        .iter()
        .map(|(index, a)| serde_json::json!({"n":index,"a":a}))
        .collect::<Vec<_>>();
    let rows=sqlx::query("WITH inputs AS (SELECT CAST(value ->> 'n' AS bigint) AS n, value -> 'a' AS a FROM jsonb_array_elements($2)), selected AS MATERIALIZED (SELECT i.n, v.frozen FROM inputs AS i INNER JOIN mdm_software_deployment.action_runs AS r ON (r.tenant_id, r.id, r.policy_version, r.device) = (CAST($1 AS uuid), CAST(i.a ->> 'operation' AS uuid), CAST(i.a ->> 'version' AS uuid), i.a ->> 'device') INNER JOIN mdm_policy.versions AS v ON (v.tenant_id, v.id) = (r.tenant_id, r.policy_version) INNER JOIN mdm_policy.policies AS p ON (p.tenant_id, p.id) = (v.tenant_id, v.policy) INNER JOIN mdm_access.devices AS reg ON (reg.tenant_id, reg.id) = (r.tenant_id, r.device) WHERE reg.state = 'active'), budget AS (SELECT CAST(COALESCE(sum(octet_length(CAST(frozen AS text))), 0) AS bigint) AS bytes FROM selected) SELECT selected.*, budget.bytes FROM budget LEFT JOIN selected ON budget.bytes <= 16777216")
        .bind(tenant.to_string()).bind(serde_json::Value::Array(inputs)).fetch_all(&mut *c).await.map_err(crate::deployment::database::db)?;
    if rows
        .first()
        .ok_or(Error::Malformed)?
        .try_get::<i64, _>("bytes")
        .map_err(crate::deployment::database::db)?
        > 16777216
    {
        return Err(Error::Unavailable(crate::deployment::Failure::Capacity));
    }
    let authorities = requests
        .iter()
        .map(|(i, a)| (*i, a))
        .collect::<BTreeMap<_, _>>();
    let mut result = requests
        .iter()
        .map(|(i, _)| (*i, false))
        .collect::<BTreeMap<_, _>>();
    let mut indices = Vec::new();
    let mut bindings = Vec::new();
    for row in rows {
        let Some(index) = row
            .try_get::<Option<i64>, _>("n")
            .map_err(crate::deployment::database::db)?
        else {
            continue;
        };
        let index = index as usize;
        let Some(crate::deployment::authority::Authority::Software { target, .. }) =
            authorities.get(&index)
        else {
            return Err(Error::Malformed);
        };
        let crate::deployment::frozen::Published::Software { action } = serde_json::from_value(
            row.try_get("frozen")
                .map_err(crate::deployment::database::db)?,
        )
        .map_err(|_| Error::Malformed)?
        else {
            continue;
        };
        if action.channel != rss_mdm_policy::SoftwareChannel::Mdm {
            continue;
        }
        let Some(variant) = action.variants.get(target) else {
            continue;
        };
        let (platform, architecture) = crate::installation::package::resource_target(*target);
        bindings.push(crate::catalog::BindingRequest {
            resource: action.resource,
            version: action.version,
            digest: action.resource_digest,
            allow_draft: false,
            selection: Some((
                platform,
                architecture,
                variant.as_str().to_owned(),
                action.intent == rss_mdm_policy::SoftwareIntent::ExplicitUninstall,
            )),
        });
        indices.push(index);
    }
    if !bindings.is_empty() {
        let decisions = if lock {
            crate::catalog::bindings_many_locked_on(c, tenant, &bindings).await
        } else {
            crate::catalog::bindings_many_on(c, tenant, &bindings).await
        }
        .map_err(|e| {
            Error::Unavailable(if matches!(e, crate::catalog::Error::Capacity) {
                crate::deployment::Failure::Capacity
            } else {
                crate::deployment::Failure::SoftwareCatalogStorage
            })
        })?;
        for (index, decision) in indices.into_iter().zip(decisions) {
            result.insert(index, decision.is_some());
        }
    }
    Ok(result)
}

impl SoftwareService {
    /// Revalidate the same immutable artifact after potentially slow content verification.
    pub async fn revalidate_software_download(
        &self,
        id: Uuid,
        token: &str,
        expected: &rss_mdm_resource::Artifact,
        audit: &RequestAudit,
    ) -> std::result::Result<(), Error> {
        if &self
            .software_installation_artifact(id, token, audit)
            .await?
            != expected
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
