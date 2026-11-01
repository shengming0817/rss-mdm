//! Current native installer qualification.
use crate::deployment::Error;
use crate::deployment::frozen::Published;
use crate::installation::package::{Identity, Package};
use rss_mdm_policy::{Architecture, Platform, SoftwareTarget};
use rss_mdm_resource as resource;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub(crate) mod recovery;
pub async fn dispatched_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    operation: Uuid,
) -> std::result::Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' AND state<>'pending')").bind(tenant).bind(operation).fetch_one(c).await.map_err(crate::deployment::database::db)
}

/// Reuses current sealed evidence; dispatch does not request a fresh device probe.
async fn observed_on(
    facts: &dyn crate::deployment::inventory::Inventory,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> std::result::Result<
    Option<(
        SoftwareTarget,
        rss_mdm_inventory::channel::Current,
        Uuid,
        i64,
    )>,
    Error,
> {
    use crate::deployment::database::db;
    use rss_mdm_inventory::ReportSource;
    let rows=sqlx::query_as::<_,(Uuid,i64,String)>("SELECT r.id,r.generation,s.source FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='mdm' AND r.state='active' AND s.enabled AND s.source IN('mdm.windows','mdm.apple')")
        .bind(tenant).bind(device).fetch_all(&mut *c).await.map_err(db)?;
    if rows.len() != 1 {
        return Ok(None);
    }
    let (registration, generation, source) = &rows[0];
    let (source, platform) = match source.as_str() {
        "mdm.windows" => (ReportSource::MdmWindows, Platform::Windows),
        "mdm.apple" => (ReportSource::MdmApple, Platform::Macos),
        _ => return Ok(None),
    };
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
    let fact = match facts
        .detail_on(c, tenant_id, *registration, *generation, source)
        .await?
    {
        rss_mdm_inventory::channel::Observation::Ready(fact) => fact,
        rss_mdm_inventory::channel::Observation::ProjectionPending { .. }
        | rss_mdm_inventory::channel::Observation::Unavailable => return Ok(None),
    };
    let Some(evidence) = &fact.evidence else {
        return Ok(None);
    };
    if evidence.catalog_digest != detection_on(c, tenant_id, source).await?.digest()? {
        return Ok(None);
    }
    let architecture = match evidence.architecture.as_deref() {
        Some("x86_64") => Architecture::X86_64,
        Some("aarch64") => Architecture::Aarch64,
        _ => return Ok(None),
    };
    if source==ReportSource::MdmApple && !sqlx::query_scalar::<_,bool>("SELECT access_rights & 4352 = 4352 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant).bind(registration).fetch_optional(&mut *c).await.map_err(db)?.unwrap_or(false){return Ok(None);}
    Ok(Some((
        SoftwareTarget::new(platform, architecture),
        fact,
        *registration,
        *generation,
    )))
}

/// Narrow absence read retained for consumers which must never infer absence from health.
pub async fn absent_on(
    facts: &dyn crate::deployment::inventory::Inventory,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<(SoftwareTarget, rss_mdm_inventory::channel::AgentEvidence)>, Error> {
    Ok(observed_on(facts, c, tenant, device)
        .await?
        .and_then(|(target, fact, _, _)| {
            (fact.state == "absent")
                .then_some(fact.evidence)
                .flatten()
                .map(|evidence| (target, evidence))
        }))
}

/// Applicability gates a new side effect. Receipt settlement only rechecks its durable authority.
pub async fn dispatch_ready_on(
    facts: &dyn crate::deployment::inventory::Inventory,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    version: Uuid,
    device: &str,
    operation: Uuid,
) -> std::result::Result<bool, Error> {
    use crate::deployment::database::db;
    if dispatched_on(c, tenant, operation).await? {
        return Ok(true);
    }
    let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.versions v JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE v.tenant_id=$1::uuid AND v.id=$2 AND p.state='enabled')").bind(tenant).bind(version).fetch_one(&mut *c).await.map_err(db)?;
    if !enabled {
        return Ok(false);
    }
    let frozen: serde_json::Value = sqlx::query_scalar(
        "SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(version)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let Published::AgentInstall { action } =
        serde_json::from_value(frozen).map_err(|_| Error::Malformed)?
    else {
        return Err(Error::Malformed);
    };
    let Some((target, fact, registration, generation)) =
        observed_on(facts, c, tenant, device).await?
    else {
        return Ok(false);
    };
    let Some(package) = action.packages.get(&target) else {
        return Ok(false);
    };
    let Some(evidence) = &fact.evidence else {
        return Ok(false);
    };
    if !evidence.matches(&package.detection_identity()) {
        return Ok(false);
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    let contact = rss_mdm_registration_service::installation::queries::native_contact_on(
        c,
        tenant,
        registration,
        generation,
    )
    .await?;
    Ok(matches!(
        recovery::signal(&fact, package, &contact, now),
        recovery::Signal::Absent | recovery::Signal::Unresponsive
    ))
}

/// Derive native observation targets from the publication owner, including retired releases.
#[derive(Clone, Serialize, Deserialize)]
pub struct DetectionCatalog {
    pub identities: Vec<Identity>,
    pub win32: Vec<Win32Identity>,
    pub complete: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Win32Identity {
    pub key: String,
    pub publisher: Option<String>,
}
impl DetectionCatalog {
    pub fn digest(&self) -> std::result::Result<[u8; 32], Error> {
        use sha2::{Digest, Sha256};
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|_| Error::Malformed)?).into())
    }
}
pub async fn detection_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    source: rss_mdm_inventory::ReportSource,
) -> std::result::Result<DetectionCatalog, Error> {
    let platform = match source {
        rss_mdm_inventory::ReportSource::MdmWindows => {
            rss_mdm_agent_wire::runtime::TaskPlatform::Windows
        }
        rss_mdm_inventory::ReportSource::MdmApple => {
            rss_mdm_agent_wire::runtime::TaskPlatform::Macos
        }
        _ => return Err(Error::Malformed),
    };
    let known = crate::agent_packages::known_in(c, tenant)
        .await
        .map_err(crate::deployment::agent_preparation::publication_error)?;
    detection_catalog(known, platform)
}
fn detection_catalog(
    known: Vec<crate::agent_packages::AdmittedPackage>,
    platform: rss_mdm_agent_wire::runtime::TaskPlatform,
) -> std::result::Result<DetectionCatalog, Error> {
    let mut catalog = DetectionCatalog {
        identities: Vec::new(),
        win32: Vec::new(),
        complete: true,
    };
    for release in known
        .into_iter()
        // Only execution definitions can have been installed through this native path.
        // Material-only downloads carry no detection claim and do not invalidate absence.
        .filter(|r| r.metadata.target.platform == platform && r.software.behavior.is_some())
    {
        if let Some(resource::SoftwareBehavior::Exe(exe)) = &release.software.behavior {
            let resource::SoftwareDetection::Registry {
                scope: resource::SoftwareScope::System,
                key,
                value,
                ..
            } = &exe.detect
            else {
                catalog.complete = false;
                continue;
            };
            let lower = key.to_ascii_lowercase();
            let suffix = [
                "software\\microsoft\\windows\\currentversion\\uninstall\\",
                "software\\wow6432node\\microsoft\\windows\\currentversion\\uninstall\\",
            ]
            .into_iter()
            .find_map(|prefix| lower.strip_prefix(prefix));
            if value.eq_ignore_ascii_case("DisplayVersion")
                && let Some(key) = suffix.filter(|v| !v.is_empty() && !v.contains('\\'))
            {
                catalog.win32.push(Win32Identity {
                    key: key.to_owned(),
                    publisher: None,
                });
            } else {
                catalog.complete = false;
            }
            continue;
        }
        match crate::installation::identity::identity(&release) {
            Ok(identity) => {
                if !catalog.identities.contains(&identity) {
                    catalog.identities.push(identity);
                }
            }
            Err(crate::catalog::Error::Unsupported | crate::catalog::Error::Input) => {
                catalog.complete = false
            }
            Err(e) => {
                return Err(match crate::deployment::Fault::from(e) {
                    crate::deployment::Fault::Request(e) => e,
                    _ => Error::Unavailable(crate::deployment::Failure::SoftwareCatalogStorage),
                });
            }
        }
    }
    Ok(catalog)
}

/// Input acknowledgements are local to agent installation reconciliation.
pub(crate) async fn inputs_pending(
    tx: &mut crate::deployment::PgTransaction<'_>,
    device: &str,
) -> crate::deployment::Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.agent_install_inputs WHERE tenant_id=$1::uuid AND device=$2 AND input_revision>observed_revision)").bind(tenant).bind(device).fetch_one(c).await})).await?)
}
