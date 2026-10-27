//! Frozen Agent installation contracts and checked native package inputs.
use crate::Error;
use rss_mdm_policy::Platform;
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_mdm_resource as resource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
pub(crate) mod recovery;

/// Published package identity binds the reviewed artifact to its native detector.
/// Signing metadata is optional; the native installer owns platform installation decisions.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    WindowsMsi {
        product: Uuid,
        publisher: Option<String>,
    },
    WindowsMsix {
        family: String,
        identity: resource::MsixIdentity,
        minimum_os: [u16; 4],
    },
    Macos {
        receipt: String,
        bundle: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        team: String,
    },
}
impl Identity {
    pub fn platform(&self) -> Platform {
        match self {
            Self::WindowsMsi { .. } | Self::WindowsMsix { .. } => Platform::Windows,
            Self::Macos { .. } => Platform::Macos,
        }
    }
    pub fn validate(&self) -> std::result::Result<(), Error> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        let valid = match self {
            Self::WindowsMsi { product, publisher } => {
                !product.is_nil() && publisher.as_ref().is_none_or(|p| bounded(p))
            }
            Self::WindowsMsix {
                family, identity, ..
            } => bounded(family) && bounded(&identity.name) && bounded(&identity.publisher),
            Self::Macos {
                receipt,
                bundle,
                team,
            } => {
                bounded(receipt)
                    && bounded(bundle)
                    && team.len() <= 256
                    && !team.chars().any(char::is_control)
            }
        };
        if valid { Ok(()) } else { Err(Error::Malformed) }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub release: rss_mdm_agent_wire::enroll::configuration::Installation,
    pub identity: Identity,
    pub target: SoftwareTarget,
    pub version: String,
    pub artifact: resource::SoftwareArtifact,
    pub source: resource::SoftwareSource,
}
impl Package {
    /// Product admission owns native inputs and the fixed Agent bootstrap arguments.
    pub fn native_task(
        &self,
        operation: Uuid,
        origin: &str,
    ) -> std::result::Result<crate::Task, Error> {
        use crate::Task;
        Ok(match &self.identity {
            Identity::WindowsMsi { .. } => Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::Msi {
                    job: self
                        .windows_job(operation, origin)
                        .map_err(|_| Error::Malformed)?,
                },
            },
            Identity::WindowsMsix { family, .. } => Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl {
                    request: rss_mdm_windows_mdm::software::MsixInstall::new(
                        family.clone(),
                        self.url(operation, origin),
                    )
                    .and_then(|v| v.request())
                    .map_err(|_| Error::Malformed)?,
                },
            },
            Identity::Macos { bundle, .. } => {
                use rss_mdm_apple_mdm::native::{
                    input::{CommandInput, Fields},
                    request::Request,
                };
                let mut body = apple_install(
                    bundle,
                    &self.version,
                    &self.url(operation, origin),
                    self.artifact.sha256,
                    operation,
                )
                .map_err(|_| Error::Malformed)?;
                body.remove("RequestType");
                Task::Macos {
                    request: Request::Command {
                        command: CommandInput {
                            request_type: "InstallEnterpriseApplication".into(),
                            fields: Fields::from_plist(&body).map_err(|_| Error::Malformed)?,
                        },
                    },
                }
            }
        })
    }
    pub fn windows_job(
        &self,
        operation: Uuid,
        origin: &str,
    ) -> std::result::Result<
        rss_mdm_windows_mdm::software::InstallJob,
        rss_mdm_windows_mdm::CodecError,
    > {
        use rss_mdm_windows_mdm::{
            native::Scope,
            software::{Enforcement, InstallJob},
        };
        let Identity::WindowsMsi { product, .. } = &self.identity else {
            return Err(rss_mdm_windows_mdm::CodecError::Unsupported);
        };
        Ok(InstallJob {
            product: product.to_string(),
            version: self.version.clone(),
            content_urls: vec![self.url(operation, origin)],
            sha256: self.artifact.sha256,
            operation: operation.to_string(),
            scope: Scope::Device,
            enforcement: Enforcement {
                command_line: "/quiet /norestart".into(),
                timeout_minutes: 5,
                retry_count: 0,
                retry_interval_minutes: 5,
                download_from_aad: false,
            },
        })
    }
    pub fn url(&self, operation: Uuid, origin: &str) -> String {
        format!(
            "{}/api/v1/agent/enroll/installations/{operation}/package",
            origin.trim_end_matches('/')
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenInstall {
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub packages: BTreeMap<SoftwareTarget, Package>,
    pub actor: rss_mdm_authorization_service::Actor,
}
#[cfg(test)]
#[path = "../tests/agent_install_unit.rs"]
mod tests;

fn apple_install(
    bundle: &str,
    version: &str,
    url: &str,
    hash: [u8; 32],
    operation: Uuid,
) -> std::result::Result<plist::Dictionary, rss_mdm_apple_mdm::Error> {
    if operation.is_nil() {
        return Err(rss_mdm_apple_mdm::Error::Malformed);
    }
    let mut body = rss_mdm_apple_mdm::software::installation_manifest(bundle, version, url, hash)?;
    body.insert(
        "Configuration".into(),
        rss_mdm_apple_mdm::protocol::dictionary([(
            "RSSInstallationOperation",
            operation.to_string().into(),
        )])
        .into(),
    );
    Ok(body)
}

use crate::frozen::Frozen;
use rss_mdm_policy::Architecture;
pub fn resource_target(target: SoftwareTarget) -> (resource::Platform, resource::Architecture) {
    let (p, a) = target.parts();
    (
        match p {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        match a {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
    )
}

impl Package {
    pub async fn admitted_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> std::result::Result<bool, Error> {
        match rss_mdm_software_service::agent_packages::admitted_on(c, tenant, &self.release).await
        {
            Ok(current) => {
                Ok(current.installer_sha256 == self.artifact.sha256
                    && current.version == self.version)
            }
            Err(
                rss_mdm_software_service::management::Error::Forbidden
                | rss_mdm_software_service::management::Error::ResourceMissing,
            ) => Ok(false),
            Err(_) => Err(Error::Unavailable(crate::Failure::SoftwareCatalogStorage)),
        }
    }
    pub fn detection_identity(&self) -> String {
        match &self.identity {
            Identity::WindowsMsi { product, .. } => product.to_string(),
            Identity::WindowsMsix { family, .. } => family.clone(),
            Identity::Macos { bundle, .. } => bundle.clone(),
        }
    }
}

pub async fn dispatched_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    operation: Uuid,
) -> std::result::Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' AND state<>'pending')").bind(tenant).bind(operation).fetch_one(c).await.map_err(crate::database::db)
}

/// Reuses current sealed evidence; dispatch does not request a fresh device probe.
async fn observed_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> std::result::Result<Option<(SoftwareTarget, crate::assets::channel::Current, Uuid, i64)>, Error>
{
    use crate::database::db;
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
    let fact =
        match crate::assets::channel::detail_in(c, tenant_id, *registration, *generation, source)
            .await?
        {
            crate::assets::channel::Observation::Ready(fact) => fact,
            crate::assets::channel::Observation::ProjectionPending { .. }
            | crate::assets::channel::Observation::Unavailable => return Ok(None),
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
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<(SoftwareTarget, crate::collection::channel::AgentEvidence)>, Error> {
    Ok(observed_on(c, tenant, device)
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
    c: &mut sqlx::PgConnection,
    tenant: &str,
    version: Uuid,
    device: &str,
    operation: Uuid,
) -> std::result::Result<bool, Error> {
    use crate::database::db;
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
    let Frozen::AgentInstall { action } =
        serde_json::from_value(frozen).map_err(|_| Error::Malformed)?
    else {
        return Err(Error::Malformed);
    };
    let Some((target, fact, registration, generation)) = observed_on(c, tenant, device).await?
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
    let contact = recovery::contact_on(c, tenant, registration, generation).await?;
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
    let known = rss_mdm_software_service::agent_packages::known_in(c, tenant)
        .await
        .map_err(crate::agent_preparation::publication_error)?;
    detection_catalog(known, platform)
}
fn detection_catalog(
    known: Vec<rss_mdm_software_service::agent_packages::AdmittedPackage>,
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
        match crate::agent_preparation::identity(&release) {
            Ok(identity) => {
                if !catalog.identities.contains(&identity) {
                    catalog.identities.push(identity);
                }
            }
            Err(Error::Unsupported | Error::Malformed) => catalog.complete = false,
            Err(e) => return Err(e),
        }
    }
    Ok(catalog)
}

/// Removing our exact bootstrap object is an activation cleanup duty, not a new install grant.
pub(crate) async fn cleanup_authorized_on(
    c: &mut sqlx::PgConnection,
    authority: &crate::authority::ExecutionAuthority,
) -> std::result::Result<bool, Error> {
    let crate::authority::ExecutionAuthority::AgentInstall { tenant, .. } = authority else {
        return Ok(false);
    };
    Ok(cleanup_authorities_on(c, tenant, &[(0, authority.clone())])
        .await?
        .get(&0)
        == Some(&true))
}

pub(crate) async fn cleanup_authorities_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    requests: &[(usize, crate::authority::ExecutionAuthority)],
) -> std::result::Result<std::collections::BTreeMap<usize, bool>, Error> {
    let input = requests
        .iter()
        .map(|(n, a)| serde_json::json!({"n":n,"a":a}))
        .collect::<Vec<_>>();
    let rows=sqlx::query_as::<_,(i64,bool)>("WITH input AS(SELECT (value->>'n')::bigint AS n,value->'a' AS a FROM jsonb_array_elements($2)) SELECT x.n,EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps b JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(b.tenant_id,b.installation) WHERE b.tenant_id=$1::uuid AND b.installation=(x.a->>'operation')::uuid AND o.device=x.a->>'device' AND b.id=(x.a->'stage'->'cleanup'->>'bootstrap')::uuid AND b.state IN('issued','consumed') AND NOT b.cleanup_complete AND EXISTS(SELECT 1 FROM mdm_access.registrations native WHERE native.tenant_id=o.tenant_id AND native.id=o.registration AND native.generation=o.registration_generation AND native.state='active') AND (b.cleanup IS NOT NULL OR EXISTS(SELECT 1 FROM mdm_access.agent_grants g JOIN mdm_access.registrations r ON(r.tenant_id,r.agent_grant_id)=(g.tenant_id,g.id) WHERE g.tenant_id=b.tenant_id AND g.native_authority->>'installation'=b.installation::text))) FROM input x").bind(tenant).bind(serde_json::Value::Array(input)).fetch_all(c).await.map_err(crate::database::db)?;
    Ok(rows
        .into_iter()
        .map(|(n, valid)| (n as usize, valid))
        .collect())
}
