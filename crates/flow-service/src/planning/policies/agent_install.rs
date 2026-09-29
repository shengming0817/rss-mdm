//! Fixed product identity and ordinary approved software admission share one native operation.
use super::*;
use rss_mdm_authorization_service::UserGrant;
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use std::collections::BTreeMap;

/// Deployment pins bind the reviewed product artifact to its claimed signing identity.
/// Production package signature/notarization verification belongs to package publication/T3.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Windows {
        product: Uuid,
        publisher: String,
    },
    Macos {
        receipt: String,
        bundle: String,
        team: String,
    },
}
impl Identity {
    pub fn platform(&self) -> Platform {
        match self {
            Self::Windows { .. } => Platform::Windows,
            Self::Macos { .. } => Platform::Macos,
        }
    }
    pub fn validate(&self) -> std::result::Result<(), Error> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        let valid = match self {
            Self::Windows { product, publisher } => !product.is_nil() && bounded(publisher),
            Self::Macos {
                receipt,
                bundle,
                team,
            } => {
                bounded(receipt)
                    && bounded(bundle)
                    && team.len() == 10
                    && team
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            }
        };
        if valid { Ok(()) } else { Err(Error::Malformed) }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub identity: Identity,
    pub package: String,
    pub version: String,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub content_origin: String,
    pub packages: BTreeMap<SoftwareTarget, Pin>,
}
impl Config {
    pub fn validate(&self) -> std::result::Result<(), Error> {
        if self.packages.is_empty() {
            return if self.content_origin.is_empty() {
                Ok(())
            } else {
                Err(Error::Malformed)
            };
        }
        rss_mdm_agent_wire::EnrollmentEntry::Windows {
            server: self.content_origin.clone(),
        }
        .validate(rss_mdm_agent_wire::TaskPlatform::Windows)
        .map_err(|_| Error::Malformed)?;
        for (target, pin) in &self.packages {
            pin.identity.validate()?;
            if target.parts().0 != pin.identity.platform()
                || pin.package.is_empty()
                || pin.version.is_empty()
                || pin.sha256 == [0; 32]
            {
                return Err(Error::Malformed);
            }
        }
        // Collection must have one stable product identity for each platform across architectures.
        for platform in [Platform::Windows, Platform::Macos] {
            let mut identities = self
                .packages
                .iter()
                .filter(|(t, _)| t.parts().0 == platform)
                .map(|(_, p)| &p.identity);
            if let Some(first) = identities.next()
                && identities.any(|i| i != first)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    pub fn identity(&self, platform: Platform) -> Option<&Identity> {
        self.packages
            .iter()
            .find(|(target, _)| target.parts().0 == platform)
            .map(|(_, p)| &p.identity)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub identity: Identity,
    pub target: SoftwareTarget,
    pub version: String,
    pub artifact: resource::SoftwareArtifact,
    pub source: resource::SoftwareSource,
    pub content_origin: String,
}
impl Package {
    pub fn url(&self, operation: Uuid) -> String {
        format!(
            "{}/api/agent/v4/installations/{operation}/package",
            self.content_origin.trim_end_matches('/')
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenInstall {
    pub resource: ResourceBinding,
    pub resource_digest: [u8; 32],
    pub admission_operation: Uuid,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub packages: BTreeMap<SoftwareTarget, Package>,
    pub deploy: UserGrant,
    pub enrollment: UserGrant,
}
impl Policies {
    pub async fn freeze_agent_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
        action: &Action,
    ) -> Result<FrozenInstall> {
        let Action::EnsureAgentInstalled {
            resource: binding,
            admission_operation,
            schedule,
            run_lifetime_seconds,
        } = action
        else {
            return Err(Error::Malformed.into());
        };
        let config = &self.execution.agent_installation;
        config.validate()?;
        let selection = binding.software().ok_or(Error::Malformed)?;
        let version = self.resource_in(tx, binding).await?;
        let catalog = rss_mdm_software_service::catalog::Catalog::new(
            self.planning.runtime.clone(),
            self.planning.tenant,
            std::sync::Arc::new(crate::software_publication::host::Audit(
                self.planning.audit_store.clone(),
            )),
        );
        let mut packages = BTreeMap::new();
        for (target, key) in &selection.variants {
            let pin = config.packages.get(target).ok_or(Error::Unsupported)?;
            let (platform, architecture) = resource_target(*target);
            let selected = catalog
                .resolve_admitted_in(
                    tx,
                    binding.id(),
                    binding.version(),
                    platform,
                    architecture,
                    &checked_input(resource::Id::new(key))?,
                )
                .await?;
            if selected.admission().operation != *admission_operation
                || selected.version().digest() != version.digest()
            {
                return Err(Error::Conflict.into());
            }
            let variant = selected
                .version()
                .resolve(
                    platform,
                    architecture,
                    &checked_input(resource::Id::new(key))?,
                )
                .map_err(|_| Error::Malformed)?;
            let resource::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Malformed.into());
            };
            let spec = definition.spec();
            let artifact = spec
                .artifacts
                .get(&spec.primary)
                .ok_or(Error::Malformed)?
                .clone();
            checked_input(artifact.artifact())?;
            if spec.package != pin.package
                || spec.version != pin.version
                || artifact.sha256 != pin.sha256
                || spec.artifacts.len() != 1
                || !spec.dependencies.is_empty()
                || spec.bundle.is_some()
                || spec.downgrade != resource::SoftwareDowngrade::Deny
                || !spec.install.arguments.is_empty()
                || !spec.install.environment.is_empty()
                || spec.install.entry.is_some()
                || spec.install.run_as != resource::RunAs::System
            {
                return Err(Error::Unsupported.into());
            }
            let exact = match (
                &pin.identity,
                &spec.detect,
                spec.format,
                spec.install.executor,
            ) {
                (
                    Identity::Windows { product, .. },
                    resource::SoftwareDetection::MsiProduct {
                        product_code,
                        version,
                    },
                    resource::SoftwareFormat::Msi,
                    resource::SoftwareExecutor::Msi,
                ) => {
                    Uuid::parse_str(product_code).ok() == Some(*product) && version == &pin.version
                }
                (
                    Identity::Macos { receipt, .. },
                    resource::SoftwareDetection::PkgReceipt {
                        receipt: actual,
                        version,
                    },
                    resource::SoftwareFormat::Pkg,
                    resource::SoftwareExecutor::PackageInstaller,
                ) => actual == receipt && version == &pin.version,
                _ => false,
            };
            if !exact {
                return Err(Error::Unsupported.into());
            }
            packages.insert(
                *target,
                Package {
                    identity: pin.identity.clone(),
                    target: *target,
                    version: pin.version.clone(),
                    artifact,
                    source: spec.source.clone(),
                    content_origin: config.content_origin.clone(),
                },
            );
        }
        Ok(FrozenInstall {
            resource: binding.clone(),
            resource_digest: version.digest().bytes(),
            admission_operation: *admission_operation,
            schedule: schedule.clone(),
            run_lifetime_seconds: *run_lifetime_seconds,
            packages,
            deploy: UserGrant::all_devices(snapshot, proof, Permission::SoftwareDeploy)?,
            enrollment: UserGrant::all_devices(snapshot, proof, Permission::Enrollment)?,
        })
    }
}
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

/// Durable Policy authority survives administrator logout and rechecks every actual grant.
pub async fn authorized_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    version: Uuid,
    device: &str,
    operation: Uuid,
    now: i64,
) -> std::result::Result<bool, Error> {
    use crate::database::db;
    let row=sqlx::query("SELECT v.frozen,p.enabled AND p.current_version=v.id AS live,mdm_planning.scope_admission((p.definition->>'scope')::uuid,$4)->>'state'='eligible' AS eligible FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.policy)=(p.tenant_id,p.id) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND v.id=$3")
        .bind(tenant).bind(policy).bind(version).bind(device).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(false);
    };
    if !row.try_get::<bool, _>("live").map_err(db)? {
        return Ok(false);
    }
    let Frozen::AgentInstall { action } =
        serde_json::from_value(row.try_get("frozen").map_err(db)?).map_err(|_| Error::Malformed)?
    else {
        return Ok(false);
    };
    if !action
        .deploy
        .valid(c, Permission::SoftwareDeploy, now)
        .await?
        || !action
            .enrollment
            .valid(c, Permission::Enrollment, now)
            .await?
    {
        return Ok(false);
    }
    if !row.try_get::<bool, _>("eligible").map_err(db)?
        && !dispatched_on(c, tenant, operation).await?
    {
        return Ok(false);
    }
    rss_mdm_software_service::catalog::admitted_on(
        c,
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        action.resource.id(),
        action.resource.version(),
        action.resource_digest,
        action.admission_operation,
        &action
            .packages
            .values()
            .map(|p| p.source.clone())
            .collect::<Vec<_>>(),
    )
    .await
    .map_err(|e| match crate::transaction::Fault::from(e) {
        crate::transaction::Fault::Request(e) => e,
        _ => Error::Unavailable(crate::Failure::SoftwareCatalogStorage),
    })
}
pub async fn dispatched_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    operation: Uuid,
) -> std::result::Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' AND state<>'pending')").bind(tenant).bind(operation).fetch_one(c).await.map_err(crate::database::db)
}

/// Reuses current sealed evidence; dispatch does not request a fresh device probe.
pub async fn absent_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> std::result::Result<Option<(SoftwareTarget, crate::collection::channel::AgentEvidence)>, Error>
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
    let Some(fact) =
        crate::assets::channel::detail_in(c, tenant_id, *registration, *generation, source)
            .await?
            .filter(|f| f.state == "absent")
    else {
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
    if source==ReportSource::MdmApple && !sqlx::query_scalar::<_,bool>("SELECT access_rights & 4352 = 4352 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant).bind(registration).fetch_optional(&mut *c).await.map_err(db)?.unwrap_or(false){return Ok(None);}
    Ok(Some((
        SoftwareTarget::new(platform, architecture),
        evidence,
    )))
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
    let Some((target, evidence)) = absent_on(c, tenant, device).await? else {
        return Ok(false);
    };
    let Some(package) = action.packages.get(&target) else {
        return Ok(false);
    };
    let identity = match &package.identity {
        Identity::Windows { product, .. } => product.to_string(),
        Identity::Macos { bundle, .. } => bundle.clone(),
    };
    if evidence.identity != identity {
        return Ok(false);
    }
    let expected = serde_json::to_vec(package).map_err(|_| Error::Malformed)?;
    let mut after = Uuid::nil();
    loop {
        let rows=sqlx::query("SELECT p.id,v.frozen,mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state' AS admission FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.enabled AND p.id>$3 AND p.definition->'action'->>'kind'='ensure_agent_installed' AND mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded' ORDER BY p.id LIMIT 64")
                .bind(tenant).bind(device).bind(after).fetch_all(&mut *c).await.map_err(db)?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.try_get("id").map_err(db)?;
            let Frozen::AgentInstall { action: other } =
                serde_json::from_value(row.try_get("frozen").map_err(db)?)
                    .map_err(|_| Error::Malformed)?
            else {
                return Err(Error::Malformed);
            };
            if let Some(package) = other.packages.get(&target)
                && (row.try_get::<String, _>("admission").map_err(db)? != "eligible"
                    || serde_json::to_vec(package).map_err(|_| Error::Malformed)? != expected)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
