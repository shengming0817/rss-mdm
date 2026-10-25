//! Native software is a projection of approved Resource material, never an Agent bootstrap.
use crate::{Error, Result, Target};
use rss_mdm_policy::{Architecture, Platform};
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Msi {
        product: Uuid,
        version: String,
    },
    Msix {
        family: String,
        identity: r::MsixIdentity,
    },
    Pkg {
        receipt: String,
        version: String,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub identity: Identity,
    pub artifact: r::SoftwareArtifact,
    pub origin: String,
    pub timeout_seconds: u32,
    pub minimum_os: Option<[u16; 4]>,
}
impl Package {
    pub fn compile(
        definition: &r::SoftwareDefinition,
        origin: String,
    ) -> std::result::Result<Self, Error> {
        let spec = definition.spec();
        if !spec.dependencies.is_empty()
            || spec.reboot != r::SoftwareReboot::Report
            || spec.downgrade != r::SoftwareDowngrade::Deny
        {
            return Err(Error::Unsupported);
        }
        let (key, identity, invocation, mechanism) =
            match spec.behavior.as_ref().ok_or(Error::Unsupported)? {
                r::SoftwareBehavior::Msi(native) | r::SoftwareBehavior::Pkg(native) => {
                    if native.scope != r::SoftwareScope::System
                        || native.upgrade != r::SoftwareUpgrade::InPlace
                        || native.install != native.upgrade_invocation
                    {
                        return Err(Error::Unsupported);
                    }
                    let (identity, mechanism) = match (
                        spec.behavior.as_ref().ok_or(Error::Unsupported)?,
                        &native.detect,
                    ) {
                        (
                            r::SoftwareBehavior::Msi(_),
                            r::SoftwareDetection::MsiProduct {
                                product_code,
                                version,
                            },
                        ) => (
                            Identity::Msi {
                                product: Uuid::parse_str(product_code.trim_matches(['{', '}']))
                                    .map_err(|_| Error::Unsupported)?,
                                version: version.clone(),
                            },
                            r::SignatureMechanism::Authenticode,
                        ),
                        (
                            r::SoftwareBehavior::Pkg(_),
                            r::SoftwareDetection::PkgReceipt { receipt, version },
                        ) => (
                            Identity::Pkg {
                                receipt: receipt.clone(),
                                version: version.clone(),
                            },
                            r::SignatureMechanism::AppleDeveloperId,
                        ),
                        _ => return Err(Error::Unsupported),
                    };
                    (&native.installer, identity, &native.install, mechanism)
                }
                r::SoftwareBehavior::Msix(msix) => {
                    let r::MsixContainer::Package { installer } = &msix.container else {
                        return Err(Error::Unsupported);
                    };
                    if msix.allow_unsigned
                        || !msix.dependencies.is_empty()
                        || msix.deployment != r::MsixDeployment::DeviceProvisioning
                        || msix.upgrade != r::SoftwareUpgrade::InPlace
                    {
                        return Err(Error::Unsupported);
                    }
                    (
                        installer,
                        Identity::Msix {
                            family: crate::agent_preparation::family(
                                &msix.identity.name,
                                &msix.identity.publisher,
                            ),
                            identity: msix.identity.clone(),
                        },
                        &msix.invocation,
                        r::SignatureMechanism::Msix,
                    )
                }
                _ => return Err(Error::Unsupported),
            };
        if invocation.run_as != r::RunAs::System
            || !invocation.environment.is_empty()
            || !invocation.arguments.is_empty()
            || invocation.exit_codes.success != [0].into_iter().collect()
            || !invocation.exit_codes.reboot.is_empty()
        {
            return Err(Error::Unsupported);
        }
        if matches!(identity, Identity::Msi { .. })
            && (invocation.timeout_seconds > 255 * 60 || invocation.timeout_seconds % 60 != 0)
        {
            return Err(Error::Unsupported);
        }
        let signature = spec
            .signatures
            .iter()
            .find(|s| &s.artifact == key && s.mechanism == mechanism && s.evidence.is_some())
            .ok_or(Error::Unsupported)?;
        if let Identity::Msix { identity, .. } = &identity
            && signature.publisher != identity.publisher
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            identity,
            artifact: spec.artifacts.get(key).ok_or(Error::Malformed)?.clone(),
            origin,
            timeout_seconds: invocation.timeout_seconds,
            minimum_os: match spec.behavior.as_ref().ok_or(Error::Unsupported)? {
                r::SoftwareBehavior::Msix(m) => Some(m.minimum_os),
                _ => None,
            },
        })
    }
    pub fn effect_version(&self) -> String {
        match &self.identity {
            Identity::Msi { version, .. } | Identity::Pkg { version, .. } => version.clone(),
            Identity::Msix { identity, .. } => identity.version.map(|v| v.to_string()).join("."),
        }
    }
    pub fn effect_identity(&self) -> String {
        match &self.identity {
            Identity::Msi { product, .. } => format!("msi:{product}"),
            Identity::Msix { family, .. } => format!("msix:{family}"),
            Identity::Pkg { receipt, .. } => format!("pkg:{receipt}"),
        }
    }
    pub fn task(
        &self,
        operation: Uuid,
        protection: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
    ) -> std::result::Result<crate::Task, Error> {
        let token = protection
            .mac(
                &serde_json::to_vec(&self.artifact).map_err(|_| Error::Malformed)?,
                &crate::protection::aad(tenant, "software.download", &operation)?,
            )
            .map_err(|_| Error::Unavailable(crate::Failure::NativeProtection))?
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let url = format!(
            "{}/api/v1/software/installations/{operation}/package?token={token}",
            self.origin.trim_end_matches('/')
        );
        Ok(match &self.identity {
            Identity::Msi { product, version } => crate::Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::Msi {
                    job: rss_mdm_windows_mdm::software::InstallJob {
                        product: product.to_string(),
                        version: version.clone(),
                        content_urls: vec![url],
                        sha256: self.artifact.sha256,
                        operation: operation.to_string(),
                        scope: rss_mdm_windows_mdm::native::Scope::Device,
                        enforcement: rss_mdm_windows_mdm::software::Enforcement {
                            command_line: "/quiet /norestart".into(),
                            timeout_minutes: u8::try_from(self.timeout_seconds.div_ceil(60))
                                .map_err(|_| Error::Unsupported)?,
                            retry_count: 0,
                            retry_interval_minutes: 5,
                            download_from_aad: false,
                        },
                    },
                },
            },
            Identity::Msix { family, .. } => crate::Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl {
                    request: rss_mdm_windows_mdm::software::MsixInstall::new(family.clone(), url)
                        .and_then(|v| v.request())
                        .map_err(|_| Error::Malformed)?,
                },
            },
            Identity::Pkg { receipt, version } => {
                use rss_mdm_apple_mdm::native::{
                    input::{CommandInput, Fields},
                    request::Request,
                };
                let mut body = rss_mdm_apple_mdm::software::installation_manifest(
                    receipt,
                    version,
                    &url,
                    self.artifact.sha256,
                )
                .map_err(|_| Error::Malformed)?;
                body.remove("RequestType");
                crate::Task::Macos {
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
}

pub async fn target_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<Option<(Target, Platform, Architecture)>> {
    Ok(target_admission_in(tx, device).await?.1)
}
pub async fn target_admission_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<(
    crate::sources::software::TaskAdmissionState,
    Option<(Target, Platform, Architecture)>,
)> {
    use crate::sources::software::TaskAdmissionState as State;
    let tenant = tx.tenant_id();
    let device = device.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        let rows = sqlx::query_as::<_, (Uuid,i64,String)>("SELECT r.id,r.generation,s.source FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='mdm' AND r.state='active' AND s.enabled AND s.source IN('mdm.windows','mdm.apple')").bind(tenant.to_string()).bind(&device).fetch_all(&mut *c).await?;
        if rows.is_empty() { return Ok(Ok((State::MissingRegistration,None))); }
        if rows.len()>1 { return Ok(Ok((State::AmbiguousRegistration,None))); }
        let (registration,generation,source) = &rows[0];
        let (report, platform) = if source=="mdm.windows" { (rss_mdm_inventory::ReportSource::MdmWindows,Platform::Windows) } else { (rss_mdm_inventory::ReportSource::MdmApple,Platform::Macos) };
        if platform==Platform::Macos && !sqlx::query_scalar::<_,bool>("SELECT access_rights & 4096 = 4096 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant.to_string()).bind(registration).fetch_optional(&mut *c).await?.unwrap_or(false) { return Ok(Ok((State::MissingNativeRights,None))); }
        let fact = match crate::assets::channel::detail_in(c,tenant,*registration,*generation,report).await { Ok(fact)=>fact,Err(e)=>return Ok(Err(e)) };
        let architecture = match fact.and_then(|f| f.evidence).and_then(|e| e.architecture) .as_deref() { Some("x86_64")=>Architecture::X86_64,Some("aarch64")=>Architecture::Aarch64,_=>return Ok(Ok((State::MissingArchitecture,None))) };
        Ok(Ok((State::Eligible,Some((Target {device,registration:*registration,generation:*generation},platform,architecture)))))
    })).await??)
}

pub async fn authority_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut sqlx::PgConnection,
    authority: &crate::authority::ExecutionAuthority,
    dispatch: bool,
) -> std::result::Result<bool, Error> {
    use sqlx::Row;
    let crate::authority::ExecutionAuthority::Software {
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
    let row = sqlx::query("SELECT v.frozen,p.definition,r.source_objects,r.state,p.state='enabled' AND p.current_version=v.id AS live,(p.definition->>'scope')::uuid AS scope,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) JOIN mdm_access.registrations reg ON(reg.tenant_id,reg.id,reg.generation)=(r.tenant_id,r.registration,r.generation) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.policy_version=$3 AND r.device=$4 AND reg.state='active'").bind(tenant).bind(operation).bind(version).bind(device).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let crate::frozen::Frozen::Software { action } =
        serde_json::from_value(row.try_get("frozen").map_err(crate::database::db)?)
            .map_err(|_| Error::Malformed)?
    else {
        return Ok(false);
    };
    if action.channel != rss_mdm_policy::SoftwareChannel::Mdm {
        return Ok(false);
    }
    if !rss_mdm_software_service::catalog::admitted_on(
        c,
        tenant_id,
        &action.resource,
        &action.version,
        action.resource_digest,
        action.lifecycle_binding,
    )
    .await
    .map_err(|_| Error::Unavailable(crate::Failure::SoftwareCatalogStorage))?
    {
        return Ok(false);
    }
    let Some(grants) = action.grants.get(device).or_else(|| action.grants.get("*")) else {
        return Ok(false);
    };
    let now = row.try_get("now").map_err(crate::database::db)?;
    let mut allowed = false;
    for grant in grants {
        allowed |= grant
            .valid(c, crate::authorization::Permission::SoftwareDeploy, now)
            .await?;
    }
    if !allowed {
        return Ok(false);
    }
    if dispatch && !crate::agent_install::dispatched_on(c, tenant, *operation).await? {
        let state: crate::actions::state::RunState =
            serde_json::from_value(row.try_get("state").map_err(crate::database::db)?)
                .map_err(|_| Error::Malformed)?;
        if state.cancellation != crate::actions::state::Cancellation::None {
            return Ok(false);
        }
        let definition: rss_mdm_policy::Definition =
            serde_json::from_value(row.try_get("definition").map_err(crate::database::db)?)
                .map_err(|_| Error::Malformed)?;
        let rss_mdm_policy::Action::Software { rollout, .. } = definition.action else {
            return Ok(false);
        };
        let assignment = crate::sources::software::SoftwareAssignment::persisted(
            definition.scope,
            rollout,
            *action,
            *version,
            row.try_get("live").map_err(crate::database::db)?,
        );
        if assignment
            .entry_on(source, c, tenant_id, device, now)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        let evidence: Vec<crate::source_authority::DeviceObject> =
            serde_json::from_value(row.try_get("source_objects").map_err(crate::database::db)?)
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

use crate::{ExecutionService, storage};
use rss_device_command as dc;
use rss_mdm_audit_integration::RequestAudit;
impl ExecutionService {
    pub async fn software_installation_content(
        &self,
        id: Uuid,
        token: &str,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_content_service::Verified, Error> {
        let artifact = self
            .software_installation_artifact(id, token, audit)
            .await?;
        let verified = self
            .content
            .as_ref()
            .ok_or(Error::Unsupported)?
            .verify(&artifact)
            .await?;
        if !verified.matches(
            &self
                .software_installation_artifact(id, token, audit)
                .await?,
        ) {
            return Err(Error::Conflict);
        }
        Ok(verified)
    }
    async fn software_installation_artifact(
        &self,
        id: Uuid,
        token: &str,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_resource::Artifact, Error> {
        audit.require_final_request();
        audit.identify_service("native-package-download");
        audit.operation(
            id,
            "software_content",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        crate::transaction::inspect(&self.runtime, self.tenant, (self, id, token), |ctx, tx| {
            Box::pin(async move {
                let (s, id, token) = *ctx;
                let tenant = s.tenant.to_string();
                let instance = s.instance.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                    })
                })
                .await??;
                crate::transaction::lock(tx).await?;
                let op = storage::load(tx, &s.protection, id).await?;
                storage::lock(tx, &op.device).await?;
                let crate::authority::ExecutionAuthority::Software { version, .. } = &op.authority
                else {
                    return Err(Error::NotFound.into());
                };
                let (_, frozen) =
                    crate::sources::storage::version_in(&s.policy_reader, tx, *version).await?;
                let crate::frozen::Frozen::Software { action } = frozen else {
                    return Err(Error::NotFound.into());
                };
                let actual =
                    serde_json::to_value(&op.request.task).map_err(|_| Error::Malformed)?;
                let package = action
                    .native_packages
                    .values()
                    .find(|package| {
                        package
                            .task(id, &s.protection, s.tenant)
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
                    .map(|i| u8::from_str_radix(&token[i..i + 2], 16).map_err(|_| Error::Forbidden))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                s.protection
                    .verify_mac(
                        &serde_json::to_vec(&package.artifact).map_err(|_| Error::Malformed)?,
                        &crate::protection::aad(s.tenant, "software.download", &id)?,
                        &tag,
                    )
                    .map_err(|_| Error::Forbidden)?;
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

impl Package {
    pub fn observation(&self) -> Option<rss_mdm_windows_mdm::native::Request> {
        use rss_mdm_windows_mdm::native::{Request, Verb};
        let Identity::Msix { family, identity } = &self.identity else {
            return None;
        };
        let architecture = match identity.architecture {
            r::MsixArchitecture::X86_64 => "x64",
            r::MsixArchitecture::Aarch64 => "arm64",
            r::MsixArchitecture::Neutral => "neutral",
        };
        let publisher = family.rsplit_once('_')?.1;
        let version = identity.version.map(|v| v.to_string()).join(".");
        let full = format!(
            "{}_{version}_{architecture}_{}_{publisher}",
            identity.name, identity.resource_id
        );
        let mut operations:Vec<_>=["Status","LastError"].into_iter().map(|property|Request::Node { node:format!("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppInstallation/*/{property}"),instance:vec![family.clone()],operation:Verb::Get,value:None }).collect();
        for property in ["IsProvisioned", "Version"] {
            operations.push(Request::Node {node:format!("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/nonStore/*/*/{property}"),instance:vec![family.clone(),full.clone()],operation:Verb::Get,value:None});
        }
        Some(Request::Sequence { operations })
    }
}
pub async fn package_on(
    protection: &rss_mdm_native_protection::Protector,
    c: &mut sqlx::PgConnection,
    authority: &crate::authority::ExecutionAuthority,
    task: &crate::Task,
) -> std::result::Result<Option<Package>, Error> {
    let crate::authority::ExecutionAuthority::Software {
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
    .map_err(crate::database::db)?;
    let crate::frozen::Frozen::Software { action } =
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

#[cfg(test)]
#[path = "../tests/native_software_unit.rs"]
mod tests;
