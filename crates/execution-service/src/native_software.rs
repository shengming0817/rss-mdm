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

pub struct NativeTarget {
    pub target: Target,
    pub platform: Platform,
    pub architecture: Architecture,
}

pub enum TargetAdmission {
    Eligible(NativeTarget),
    ProjectionPending(NativeTarget),
    Rejected(crate::sources::software::TaskAdmissionState),
}

pub async fn target_admission_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<TargetAdmission> {
    use crate::sources::software::TaskAdmissionState as State;
    let tenant = tx.tenant_id();
    let device = device.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        let rows = sqlx::query_as::<_, (Uuid,i64,String)>("SELECT r.id,r.generation,s.source FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='mdm' AND r.state='active' AND s.enabled AND s.source IN('mdm.windows','mdm.apple')").bind(tenant.to_string()).bind(&device).fetch_all(&mut *c).await?;
        if rows.is_empty() { return Ok(Ok(TargetAdmission::Rejected(State::MissingRegistration))); }
        if rows.len()>1 { return Ok(Ok(TargetAdmission::Rejected(State::AmbiguousRegistration))); }
        let (registration,generation,source) = &rows[0];
        let (report, platform) = if source=="mdm.windows" { (rss_mdm_inventory::ReportSource::MdmWindows,Platform::Windows) } else { (rss_mdm_inventory::ReportSource::MdmApple,Platform::Macos) };
        if platform==Platform::Macos && !sqlx::query_scalar::<_,bool>("SELECT access_rights & 4096 = 4096 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant.to_string()).bind(registration).fetch_optional(&mut *c).await?.unwrap_or(false) { return Ok(Ok(TargetAdmission::Rejected(State::MissingNativeRights))); }
        let fact = match crate::assets::channel::detail_in(c,tenant,*registration,*generation,report).await { Ok(fact)=>fact,Err(e)=>return Ok(Err(e)) };
        let (evidence, pending) = match fact {
            crate::assets::channel::Observation::Ready(fact) => (fact.evidence, false),
            crate::assets::channel::Observation::ProjectionPending { evidence } => (evidence, true),
            crate::assets::channel::Observation::Unavailable => return Ok(Ok(TargetAdmission::Rejected(State::ChannelUnknown))),
        };
        let architecture = match evidence.and_then(|e| e.architecture).as_deref() {
            Some("x86_64") => Architecture::X86_64,
            Some("aarch64") => Architecture::Aarch64,
            _ => return Ok(Ok(TargetAdmission::Rejected(State::MissingArchitecture))),
        };
        let target = NativeTarget { target: Target { device, registration: *registration, generation: *generation }, platform, architecture };
        Ok(Ok(if pending { TargetAdmission::ProjectionPending(target) } else { TargetAdmission::Eligible(target) }))
    })).await??)
}

pub async fn dispatch_authority_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut sqlx::PgConnection,
    authority: &crate::authority::ExecutionAuthority,
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
    let row = sqlx::query("SELECT v.frozen,p.definition,r.source_objects,r.state,p.state='enabled' AS live,(p.definition->>'scope')::uuid AS scope,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) JOIN mdm_access.registrations reg ON(reg.tenant_id,reg.id,reg.generation)=(r.tenant_id,r.registration,r.generation) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.policy_version=$3 AND r.device=$4 AND reg.state='active'").bind(tenant).bind(operation).bind(version).bind(device).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
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
    if !authorities_on(c, tenant_id, &[(0, authority.clone())], true)
        .await?
        .get(&0)
        .copied()
        .unwrap_or(false)
    {
        return Ok(false);
    }
    let now: i64 = row.try_get("now").map_err(crate::database::db)?;
    if !crate::agent_install::dispatched_on(c, tenant, *operation).await? {
        let state: crate::actions::state::RunState =
            serde_json::from_value(row.try_get("state").map_err(crate::database::db)?)
                .map_err(|_| Error::Malformed)?;
        if state.cancellation != crate::actions::state::Cancellation::None {
            return Ok(false);
        }
        if !row
            .try_get::<bool, _>("live")
            .map_err(crate::database::db)?
            || now < action.schedule.not_before
            || now >= action.schedule.ends_at()
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
        audit.identify_service("native-package-download");
        audit.operation(
            id,
            "software_content",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        crate::transaction::inspect(&self.runtime, self.tenant, (self, id, token), |ctx, tx| {
            Box::pin(async move {
                let (s, id, token) = *ctx;
                let tenant = s.tenant.to_string();
                let instance = s.instance.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(crate::authorization::lock_shared_on(c, &tenant, &instance).await)
                    })
                })
                .await??;
                let op = storage::load(tx, &s.protection, id).await?;
                storage::lock_device(tx, &op.device).await?;
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
                    || !storage::authority_decision(&s.source, &s.protection, tx, &op, now)
                        .await?
                        .is_authorized()
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

/// Shared selected-software authority facts for dispatch and directory reads.
pub(crate) async fn authorities_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    requests: &[(usize, crate::authority::ExecutionAuthority)],
    lock: bool,
) -> std::result::Result<std::collections::BTreeMap<usize, bool>, Error> {
    use sqlx::Row;
    use std::collections::BTreeMap;
    let inputs = requests
        .iter()
        .map(|(index, a)| serde_json::json!({"n":index,"a":a}))
        .collect::<Vec<_>>();
    let rows=sqlx::query("WITH inputs AS(SELECT (value->>'n')::bigint AS n,value->'a' AS a FROM jsonb_array_elements($2)),selected AS MATERIALIZED(SELECT i.n,v.frozen FROM inputs i JOIN mdm_commands.action_runs r ON(r.tenant_id,r.id,r.policy_version,r.device)=($1::uuid,(i.a->>'operation')::uuid,(i.a->>'version')::uuid,i.a->>'device') JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) JOIN mdm_access.registrations reg ON(reg.tenant_id,reg.id,reg.generation)=(r.tenant_id,r.registration,r.generation) WHERE reg.state='active'),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216")
        .bind(tenant.to_string()).bind(serde_json::Value::Array(inputs)).fetch_all(&mut *c).await.map_err(crate::database::db)?;
    if rows
        .first()
        .ok_or(Error::Malformed)?
        .try_get::<i64, _>("bytes")
        .map_err(crate::database::db)?
        > 16777216
    {
        return Err(Error::Unavailable(crate::Failure::Capacity));
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
            .map_err(crate::database::db)?
        else {
            continue;
        };
        let index = index as usize;
        let Some(crate::authority::ExecutionAuthority::Software { target, .. }) =
            authorities.get(&index)
        else {
            return Err(Error::Malformed);
        };
        let crate::frozen::Frozen::Software { action } =
            serde_json::from_value(row.try_get("frozen").map_err(crate::database::db)?)
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
        let (platform, architecture) = crate::agent_install::resource_target(*target);
        bindings.push(rss_mdm_software_service::catalog::BindingRequest {
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
            rss_mdm_software_service::catalog::bindings_many_locked_on(c, tenant, &bindings).await
        } else {
            rss_mdm_software_service::catalog::bindings_many_on(c, tenant, &bindings).await
        }
        .map_err(|e| {
            Error::Unavailable(
                if matches!(e, rss_mdm_software_service::catalog::Error::Capacity) {
                    crate::Failure::Capacity
                } else {
                    crate::Failure::SoftwareCatalogStorage
                },
            )
        })?;
        for (index, decision) in indices.into_iter().zip(decisions) {
            result.insert(index, decision.is_some());
        }
    }
    Ok(result)
}
