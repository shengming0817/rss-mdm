//! Agent installation freezes an explicitly published release, never deployment pins.
use super::package::{FrozenInstall, Package};
use crate::catalog::{Error, Result};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgRuntime;
use rss_transactional_messaging_postgres::PgTransaction;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;
/// Installation publication consumes readiness, never the registration service itself.
pub trait Admission: Send + Sync {
    fn installed_origin(&self) -> Option<&str>;
    fn ready_signing_revision<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        now: i64,
    ) -> futures::future::BoxFuture<'a, Result<Option<u64>>>;
}
pub struct Inputs {
    pub runtime: Arc<PgRuntime>,

    pub bootstrap_configured: bool,
    pub admission: Arc<dyn Admission>,
}
impl Inputs {
    fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        Ok(())
    }

    pub async fn admit_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<()> {
        self.validate_in(tx)?;
        if !self.bootstrap_configured {
            return Err(Error::Unsupported);
        }
        if tx.tenant_id() != binding.tenant() {
            return Err(Error::NotAdmitted);
        }
        let revision = tx
            .with_connection_context(&mut (self,), |(owner,), c| {
                Box::pin(async move {
                    let now: i64 = sqlx::query_scalar(
                        "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                    )
                    .fetch_one(&mut *c)
                    .await?;
                    Ok(owner
                        .admission
                        .ready_signing_revision(c, binding, now)
                        .await)
                })
            })
            .await??
            .ok_or(Error::Unsupported)?;
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(rss_mdm_task_trust::trust::check_revision(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    rss_mdm_task_trust::Use::AgentTask,
                    c,
                    tenant,
                    revision,
                )
                .await
                .map_err(|_| Error::Dependency))
            })
        })
        .await??;
        Ok(())
    }
    pub async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &rss_mdm_authorization_service::Snapshot,
        releases: &BTreeMap<SoftwareTarget, Uuid>,
        schedule: &Schedule,
        lifetime: u32,
    ) -> Result<FrozenInstall> {
        self.validate_in(tx)?;
        self.admit_in(tx, proof.binding()).await?;
        let mut packages = BTreeMap::new();
        for (target, id) in releases {
            let tenant = tx.tenant_id();
            let id = *id;
            let release = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(crate::agent_packages::resolve_in(c, tenant, id)
                            .await
                            .map_err(publication_error))
                    })
                })
                .await??;
            let (platform, architecture) = target.parts();
            let metadata = &release.metadata;
            let expected_platform = match platform {
                rss_mdm_policy::Platform::Windows => {
                    rss_mdm_agent_wire::runtime::TaskPlatform::Windows
                }
                rss_mdm_policy::Platform::Macos => rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
            };
            let expected_arch = match architecture {
                rss_mdm_policy::Architecture::X86_64 => {
                    rss_mdm_agent_wire::runtime::TaskArchitecture::X86_64
                }
                rss_mdm_policy::Architecture::Aarch64 => {
                    rss_mdm_agent_wire::runtime::TaskArchitecture::Aarch64
                }
            };
            if metadata.target.platform != expected_platform
                || metadata.target.architecture != expected_arch
            {
                return Err(Error::Unsupported);
            }
            let spec = &release.software;
            let behavior = spec.behavior.as_ref().ok_or(Error::Unsupported)?;
            if !spec.dependencies.is_empty()
                || spec.downgrade != resource::SoftwareDowngrade::Deny
                || !behavior.invocation().arguments.is_empty()
                || !behavior.invocation().environment.is_empty()
                || behavior.invocation().run_as != resource::RunAs::System
            {
                return Err(Error::Unsupported);
            }
            let identity = crate::installation::identity::identity(&release)?;
            let artifact = spec
                .artifacts
                .get(&spec.material.installer)
                .ok_or(Error::Input)?
                .clone();
            if artifact.sha256 != metadata.installer_sha256 || artifact.length != metadata.length {
                return Err(Error::Conflict);
            }
            packages.insert(
                *target,
                Package {
                    release: rss_mdm_agent_wire::enroll::configuration::Installation {
                        release_id: id,
                    },
                    identity,
                    target: *target,
                    version: metadata.version.clone(),
                    artifact,
                    source: spec.source.clone(),
                },
            );
        }
        snapshot
            .require_all_devices(proof, Permission::SoftwareDeploy)
            .map_err(|_| Error::NotAdmitted)?;
        snapshot
            .require_all_devices(proof, Permission::Enrollment)
            .map_err(|_| Error::NotAdmitted)?;
        Ok(FrozenInstall {
            schedule: schedule.clone(),
            run_lifetime_seconds: lifetime,
            packages,
            actor: proof.actor(),
        })
    }
}
pub(crate) fn publication_error(error: crate::management::Error) -> Error {
    use crate::management::Error as E;
    match error {
        E::Forbidden => Error::NotAdmitted,
        E::ResourceMissing => Error::Missing,
        E::Malformed => Error::Input,
        E::Conflict => Error::Conflict,
        _ => Error::Dependency,
    }
}
