//! Agent installation freezes an explicitly published release, never deployment pins.
use super::package::{FrozenInstall, Package};
use crate::catalog::{Error, Result};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_mdm_resource as resource;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use rss_transactional_messaging_postgres::PgTransaction;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;
/// Installation publication consumes readiness, never the registration service itself.
pub trait Admission: Send + Sync {
    fn ready_signing_revision(&self, now: i64) -> Option<u64>;
}
pub struct Inputs {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub bootstrap_configured: bool,
    pub admission: Arc<dyn Admission>,
}
impl Inputs {
    fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }

    pub async fn admit_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.validate_in(tx)?;
        if !self.bootstrap_configured {
            return Err(Error::Unsupported);
        }
        let revision = self
            .admission
            .ready_signing_revision(
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar(
                            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                        )
                        .fetch_one(c)
                        .await
                    })
                })
                .await?,
            )
            .ok_or(Error::Unsupported)?;
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    rss_mdm_task_trust::trust::check_revision(c, tenant, revision)
                        .await
                        .map_err(|_| Error::Dependency),
                )
            })
        })
        .await??;
        tx.with_connection(move |c| Box::pin(async move {
            Ok(rss_mdm_registration_service::agent::connections::installation_configuration_on(c, &tenant.to_string()).await.map(|_| ()).map_err(|_| Error::Dependency))
        })).await??;
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
        self.admit_in(tx).await?;
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
