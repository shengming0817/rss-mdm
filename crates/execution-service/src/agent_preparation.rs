//! Policy publication and source authority for Agent installation.
use crate::agent_install::{FrozenInstall, Identity, Package};
use crate::authorization::{self, Permission, context::AuthorizedPrincipal};
use crate::{Error, Inputs, transaction::*};
use rss_mdm_authorization_service::UserGrant;
use rss_mdm_policy::Action;
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgTransaction;
use std::collections::BTreeMap;
use uuid::Uuid;
impl Inputs {
    pub async fn freeze_agent_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &authorization::Snapshot,
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
        let config = &self.agent_installation;
        config.validate()?;
        let selection = binding.software().ok_or(Error::Malformed)?;
        let version = self
            .active_version_in(tx, binding.id(), binding.version())
            .await?;
        let mut packages = BTreeMap::new();
        for (target, key) in &selection.variants {
            let pin = config.packages.get(target).ok_or(Error::Unsupported)?;
            let (platform, architecture) = crate::agent_install::resource_target(*target);
            let selected = self
                .software
                .resolve_in(
                    tx,
                    &rss_mdm_software_service::preparation::Selection {
                        resource: binding.id(),
                        version: binding.version(),
                        digest: version.digest().bytes(),
                        admission: *admission_operation,
                        variant: key,
                        uninstall: false,
                    },
                    rss_mdm_software_service::preparation::Target {
                        platform,
                        architecture,
                    },
                )
                .await?;
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
                .get(spec.behavior.installer())
                .ok_or(Error::Malformed)?
                .clone();
            checked_input(artifact.artifact())?;
            if spec.package != pin.package
                || spec.version != pin.version
                || artifact.sha256 != pin.sha256
                || spec.artifacts.len() != 1
                || !spec.dependencies.is_empty()
                || spec.behavior.bundle().is_some()
                || spec.downgrade != resource::SoftwareDowngrade::Deny
                || !spec.behavior.invocation().arguments.is_empty()
                || !spec.behavior.invocation().environment.is_empty()
                || spec.behavior.invocation().run_as != resource::RunAs::System
            {
                return Err(Error::Unsupported.into());
            }
            let exact = match (&pin.identity, &spec.behavior) {
                (Identity::Windows { product, .. }, resource::SoftwareBehavior::Msi(native)) => {
                    match &native.detect {
                        resource::SoftwareDetection::MsiProduct {
                            product_code,
                            version,
                        } => {
                            Uuid::parse_str(product_code).ok() == Some(*product)
                                && version == &pin.version
                        }
                        _ => false,
                    }
                }
                (Identity::Macos { receipt, .. }, resource::SoftwareBehavior::Pkg(native)) => {
                    match &native.detect {
                        resource::SoftwareDetection::PkgReceipt {
                            receipt: actual,
                            version,
                        } => actual == receipt && version == &pin.version,
                        _ => false,
                    }
                }
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
