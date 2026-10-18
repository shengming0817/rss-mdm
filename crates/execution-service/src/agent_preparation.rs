//! Agent installation freezes an explicitly published release, never deployment pins.
use crate::agent_install::{FrozenInstall, Identity, Package};
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::{Error, Inputs, transaction::*};
use rss_mdm_authorization_service::UserGrant;
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgTransaction;
use std::collections::BTreeMap;
use uuid::Uuid;
impl Inputs {
    pub(crate) async fn freeze_agent_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
        releases: &BTreeMap<SoftwareTarget, Uuid>,
        schedule: &Schedule,
        lifetime: u32,
    ) -> Result<FrozenInstall> {
        if self.agent_origin.is_empty() || self.bootstrap.is_none() {
            return Err(Error::Unsupported.into());
        }
        let mut packages = BTreeMap::new();
        for (target, id) in releases {
            let tenant = tx.tenant_id();
            let id = *id;
            let release = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(
                            rss_mdm_software_service::agent_packages::resolve_in(c, tenant, id)
                                .await
                                .map_err(crate::agent_preparation::publication_error),
                        )
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
                || metadata.origin != self.agent_origin
            {
                return Err(Error::Unsupported.into());
            }
            let spec = &release.software;
            if !spec.dependencies.is_empty()
                || spec.downgrade != resource::SoftwareDowngrade::Deny
                || !spec.behavior.invocation().arguments.is_empty()
                || !spec.behavior.invocation().environment.is_empty()
                || spec.behavior.invocation().run_as != resource::RunAs::System
            {
                return Err(Error::Unsupported.into());
            }
            let identity = identity(&release)?;
            let artifact = spec
                .artifacts
                .get(spec.behavior.installer())
                .ok_or(Error::Malformed)?
                .clone();
            if artifact.sha256 != metadata.installer_sha256 || artifact.length != metadata.length {
                return Err(Error::Conflict.into());
            }
            packages.insert(
                *target,
                Package {
                    release: rss_mdm_agent_wire::enroll::configuration::Installation {
                        release_id: id,
                        candidate_sha256: metadata.candidate_sha256,
                    },
                    identity,
                    target: *target,
                    version: metadata.version.clone(),
                    artifact,
                    source: spec.source.clone(),
                    content_origin: self.agent_origin.clone(),
                },
            );
        }
        Ok(FrozenInstall {
            schedule: schedule.clone(),
            run_lifetime_seconds: lifetime,
            packages,
            deploy: UserGrant::all_devices(snapshot, proof, Permission::SoftwareDeploy)?,
            enrollment: UserGrant::all_devices(snapshot, proof, Permission::Enrollment)?,
        })
    }
}
/// Windows PublisherId uses the first 64 SHA256 bits of the UTF-16LE publisher DN.
pub(crate) fn family(name: &str, publisher: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes: Vec<u8> = publisher
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha256::digest(bytes);
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut encoded = String::new();
    for i in 0..13 {
        let mut value = 0u8;
        for j in 0..5 {
            let bit = i * 5 + j;
            value = (value << 1)
                | if bit < 64 {
                    (digest[bit / 8] >> (7 - bit % 8)) & 1
                } else {
                    0
                };
        }
        encoded.push(alphabet[usize::from(value)] as char);
    }
    format!("{name}_{encoded}")
}

pub(crate) fn publication_error(error: rss_mdm_software_service::management::Error) -> Error {
    use rss_mdm_software_service::management::Error as E;
    match error {
        E::Forbidden => Error::Forbidden,
        E::ResourceMissing => Error::NotFound,
        E::Malformed => Error::Malformed,
        E::Conflict => Error::Conflict,
        _ => Error::Unavailable(crate::Failure::SoftwareCatalogStorage),
    }
}

/// Detection and execution consume the same published native identity.
pub fn identity(
    release: &rss_mdm_software_service::agent_packages::AdmittedPackage,
) -> std::result::Result<Identity, Error> {
    let spec = &release.software;
    let metadata = &release.metadata;
    use rss_mdm_software_service::agent_packages::Packaging;
    let identity = match (&spec.behavior, &release.packaging) {
        (resource::SoftwareBehavior::Msi(native), Packaging::WindowsMsi { publisher, .. }) => {
            let resource::SoftwareDetection::MsiProduct {
                product_code,
                version,
            } = &native.detect
            else {
                return Err(Error::Unsupported);
            };
            if version != &metadata.version {
                return Err(Error::Unsupported);
            }
            Identity::WindowsMsi {
                product: Uuid::parse_str(product_code.trim_matches(['{', '}']))
                    .map_err(|_| Error::Malformed)?,
                publisher: publisher.clone(),
            }
        }
        (resource::SoftwareBehavior::Msix(native), Packaging::WindowsMsix { publisher, .. }) => {
            if publisher != &native.identity.publisher {
                return Err(Error::Unsupported);
            }
            Identity::WindowsMsix {
                family: family(&native.identity.name, publisher),
                identity: native.identity.clone(),
                minimum_os: native.minimum_os,
            }
        }
        (resource::SoftwareBehavior::Pkg(native), Packaging::MacosPkg { bundle, team, .. }) => {
            let resource::SoftwareDetection::PkgReceipt { receipt, version } = &native.detect
            else {
                return Err(Error::Unsupported);
            };
            if version != &metadata.version {
                return Err(Error::Unsupported);
            }
            Identity::Macos {
                receipt: receipt.clone(),
                bundle: bundle.clone(),
                team: team.clone(),
            }
        }
        _ => return Err(Error::Unsupported),
    };
    identity.validate()?;
    Ok(identity)
}
#[cfg(test)]
mod tests {
    #[test]
    fn microsoft_publisher_identity_matches_platform_reference() {
        assert_eq!(
            super::family(
                "Microsoft.Windows.Photos",
                "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            ),
            "Microsoft.Windows.Photos_8wekyb3d8bbwe"
        );
    }
}
