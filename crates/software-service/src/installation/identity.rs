use super::package::Identity;
use crate::catalog::Error;
use rss_mdm_resource as resource;
use uuid::Uuid;
/// Detection and execution consume the same published native identity.
pub fn identity(
    release: &crate::agent_packages::AdmittedPackage,
) -> std::result::Result<Identity, Error> {
    let spec = &release.software;
    let metadata = &release.metadata;
    let identity = match spec.behavior.as_ref().ok_or(Error::Unsupported)? {
        resource::SoftwareBehavior::Msi(native) => {
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
                    .map_err(|_| Error::Input)?,
                publisher: None,
            }
        }
        resource::SoftwareBehavior::Msix(native) => Identity::WindowsMsix {
            family: crate::deployment::identity::family(
                &native.identity.name,
                &native.identity.publisher,
            ),
            identity: native.identity.clone(),
            minimum_os: native.minimum_os,
        },
        resource::SoftwareBehavior::Pkg(native) => {
            let resource::SoftwareDetection::PkgReceipt { receipt, version } = &native.detect
            else {
                return Err(Error::Unsupported);
            };
            if version != &metadata.version {
                return Err(Error::Unsupported);
            }
            let bundle = spec.material.bundle_id.as_ref().ok_or(Error::Unsupported)?;
            Identity::Macos {
                receipt: receipt.clone(),
                bundle: bundle.clone(),
                team: String::new(),
            }
        }
        _ => return Err(Error::Unsupported),
    };
    identity.validate()?;
    Ok(identity)
}
