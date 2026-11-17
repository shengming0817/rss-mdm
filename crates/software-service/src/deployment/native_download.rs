//! Product download signing over the original frozen software facts.
//! ref: object_store 0.14.2 src/signer.rs (credential owner issues the URL).
use super::{Task, native::Package};
use crate::catalog::Error;
use rss_mdm_native_protection::Protector;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Canonical software download path, consumed by the HTTP ingress registration.
pub const PACKAGE_PATH: &str = "/api/v1/software/installations/{id}/package";

/// Publication-time inputs; rebuilding a task never substitutes the current host configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSoftware {
    pub origin: String,
    pub packages: BTreeMap<rss_mdm_policy::SoftwareTarget, Package>,
}

impl NativeSoftware {
    pub fn task(
        &self,
        package: &Package,
        operation: Uuid,
        protection: &Protector,
        tenant: TenantId,
    ) -> Result<Task, Error> {
        let aad = aad(tenant, operation)?;
        let tag = protection
            .mac(
                &serde_json::to_vec(&package.artifact).map_err(|_| Error::Input)?,
                &aad,
            )
            .map_err(|_| Error::Integrity)?;
        let token = tag
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PACKAGE_PATH.replace("{id}", &operation.to_string());
        let url = format!("{}{path}?token={token}", self.origin.trim_end_matches('/'));
        package.task(operation, &url)
    }

    pub fn package_for_task(
        &self,
        operation: Uuid,
        protection: &Protector,
        tenant: TenantId,
        task: &Task,
    ) -> Result<Option<&Package>, Error> {
        let actual = serde_json::to_value(task).map_err(|_| Error::Input)?;
        for package in self.packages.values() {
            let expected = self.task(package, operation, protection, tenant)?;
            if serde_json::to_value(expected).map_err(|_| Error::Input)? == actual {
                return Ok(Some(package));
            }
        }
        Ok(None)
    }
}

/// A locator or caller-supplied URL confers no authority; verify the original artifact binding.
pub(crate) fn verify_token(
    protection: &Protector,
    tenant: TenantId,
    operation: Uuid,
    artifact: &rss_mdm_resource::SoftwareArtifact,
    token: &str,
) -> Result<(), Error> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::NotAdmitted);
    }
    let mut tag = [0u8; 32];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&token[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::NotAdmitted)?;
    }
    protection
        .verify_mac(
            &serde_json::to_vec(artifact).map_err(|_| Error::Input)?,
            &aad(tenant, operation)?,
            &tag,
        )
        .map_err(|_| Error::NotAdmitted)
}

fn aad(tenant: TenantId, operation: Uuid) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    rss_mdm_native_protection::canonical::aad(tenant, "software.download", &operation)
        .map_err(|_| Error::Input)
}

#[cfg(test)]
mod tests {
    use super::super::native::Identity;
    use super::*;
    use rss_mdm_policy::SoftwareTarget;
    use rss_mdm_resource as r;

    #[test]
    fn frozen_download_binds_tenant_operation_and_artifact_for_every_platform() {
        let protector = Protector::new(&[57; 32]).unwrap();
        let tenant = TenantId::parse(&Uuid::new_v4().to_string()).unwrap();
        let operation = Uuid::new_v4();
        let identities = [
            Identity::Msi {
                product: Uuid::new_v4(),
                version: "1.2".into(),
            },
            Identity::Msix {
                family: "Acme.App_0123456789abc".into(),
                identity: r::MsixIdentity {
                    name: "Acme.App".into(),
                    publisher: "CN=Acme".into(),
                    version: [1, 2, 0, 0],
                    architecture: r::MsixArchitecture::X86_64,
                    resource_id: String::new(),
                },
            },
            Identity::Pkg {
                receipt: "com.acme.app".into(),
                version: "1.2".into(),
            },
        ];
        for identity in identities {
            let package = Package {
                identity,
                artifact: r::SoftwareArtifact {
                    reference: "package".into(),
                    origin: None,
                    length: 3,
                    sha256: r::Digest::of(b"msi").bytes(),
                },
                timeout_seconds: 600,
                minimum_os: None,
            };
            let frozen = NativeSoftware {
                origin: "https://frozen.example.test/".into(),
                packages: [(SoftwareTarget::WindowsX86_64, package.clone())].into(),
            };
            let task = frozen
                .task(&package, operation, &protector, tenant)
                .unwrap();
            let url = format!(
                "https://frozen.example.test/api/v1/software/installations/{operation}/package?token="
            );
            let encoded = serde_json::to_string(&task).unwrap();
            let start = encoded
                .find(&url)
                .expect("native platform consumes the signed URL")
                + url.len();
            let token = &encoded[start..start + 64];
            verify_token(&protector, tenant, operation, &package.artifact, token).unwrap();
            assert!(
                verify_token(&protector, tenant, Uuid::new_v4(), &package.artifact, token).is_err()
            );
            assert!(
                verify_token(
                    &protector,
                    TenantId::parse(&Uuid::new_v4().to_string()).unwrap(),
                    operation,
                    &package.artifact,
                    token
                )
                .is_err()
            );
            let mut changed = package.artifact.clone();
            changed.sha256[0] ^= 1;
            assert!(verify_token(&protector, tenant, operation, &changed, token).is_err());
            assert!(
                verify_token(&protector, tenant, operation, &package.artifact, "invalid").is_err()
            );
            let restarted: NativeSoftware =
                serde_json::from_value(serde_json::to_value(&frozen).unwrap()).unwrap();
            assert!(
                restarted
                    .package_for_task(
                        operation,
                        &Protector::new(&[57; 32]).unwrap(),
                        tenant,
                        &task
                    )
                    .unwrap()
                    .is_some()
            );
            let changed_host = NativeSoftware {
                origin: "https://new.example.test".into(),
                ..restarted
            };
            assert!(
                changed_host
                    .package_for_task(operation, &protector, tenant, &task)
                    .unwrap()
                    .is_none()
            );
        }
    }
}
