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
            .mac(&serde_json::to_vec(&package.artifact).map_err(|_| Error::Input)?, &aad)
            .map_err(|_| Error::Integrity)?;
        let token = tag.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
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
        .verify_mac(&serde_json::to_vec(artifact).map_err(|_| Error::Input)?, &aad(tenant, operation)?, &tag)
        .map_err(|_| Error::NotAdmitted)
}

fn aad(tenant: TenantId, operation: Uuid) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    rss_mdm_native_protection::canonical::aad(tenant, "software.download", &operation)
        .map_err(|_| Error::Input)
}
