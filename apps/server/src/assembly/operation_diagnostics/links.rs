use super::*;
fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub(super) fn urls(
    tenant: &str,
    owner: O,
    id: Uuid,
    q: &rss_mdm_management_http::operation_diagnostics::LocatorQuery,
    receipt: &Evidence<ReceiptSummary>,
) -> (Option<String>, Option<String>) {
    let original = match owner {
        O::AgentConfiguration => Some(format!(
            "/api/v1/tenants/{tenant}/agent-configuration-operations/{id}"
        )),
        O::SoftwareCatalog => Some(format!(
            "/api/v1/tenants/{tenant}/agent-packages/operations/{id}"
        )),
        O::Content => q.target.as_ref().map(|target| {
            format!(
                "/api/v1/tenants/{tenant}/resources/{}/content/operations/{id}",
                segment(target)
            )
        }),
        O::SoftwareSourceSnapshot => q.target.as_ref().map(|target| {
            format!(
                "/api/v1/tenants/{tenant}/software/source-snapshots/{}/operations/{id}",
                segment(target)
            )
        }),
        O::Smtp => Some(format!("/api/v1/tenants/{tenant}/smtp/operations/{id}")),
        O::StorageConnection => Some(format!(
            "/api/v1/tenants/{tenant}/storage/connections/operations/{id}"
        )),
        O::StorageMigration => Some(format!(
            "/api/v1/tenants/{tenant}/storage/migrations/operations/{id}"
        )),
        O::TaskTrust => Some(format!(
            "/api/v1/tenants/{tenant}/task-signing/operations/{id}"
        )),
        O::FirstUse => Some(format!(
            "/api/v1/tenants/{tenant}/settings/first-use/operations/{id}"
        )),
        O::UserProfile => Some(format!(
            "/api/v1/tenants/{tenant}/user-attribute-operations/{id}"
        )),
        O::CertificateArchive => Some(format!(
            "/api/v1/tenants/{tenant}/certificate-archive/operations/{id}"
        )),
        O::AppleRuntimeMaterial => Some(format!(
            "/api/v1/tenants/{tenant}/apple/material-operations/{id}"
        )),
        O::WindowsWns => Some(format!(
            "/api/v1/tenants/{tenant}/windows/wns/operations/{id}"
        )),
        O::DeviceAccess => q.device.as_ref().map(|device| {
            format!(
                "/api/v1/tenants/{tenant}/devices/{}/device-access/operations/{id}",
                segment(&device.to_string())
            )
        }),
        _ => None,
    };
    let object = match receipt {
        Evidence::Available(v) => v.object.as_deref(),
        _ => None,
    };
    let current = object.and_then(|object| {
        let prefix = match owner {
            O::Resource => "resources",
            O::Policy => "policies",
            O::Group => "groups",
            O::Scope => "scopes",
            O::Compliance => "compliance-rules",
            O::CertificateArchive => "certificate-archive/entries",
            O::UserProfile => "user-attribute-definitions",
            _ => return None,
        };
        Some(format!(
            "/api/v1/tenants/{tenant}/{prefix}/{}",
            segment(object)
        ))
    });
    (original, current)
}
