//! Production query declarations own paging and fields. Only compiled catalogs have static descriptions.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Description {
    ResourceOwner,
    QueryOwner,
    SourceCatalog {
        id: &'static str,
        source: &'static str,
        order: &'static str,
    },
}
pub static RESOURCE: Description = Description::ResourceOwner;
pub static BLUEPRINTS: Description = Description::SourceCatalog {
    id: "blueprints",
    source: "crates/resource/src/blueprints.rs",
    order: "catalog construction order",
};
pub static WEBHOOK_TYPES: Description = Description::SourceCatalog {
    id: "webhook_types",
    source: "crates/webhook-service/src/model.rs",
    order: "declaration order",
};
pub static ADE_DEVICES: Description = Description::QueryOwner;
pub static ADE_PROFILES: Description = Description::QueryOwner;
pub static AGENT_CONFIGURATIONS: Description = Description::QueryOwner;
pub static AGENT_PACKAGES: Description = Description::QueryOwner;
pub static API_KEYS: Description = Description::QueryOwner;
pub static APPLE_ACCOUNTS: Description = Description::QueryOwner;
pub static APPLE_MATERIAL_VERSIONS: Description = Description::QueryOwner;
pub static APPLE_ORGANIZATIONS: Description = Description::QueryOwner;
pub static ASSET_FIELDS: Description = Description::QueryOwner;
pub static ASSET_RESULTS: Description = Description::QueryOwner;
pub static ASSOCIATION_CHANGES: Description = Description::QueryOwner;
pub static AUDIT: Description = Description::QueryOwner;
pub static AUTHORIZATION_RULES: Description = Description::QueryOwner;
pub static CERTIFICATES: Description = Description::QueryOwner;
pub static CERTIFICATE_VERSIONS: Description = Description::QueryOwner;
pub static COMPLIANCE_RULES: Description = Description::QueryOwner;
pub static DEVICES: Description = Description::QueryOwner;
pub static DEVICE_ACCESS: Description = Description::QueryOwner;
pub static DEVICE_ASSOCIATIONS: Description = Description::QueryOwner;
pub static DEVICE_TIMELINE: Description = Description::QueryOwner;
pub static DEVICE_VIEWS: Description = Description::QueryOwner;
pub static ENTERPRISE_CONFIGURATION: Description = Description::QueryOwner;
pub static EXECUTIONS: Description = Description::QueryOwner;
pub static GROUPS: Description = Description::QueryOwner;
pub static POLICIES: Description = Description::QueryOwner;
pub static PROVISIONINGS: Description = Description::QueryOwner;
pub static PUBLICATIONS: Description = Description::QueryOwner;
pub static PUBLICATION_TARGETS: Description = Description::QueryOwner;
pub static RECOVERY_CREDENTIALS: Description = Description::QueryOwner;
pub static SAVED_QUERIES: Description = Description::QueryOwner;
pub static SCOPES: Description = Description::QueryOwner;
pub static SMTP_VERSIONS: Description = Description::QueryOwner;
pub static SOFTWARE_SOURCES: Description = Description::QueryOwner;
pub static SOFTWARE_VERSIONS: Description = Description::QueryOwner;
pub static STORAGE_CONNECTION_VERSIONS: Description = Description::QueryOwner;
pub static TENANTS: Description = Description::QueryOwner;
pub static USER_ATTRIBUTES: Description = Description::QueryOwner;
pub static USER_GROUPS: Description = Description::QueryOwner;
pub static USER_GROUP_MEMBERS: Description = Description::QueryOwner;
pub static WEBHOOK_DELIVERIES: Description = Description::QueryOwner;
pub static WEBHOOK_SUBSCRIPTIONS: Description = Description::QueryOwner;
pub static WNS_VERSIONS: Description = Description::QueryOwner;

pub fn valid(resource: &crate::Resource) -> bool {
    use crate::{Category, Operation, QueryPolicy};
    match resource.collection {
        None => {
            !resource.category.required().contains(&Operation::List)
                && matches!(
                    resource.query,
                    QueryPolicy::NotCollection | QueryPolicy::Protocol | QueryPolicy::Unified
                )
        }
        Some(Description::QueryOwner) => resource.query == QueryPolicy::Unified,
        Some(Description::ResourceOwner) => {
            resource.id == "resource" && resource.query == QueryPolicy::ResourceV1
        }
        Some(Description::SourceCatalog { id, source, order }) => {
            resource.id == *id
                && resource.category == Category::Facts
                && resource.query == QueryPolicy::SourceCatalog
                && !source.is_empty()
                && !order.is_empty()
        }
    }
}

pub static MANAGEMENT_ACTIVITIES: Description = Description::QueryOwner;

pub static PKI_ROTATION_BLOCKERS: Description = Description::QueryOwner;

pub static AGENT_REQUESTS: Description = Description::QueryOwner;
pub static AGENT_ISSUANCE_RECOVERY_OPERATIONS: Description = Description::QueryOwner;

pub static WINDOWS_CERTIFICATE_REQUESTS: Description = Description::QueryOwner;
pub static WINDOWS_SIGNING_RECOVERY_OPERATIONS: Description = Description::QueryOwner;
