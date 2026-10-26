//! Product resource inventory: required semantics exist independently of route registration.
use crate::{Category, QueryPolicy, Resource};
pub static ADE_CONFIGURATION: Resource = Resource {
    id: "ade_configuration",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.ade",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static ADE_DEVICES: Resource = Resource {
    id: "ade_devices",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.ade",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::ADE_DEVICES),
};
pub static ADE_PROFILES: Resource = Resource {
    id: "ade_profiles",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.ade",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::ADE_PROFILES),
};
pub static AGENT_CONFIGURATIONS: Resource = Resource {
    id: "agent_configurations",
    category: Category::Signed,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::AGENT_CONFIGURATIONS),
};
pub static AGENT_CONFIGURATION_OPERATIONS: Resource = Resource {
    id: "agent_configuration_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AGENT_CONNECTIONS: Resource = Resource {
    id: "agent_connections",
    category: Category::Singleton,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AGENT_CONNECTION_OPERATIONS: Resource = Resource {
    id: "agent_connection_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AGENT_ENROLLMENT_SETTINGS: Resource = Resource {
    id: "agent_enrollment_settings",
    category: Category::Singleton,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AGENT_ISSUANCE_RECOVERY: Resource = Resource {
    id: "agent_issuance_recovery",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.registration",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AGENT_PACKAGES: Resource = Resource {
    id: "agent_packages",
    category: Category::Signed,
    owner: "management-http",
    proof: "software.catalog",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::AGENT_PACKAGES),
};
pub static AGENT_REGISTRATION_RECOVERY: Resource = Resource {
    id: "agent_registration_recovery",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.registration",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AGENT_REQUEST_COMMANDS: Resource = Resource {
    id: "agent_request_commands",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.registration",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static API_KEYS: Resource = Resource {
    id: "api_keys",
    category: Category::Signed,
    owner: "management-http",
    proof: "authorization.programmatic",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::API_KEYS),
};
pub static API_NETWORK_POLICY: Resource = Resource {
    id: "api_network_policy",
    category: Category::Singleton,
    owner: "management-http",
    proof: "authorization.programmatic",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static APPLE_ACCOUNT_CONFIGURATION: Resource = Resource {
    id: "apple_account_configuration",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static APPLE_MATERIALS: Resource = Resource {
    id: "apple_materials",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static APPLE_MATERIAL_OPERATIONS: Resource = Resource {
    id: "apple_material_operations",
    category: Category::ReadModel,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static APPLE_ORGANIZATIONS: Resource = Resource {
    id: "apple_organizations",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::APPLE_ORGANIZATIONS),
};
pub static ASSET_FIELDS: Resource = Resource {
    id: "asset_fields",
    category: Category::Mutable,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::ASSET_FIELDS),
};
pub static ASSET_LAYOUT: Resource = Resource {
    id: "asset_layout",
    category: Category::Singleton,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static ASSET_QUERIES: Resource = Resource {
    id: "asset_queries",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "assets.queries",
    query: QueryPolicy::Unified,
    collection: None,
};
pub static ASSET_RETENTION: Resource = Resource {
    id: "asset_retention",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AUDIT: Resource = Resource {
    id: "audit",
    category: Category::Facts,
    owner: "management-http",
    proof: "timeline.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::AUDIT),
};
pub static AUTHORIZATION_DEPARTMENTS: Resource = Resource {
    id: "authorization_departments",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "authorization.membership",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static AUTHORIZATION_RULES: Resource = Resource {
    id: "authorization_rules",
    category: Category::Mutable,
    owner: "management-http",
    proof: "authorization.rules",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::AUTHORIZATION_RULES),
};
pub static BLUEPRINTS: Resource = Resource {
    id: "blueprints",
    category: Category::Facts,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::SourceCatalog,
    collection: Some(&super::collections::BLUEPRINTS),
};
pub static CERTIFICATES: Resource = Resource {
    id: "certificates",
    category: Category::Signed,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::CERTIFICATES),
};
pub static CERTIFICATE_OPERATIONS: Resource = Resource {
    id: "certificate_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static CERTIFICATE_SETTINGS: Resource = Resource {
    id: "certificate_settings",
    category: Category::Singleton,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static CERTIFICATE_VAULT: Resource = Resource {
    id: "certificate_vault",
    category: Category::Singleton,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static COMPLIANCE_RULES: Resource = Resource {
    id: "compliance_rules",
    category: Category::Mutable,
    owner: "management-http",
    proof: "compliance.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::COMPLIANCE_RULES),
};
pub static CONTENT_MAINTENANCE: Resource = Resource {
    id: "content_maintenance",
    category: Category::Command,
    owner: "management-http",
    proof: "content.gc",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static DEVICES: Resource = Resource {
    id: "devices",
    category: Category::Projection,
    owner: "management-http",
    proof: "enrollment.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::DEVICES),
};
pub static DEVICE_ASSOCIATIONS: Resource = Resource {
    id: "device_associations",
    category: Category::Signed,
    owner: "management-http",
    proof: "device.views",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::DEVICE_ASSOCIATIONS),
};
pub static DEVICE_RETIREMENTS: Resource = Resource {
    id: "device_retirements",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "device.revocation",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static DEVICE_VIEWS: Resource = Resource {
    id: "device_views",
    category: Category::Projection,
    owner: "management-http",
    proof: "device.views",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::DEVICE_VIEWS),
};
pub static DIAGNOSTICS: Resource = Resource {
    id: "diagnostics",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "diagnostics.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static DOWNLOAD_AGENT_CHANNEL: Resource = Resource {
    id: "download_agent_channel",
    category: Category::Download,
    owner: "agent-channel",
    proof: "agent.registration",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static DOWNLOAD_APPLE_CHANNEL: Resource = Resource {
    id: "download_apple_channel",
    category: Category::Download,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static DOWNLOAD_MANAGEMENT_HTTP: Resource = Resource {
    id: "download_management_http",
    category: Category::Download,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static EFFECTIVE_AUTHORITY: Resource = Resource {
    id: "effective_authority",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "authorization.rules",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static ENROLLMENT_ATTEMPTS: Resource = Resource {
    id: "enrollment_attempts",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "enrollment.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static ENTRA_POLICY: Resource = Resource {
    id: "entra_policy",
    category: Category::Singleton,
    owner: "management-http",
    proof: "windows.entra",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static EXECUTIONS: Resource = Resource {
    id: "executions",
    category: Category::Facts,
    owner: "management-http",
    proof: "execution.agent.history",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::EXECUTIONS),
};
pub static FIRST_USE: Resource = Resource {
    id: "first_use",
    category: Category::Singleton,
    owner: "management-http",
    proof: "settings.first_use",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static GROUPS: Resource = Resource {
    id: "groups",
    category: Category::Mutable,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::GROUPS),
};
pub static HEALTH: Resource = Resource {
    id: "health",
    category: Category::Health,
    owner: "app",
    proof: "api.diagnostics",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static IDENTITY_CONTEXT: Resource = Resource {
    id: "identity_context",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "api.identity_context",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static PKI_OPERATIONS: Resource = Resource {
    id: "pki_operations",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.pki",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static POLICIES: Resource = Resource {
    id: "policies",
    category: Category::Mutable,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::POLICIES),
};
pub static PROTOCOL_AGENT_CHANNEL: Resource = Resource {
    id: "protocol_agent_channel",
    category: Category::Protocol,
    owner: "agent-channel",
    proof: "agent.registration",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static PROTOCOL_APPLE_CHANNEL: Resource = Resource {
    id: "protocol_apple_channel",
    category: Category::Protocol,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static PROTOCOL_MANAGEMENT_HTTP: Resource = Resource {
    id: "protocol_management_http",
    category: Category::Protocol,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static PROTOCOL_WINDOWS_CHANNEL: Resource = Resource {
    id: "protocol_windows_channel",
    category: Category::Protocol,
    owner: "windows-channel",
    proof: "windows.enrollment",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub static PROVISIONINGS: Resource = Resource {
    id: "provisionings",
    category: Category::Projection,
    owner: "app",
    proof: "installation.tenants",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::PROVISIONINGS),
};
pub static PUBLICATIONS: Resource = Resource {
    id: "publications",
    category: Category::Signed,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::PUBLICATIONS),
};
pub static PUBLICATION_TARGETS: Resource = Resource {
    id: "publication_targets",
    category: Category::Facts,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::PUBLICATION_TARGETS),
};
pub static REGISTRATION_CHANNELS: Resource = Resource {
    id: "registration_channels",
    category: Category::Singleton,
    owner: "management-http",
    proof: "enrollment.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static REGISTRATION_DEFAULT_QUOTA: Resource = Resource {
    id: "registration_default_quota",
    category: Category::Singleton,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static REGISTRATION_QUOTA_USAGE: Resource = Resource {
    id: "registration_quota_usage",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static REGISTRATION_USER_QUOTA: Resource = Resource {
    id: "registration_user_quota",
    category: Category::Singleton,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static RESOURCE: Resource = Resource {
    id: "resource",
    category: Category::Versioned,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::ResourceV1,
    collection: Some(&super::collections::RESOURCE),
};
pub static SAVED_QUERIES: Resource = Resource {
    id: "saved_queries",
    category: Category::Mutable,
    owner: "management-http",
    proof: "assets.queries",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::SAVED_QUERIES),
};
pub static SCOPES: Resource = Resource {
    id: "scopes",
    category: Category::Mutable,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::SCOPES),
};
pub static SELF_ENROLLMENTS: Resource = Resource {
    id: "self_enrollments",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static SETTINGS_CATALOG: Resource = Resource {
    id: "settings_catalog",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "settings.first_use",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static SMTP: Resource = Resource {
    id: "smtp",
    category: Category::Singleton,
    owner: "management-http",
    proof: "installation.smtp",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static SOFTWARE_SOURCES: Resource = Resource {
    id: "software_sources",
    category: Category::Versioned,
    owner: "management-http",
    proof: "software.catalog",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::SOFTWARE_SOURCES),
};
pub static SOFTWARE_VERSIONS: Resource = Resource {
    id: "software_versions",
    category: Category::Versioned,
    owner: "management-http",
    proof: "software.catalog",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::SOFTWARE_VERSIONS),
};
pub static STORAGE_CONNECTIONS: Resource = Resource {
    id: "storage_connections",
    category: Category::Singleton,
    owner: "management-http",
    proof: "installation.storage_reconcile",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static TASK_TRUST: Resource = Resource {
    id: "task_trust",
    category: Category::Singleton,
    owner: "management-http",
    proof: "execution.agent.task_trust",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static TASK_TRUST_OPERATIONS: Resource = Resource {
    id: "task_trust_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "execution.agent.task_trust",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static TELEMETRY_QUERIES: Resource = Resource {
    id: "telemetry_queries",
    category: Category::Command,
    owner: "management-http",
    proof: "telemetry.storage",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static TENANTS: Resource = Resource {
    id: "tenants",
    category: Category::Mutable,
    owner: "app",
    proof: "installation.tenants",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::TENANTS),
};
pub static USER_ATTRIBUTES: Resource = Resource {
    id: "user_attributes",
    category: Category::Mutable,
    owner: "management-http",
    proof: "settings.user_profiles",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::USER_ATTRIBUTES),
};
pub static USER_ATTRIBUTE_OPERATIONS: Resource = Resource {
    id: "user_attribute_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "settings.user_profiles",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static USER_GROUPS: Resource = Resource {
    id: "user_groups",
    category: Category::Mutable,
    owner: "management-http",
    proof: "authorization.rules",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::USER_GROUPS),
};
pub static USER_PROFILES: Resource = Resource {
    id: "user_profiles",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "settings.user_profiles",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static WEBHOOK_DELIVERIES: Resource = Resource {
    id: "webhook_deliveries",
    category: Category::Projection,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::WEBHOOK_DELIVERIES),
};
pub static WEBHOOK_HEALTH: Resource = Resource {
    id: "webhook_health",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static WEBHOOK_MATERIALS: Resource = Resource {
    id: "webhook_materials",
    category: Category::Singleton,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static WEBHOOK_SUBSCRIPTIONS: Resource = Resource {
    id: "webhook_subscriptions",
    category: Category::Mutable,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::WEBHOOK_SUBSCRIPTIONS),
};
pub static WEBHOOK_TYPES: Resource = Resource {
    id: "webhook_types",
    category: Category::Facts,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::SourceCatalog,
    collection: Some(&super::collections::WEBHOOK_TYPES),
};
pub static WNS: Resource = Resource {
    id: "wns",
    category: Category::Singleton,
    owner: "windows-channel",
    proof: "windows.push_transport",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static WORKSPACE: Resource = Resource {
    id: "workspace",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::NotCollection,
    collection: None,
};
pub static ALL: &[&Resource] = &[
    &POLICY_EVENT_BATCHES,
    &POLICY_EVENT_MEMBERS,
    &GROUP_REFERENCES,
    &INVENTORY_LIST_ITEMS,
    &INVENTORY_SCOPES,
    &ASSET_FACETS,
    &FIELD_REFERENCES,
    &COLLECTION_ITEMS,
    &DEVICE_ASSOCIATION_CANDIDATES,
    &DEVICE_VIEW_ITEMS,
    &DEVICE_DECLARATIONS,
    &DEVICE_GROUPS,
    &POLICY_ASSIGNMENTS,
    &POLICY_RUNS,
    &POLICY_PREVIEWS,
    &DEVICE_REGISTRATIONS,
    &GROUP_RESULTS,
    &SCOPE_RESULTS,
    &COMPLIANCE_HISTORY,
    &CERTIFICATE_VERSIONS,
    &APPLE_ACCOUNTS,
    &SMTP_VERSIONS,
    &STORAGE_CONNECTION_VERSIONS,
    &WNS_VERSIONS,
    &APPLE_MATERIAL_VERSIONS,
    &ASSOCIATION_CHANGES,
    &USER_GROUP_MEMBERS,
    &ASSET_RESULTS,
    &DEVICE_ACCESS,
    &ENTERPRISE_CONFIGURATION,
    &RECOVERY_CREDENTIALS,
    &DEVICE_TIMELINE,
    &MANAGEMENT_ACTIVITIES,
    &PLATFORM_SSO_CONFIGURATION,
    &APPLE_ACCOUNT_BINDINGS,
    &ADE_CONFIGURATION,
    &ADE_DEVICES,
    &ADE_PROFILES,
    &AGENT_CONFIGURATIONS,
    &AGENT_CONFIGURATION_OPERATIONS,
    &AGENT_CONNECTIONS,
    &AGENT_CONNECTION_OPERATIONS,
    &AGENT_ENROLLMENT_SETTINGS,
    &AGENT_ISSUANCE_RECOVERY,
    &AGENT_PACKAGES,
    &AGENT_REGISTRATION_RECOVERY,
    &AGENT_REQUEST_COMMANDS,
    &API_KEYS,
    &API_NETWORK_POLICY,
    &APPLE_ACCOUNT_CONFIGURATION,
    &APPLE_MATERIALS,
    &APPLE_MATERIAL_OPERATIONS,
    &APPLE_ORGANIZATIONS,
    &ASSET_FIELDS,
    &ASSET_LAYOUT,
    &ASSET_QUERIES,
    &ASSET_RETENTION,
    &AUDIT,
    &AUTHORIZATION_DEPARTMENTS,
    &AUTHORIZATION_RULES,
    &BLUEPRINTS,
    &CERTIFICATES,
    &CERTIFICATE_OPERATIONS,
    &CERTIFICATE_SETTINGS,
    &CERTIFICATE_VAULT,
    &COMPLIANCE_RULES,
    &CONTENT_MAINTENANCE,
    &DEVICES,
    &DEVICE_ASSOCIATIONS,
    &DEVICE_RETIREMENTS,
    &DEVICE_VIEWS,
    &DIAGNOSTICS,
    &DOWNLOAD_AGENT_CHANNEL,
    &DOWNLOAD_APPLE_CHANNEL,
    &DOWNLOAD_MANAGEMENT_HTTP,
    &EFFECTIVE_AUTHORITY,
    &ENROLLMENT_ATTEMPTS,
    &ENTRA_POLICY,
    &EXECUTIONS,
    &FIRST_USE,
    &GROUPS,
    &HEALTH,
    &IDENTITY_CONTEXT,
    &PKI_OPERATIONS,
    &POLICIES,
    &PROTOCOL_AGENT_CHANNEL,
    &PROTOCOL_APPLE_CHANNEL,
    &PROTOCOL_MANAGEMENT_HTTP,
    &PROTOCOL_WINDOWS_CHANNEL,
    &PROVISIONINGS,
    &PUBLICATIONS,
    &PUBLICATION_TARGETS,
    &REGISTRATION_CHANNELS,
    &REGISTRATION_DEFAULT_QUOTA,
    &REGISTRATION_QUOTA_USAGE,
    &REGISTRATION_USER_QUOTA,
    &RESOURCE,
    &SAVED_QUERIES,
    &SCOPES,
    &SELF_ENROLLMENTS,
    &SETTINGS_CATALOG,
    &SMTP,
    &SOFTWARE_SOURCES,
    &SOFTWARE_VERSIONS,
    &STORAGE_CONNECTIONS,
    &TASK_TRUST,
    &TASK_TRUST_OPERATIONS,
    &TELEMETRY_QUERIES,
    &TENANTS,
    &USER_ATTRIBUTES,
    &USER_ATTRIBUTE_OPERATIONS,
    &USER_GROUPS,
    &USER_PROFILES,
    &WEBHOOK_DELIVERIES,
    &WEBHOOK_HEALTH,
    &WEBHOOK_MATERIALS,
    &WEBHOOK_SUBSCRIPTIONS,
    &WEBHOOK_TYPES,
    &WNS,
    &WORKSPACE,
];

/// Browser expectations come from product configuration, never from observed endpoints.
pub fn browser(installation: bool, agent: bool, recovery: bool) -> Vec<&'static Resource> {
    ALL.iter()
        .copied()
        .filter(|r| {
            !matches!(r.id, "protocol_agent_channel" | "download_agent_channel")
                && (agent || !matches!(r.id, "device_access" | "enterprise_configuration"))
                && (recovery || r.id != "recovery_credentials")
                && (installation || !matches!(r.id, "tenants" | "provisionings"))
        })
        .collect()
}

pub static DEVICE_ACCESS: Resource = Resource {
    id: "device_access",
    category: Category::Signed,
    owner: "management-http",
    proof: "device-access.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::DEVICE_ACCESS),
};

pub static RECOVERY_CREDENTIALS: Resource = Resource {
    id: "recovery_credentials",
    category: Category::Facts,
    owner: "management-http",
    proof: "recovery-credentials.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::RECOVERY_CREDENTIALS),
};

pub static DEVICE_TIMELINE: Resource = Resource {
    id: "device_timeline",
    category: Category::Facts,
    owner: "management-http",
    proof: "timeline.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::DEVICE_TIMELINE),
};

pub static PLATFORM_SSO_CONFIGURATION: Resource = Resource {
    id: "platform_sso_configuration",
    category: Category::ReadModel,
    owner: "apple-channel",
    proof: "apple.platform_sso",
    query: QueryPolicy::NotCollection,
    collection: None,
};

pub static APPLE_ACCOUNT_BINDINGS: Resource = Resource {
    id: "apple_account_bindings",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::NotCollection,
    collection: None,
};

/// Native listeners have independent expectations, even when the browser exposes no such routes.
pub const WINDOWS_LISTENER: &[&Resource] = &[&PROTOCOL_WINDOWS_CHANNEL];
pub const APPLE_LISTENER: &[&Resource] = &[&PROTOCOL_APPLE_CHANNEL, &DOWNLOAD_APPLE_CHANNEL];
pub const AGENT_LISTENER: &[&Resource] = &[
    &PROTOCOL_AGENT_CHANNEL,
    &DOWNLOAD_AGENT_CHANNEL,
    &POLICY_EVENT_BATCHES,
    &POLICY_EVENT_MEMBERS,
    &PROTOCOL_APPLE_CHANNEL,
    &PROTOCOL_MANAGEMENT_HTTP,
    &DOWNLOAD_MANAGEMENT_HTTP,
];

pub static ASSOCIATION_CHANGES: Resource = Resource {
    id: "association_changes",
    category: Category::Facts,
    owner: "management-http",
    proof: "device.associations",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::ASSOCIATION_CHANGES),
};

pub static USER_GROUP_MEMBERS: Resource = Resource {
    id: "user_group_members",
    category: Category::Facts,
    owner: "management-http",
    proof: "authorization.membership",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::USER_GROUP_MEMBERS),
};

pub static ASSET_RESULTS: Resource = Resource {
    id: "asset_results",
    category: Category::Facts,
    owner: "management-http",
    proof: "assets.queries",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::ASSET_RESULTS),
};

pub static ENTERPRISE_CONFIGURATION: Resource = Resource {
    id: "enterprise_configuration",
    category: Category::Versioned,
    owner: "management-http",
    proof: "device-access.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::ENTERPRISE_CONFIGURATION),
};

pub static CERTIFICATE_VERSIONS: Resource = Resource {
    id: "certificate_versions",
    category: Category::Facts,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::CERTIFICATE_VERSIONS),
};

pub static APPLE_ACCOUNTS: Resource = Resource {
    id: "apple_accounts",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::APPLE_ACCOUNTS),
};

pub static SMTP_VERSIONS: Resource = Resource {
    id: "smtp_versions",
    category: Category::Facts,
    owner: "management-http",
    proof: "installation.smtp",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::SMTP_VERSIONS),
};

pub static STORAGE_CONNECTION_VERSIONS: Resource = Resource {
    id: "storage_connection_versions",
    category: Category::Facts,
    owner: "management-http",
    proof: "content.storage",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::STORAGE_CONNECTION_VERSIONS),
};

pub static WNS_VERSIONS: Resource = Resource {
    id: "wns_versions",
    category: Category::Facts,
    owner: "windows-channel",
    proof: "windows.management",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::WNS_VERSIONS),
};

pub static APPLE_MATERIAL_VERSIONS: Resource = Resource {
    id: "apple_material_versions",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::APPLE_MATERIAL_VERSIONS),
};

pub static POLICY_ASSIGNMENTS: Resource = Resource {
    id: "policy_assignments",
    category: Category::Facts,
    owner: "execution-service",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static POLICY_RUNS: Resource = Resource {
    id: "policy_runs",
    category: Category::Facts,
    owner: "execution-service",
    proof: "execution.agent.history",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static POLICY_PREVIEWS: Resource = Resource {
    id: "policy_previews",
    category: Category::Facts,
    owner: "execution-service",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static DEVICE_REGISTRATIONS: Resource = Resource {
    id: "device_registrations",
    category: Category::Facts,
    owner: "registration-service",
    proof: "enrollment.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static GROUP_RESULTS: Resource = Resource {
    id: "group_results",
    category: Category::Facts,
    owner: "inventory-service",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static SCOPE_RESULTS: Resource = Resource {
    id: "scope_results",
    category: Category::Facts,
    owner: "flow-service",
    proof: "planning.scope",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static COMPLIANCE_HISTORY: Resource = Resource {
    id: "compliance_history",
    category: Category::Facts,
    owner: "inventory-service",
    proof: "compliance.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static DEVICE_GROUPS: Resource = Resource {
    id: "device_groups",
    category: Category::Facts,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static DEVICE_DECLARATIONS: Resource = Resource {
    id: "device_declarations",
    category: Category::Facts,
    owner: "management-http",
    proof: "apple.ddm",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static DEVICE_VIEW_ITEMS: Resource = Resource {
    id: "device_view_items",
    category: Category::Facts,
    owner: "management-http",
    proof: "device.views",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static DEVICE_ASSOCIATION_CANDIDATES: Resource = Resource {
    id: "device_association_candidates",
    category: Category::Facts,
    owner: "management-http",
    proof: "device.associations",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static COLLECTION_ITEMS: Resource = Resource {
    id: "collection_items",
    category: Category::Facts,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static FIELD_REFERENCES: Resource = Resource {
    id: "field_references",
    category: Category::Facts,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static ASSET_FACETS: Resource = Resource {
    id: "asset_facets",
    category: Category::Facts,
    owner: "management-http",
    proof: "assets.queries",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static INVENTORY_SCOPES: Resource = Resource {
    id: "inventory_scopes",
    category: Category::Facts,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static INVENTORY_LIST_ITEMS: Resource = Resource {
    id: "inventory_list_items",
    category: Category::Facts,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static GROUP_REFERENCES: Resource = Resource {
    id: "group_references",
    category: Category::Facts,
    owner: "inventory-service",
    proof: "planning.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static POLICY_EVENT_BATCHES: Resource = Resource {
    id: "policy_event_batches",
    category: Category::Projection,
    owner: "flow-service",
    proof: "planning.custom_events",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};
pub static POLICY_EVENT_MEMBERS: Resource = Resource {
    id: "policy_event_members",
    category: Category::Facts,
    owner: "flow-service",
    proof: "planning.custom_events",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::Description::QueryOwner),
};

pub static MANAGEMENT_ACTIVITIES: Resource = Resource {
    id: "management_activities",
    category: Category::Facts,
    owner: "timeline-service",
    proof: "timeline.http",
    query: QueryPolicy::Unified,
    collection: Some(&super::collections::MANAGEMENT_ACTIVITIES),
};
