//! Product resource inventory: required semantics exist independently of route registration.
use crate::{Category, QueryPolicy, Resource};
pub static ADE_CONFIGURATION: Resource = Resource {
    id: "ade_configuration",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.ade",
    query: QueryPolicy::NotCollection,
};
pub static ADE_DEVICES: Resource = Resource {
    id: "ade_devices",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.ade",
    query: QueryPolicy::Pending(2906),
};
pub static ADE_PROFILES: Resource = Resource {
    id: "ade_profiles",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.ade",
    query: QueryPolicy::Pending(2906),
};
pub static AGENT_CONFIGURATIONS: Resource = Resource {
    id: "agent_configurations",
    category: Category::Signed,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::Pending(2902),
};
pub static AGENT_CONFIGURATION_OPERATIONS: Resource = Resource {
    id: "agent_configuration_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
};
pub static AGENT_CONNECTIONS: Resource = Resource {
    id: "agent_connections",
    category: Category::Singleton,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
};
pub static AGENT_CONNECTION_OPERATIONS: Resource = Resource {
    id: "agent_connection_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
};
pub static AGENT_ENROLLMENT_SETTINGS: Resource = Resource {
    id: "agent_enrollment_settings",
    category: Category::Singleton,
    owner: "management-http",
    proof: "agent.configurations",
    query: QueryPolicy::NotCollection,
};
pub static AGENT_ISSUANCE_RECOVERY: Resource = Resource {
    id: "agent_issuance_recovery",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.registration",
    query: QueryPolicy::NotCollection,
};
pub static AGENT_PACKAGES: Resource = Resource {
    id: "agent_packages",
    category: Category::Signed,
    owner: "management-http",
    proof: "software.catalog",
    query: QueryPolicy::Pending(2902),
};
pub static AGENT_REGISTRATION_RECOVERY: Resource = Resource {
    id: "agent_registration_recovery",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.registration",
    query: QueryPolicy::NotCollection,
};
pub static AGENT_REQUEST_COMMANDS: Resource = Resource {
    id: "agent_request_commands",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.registration",
    query: QueryPolicy::NotCollection,
};
pub static API_KEYS: Resource = Resource {
    id: "api_keys",
    category: Category::Signed,
    owner: "management-http",
    proof: "authorization.programmatic",
    query: QueryPolicy::Pending(2906),
};
pub static API_NETWORK_POLICY: Resource = Resource {
    id: "api_network_policy",
    category: Category::Singleton,
    owner: "management-http",
    proof: "authorization.programmatic",
    query: QueryPolicy::NotCollection,
};
pub static APPLE_ACCOUNT_CONFIGURATION: Resource = Resource {
    id: "apple_account_configuration",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::NotCollection,
};
pub static APPLE_MATERIALS: Resource = Resource {
    id: "apple_materials",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::NotCollection,
};
pub static APPLE_MATERIAL_OPERATIONS: Resource = Resource {
    id: "apple_material_operations",
    category: Category::ReadModel,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::NotCollection,
};
pub static APPLE_ORGANIZATIONS: Resource = Resource {
    id: "apple_organizations",
    category: Category::Facts,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::Pending(2906),
};
pub static ASSET_FIELDS: Resource = Resource {
    id: "asset_fields",
    category: Category::Mutable,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::Pending(2904),
};
pub static ASSET_LAYOUT: Resource = Resource {
    id: "asset_layout",
    category: Category::Singleton,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::NotCollection,
};
pub static ASSET_QUERIES: Resource = Resource {
    id: "asset_queries",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "assets.queries",
    query: QueryPolicy::Pending(2904),
};
pub static ASSET_RETENTION: Resource = Resource {
    id: "asset_retention",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "assets.http",
    query: QueryPolicy::NotCollection,
};
pub static AUDIT: Resource = Resource {
    id: "audit",
    category: Category::Facts,
    owner: "management-http",
    proof: "timeline.http",
    query: QueryPolicy::Pending(2906),
};
pub static AUTHORIZATION_DEPARTMENTS: Resource = Resource {
    id: "authorization_departments",
    category: Category::Facts,
    owner: "management-http",
    proof: "authorization.membership",
    query: QueryPolicy::FixedWindow,
};
pub static AUTHORIZATION_RULES: Resource = Resource {
    id: "authorization_rules",
    category: Category::Mutable,
    owner: "management-http",
    proof: "authorization.rules",
    query: QueryPolicy::Pending(2906),
};
pub static BLUEPRINTS: Resource = Resource {
    id: "blueprints",
    category: Category::Facts,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::FixedWindow,
};
pub static CERTIFICATES: Resource = Resource {
    id: "certificates",
    category: Category::Signed,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::Pending(2906),
};
pub static CERTIFICATE_OPERATIONS: Resource = Resource {
    id: "certificate_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::NotCollection,
};
pub static CERTIFICATE_SETTINGS: Resource = Resource {
    id: "certificate_settings",
    category: Category::Singleton,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::NotCollection,
};
pub static CERTIFICATE_VAULT: Resource = Resource {
    id: "certificate_vault",
    category: Category::Singleton,
    owner: "management-http",
    proof: "certificate-archive.http",
    query: QueryPolicy::NotCollection,
};
pub static COMPLIANCE_RULES: Resource = Resource {
    id: "compliance_rules",
    category: Category::Mutable,
    owner: "management-http",
    proof: "compliance.http",
    query: QueryPolicy::Pending(2902),
};
pub static CONTENT_MAINTENANCE: Resource = Resource {
    id: "content_maintenance",
    category: Category::Command,
    owner: "management-http",
    proof: "content.gc",
    query: QueryPolicy::NotCollection,
};
pub static DEVICES: Resource = Resource {
    id: "devices",
    category: Category::Projection,
    owner: "management-http",
    proof: "enrollment.http",
    query: QueryPolicy::Pending(2904),
};
pub static DEVICE_ASSOCIATIONS: Resource = Resource {
    id: "device_associations",
    category: Category::Signed,
    owner: "management-http",
    proof: "device.views",
    query: QueryPolicy::Pending(2904),
};
pub static DEVICE_RETIREMENTS: Resource = Resource {
    id: "device_retirements",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "device.revocation",
    query: QueryPolicy::NotCollection,
};
pub static DEVICE_VIEWS: Resource = Resource {
    id: "device_views",
    category: Category::Projection,
    owner: "management-http",
    proof: "device.views",
    query: QueryPolicy::Pending(2904),
};
pub static DIAGNOSTICS: Resource = Resource {
    id: "diagnostics",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "diagnostics.http",
    query: QueryPolicy::NotCollection,
};
pub static DOWNLOAD_AGENT_CHANNEL: Resource = Resource {
    id: "download_agent_channel",
    category: Category::Download,
    owner: "agent-channel",
    proof: "agent.registration",
    query: QueryPolicy::Protocol,
};
pub static DOWNLOAD_APPLE_CHANNEL: Resource = Resource {
    id: "download_apple_channel",
    category: Category::Download,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::Protocol,
};
pub static DOWNLOAD_MANAGEMENT_HTTP: Resource = Resource {
    id: "download_management_http",
    category: Category::Download,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Protocol,
};
pub static EFFECTIVE_AUTHORITY: Resource = Resource {
    id: "effective_authority",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "authorization.rules",
    query: QueryPolicy::NotCollection,
};
pub static ENROLLMENT_ATTEMPTS: Resource = Resource {
    id: "enrollment_attempts",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "enrollment.http",
    query: QueryPolicy::NotCollection,
};
pub static ENTRA_POLICY: Resource = Resource {
    id: "entra_policy",
    category: Category::Singleton,
    owner: "management-http",
    proof: "windows.entra",
    query: QueryPolicy::NotCollection,
};
pub static EXECUTIONS: Resource = Resource {
    id: "executions",
    category: Category::Facts,
    owner: "management-http",
    proof: "execution.agent.history",
    query: QueryPolicy::Pending(2904),
};
pub static FIRST_USE: Resource = Resource {
    id: "first_use",
    category: Category::Singleton,
    owner: "management-http",
    proof: "settings.first_use",
    query: QueryPolicy::NotCollection,
};
pub static GROUPS: Resource = Resource {
    id: "groups",
    category: Category::Mutable,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Pending(2902),
};
pub static HEALTH: Resource = Resource {
    id: "health",
    category: Category::Health,
    owner: "app",
    proof: "api.diagnostics",
    query: QueryPolicy::Protocol,
};
pub static IDENTITY_CONTEXT: Resource = Resource {
    id: "identity_context",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "api.identity_context",
    query: QueryPolicy::NotCollection,
};
pub static PKI_OPERATIONS: Resource = Resource {
    id: "pki_operations",
    category: Category::Command,
    owner: "management-http",
    proof: "agent.pki",
    query: QueryPolicy::NotCollection,
};
pub static POLICIES: Resource = Resource {
    id: "policies",
    category: Category::Mutable,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Pending(2902),
};
pub static PROTOCOL_AGENT_CHANNEL: Resource = Resource {
    id: "protocol_agent_channel",
    category: Category::Protocol,
    owner: "agent-channel",
    proof: "agent.registration",
    query: QueryPolicy::Protocol,
};
pub static PROTOCOL_APPLE_CHANNEL: Resource = Resource {
    id: "protocol_apple_channel",
    category: Category::Protocol,
    owner: "apple-channel",
    proof: "apple.host",
    query: QueryPolicy::Protocol,
};
pub static PROTOCOL_MANAGEMENT_HTTP: Resource = Resource {
    id: "protocol_management_http",
    category: Category::Protocol,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Protocol,
};
pub static PROTOCOL_WINDOWS_CHANNEL: Resource = Resource {
    id: "protocol_windows_channel",
    category: Category::Protocol,
    owner: "windows-channel",
    proof: "windows.enrollment",
    query: QueryPolicy::Protocol,
};
pub static PROVISIONINGS: Resource = Resource {
    id: "provisionings",
    category: Category::Facts,
    owner: "app",
    proof: "installation.tenants",
    query: QueryPolicy::Pending(2906),
};
pub static PUBLICATIONS: Resource = Resource {
    id: "publications",
    category: Category::Signed,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::Pending(2902),
};
pub static PUBLICATION_TARGETS: Resource = Resource {
    id: "publication_targets",
    category: Category::Facts,
    owner: "management-http",
    proof: "software.http",
    query: QueryPolicy::FixedWindow,
};
pub static REGISTRATION_CHANNELS: Resource = Resource {
    id: "registration_channels",
    category: Category::Singleton,
    owner: "management-http",
    proof: "enrollment.http",
    query: QueryPolicy::NotCollection,
};
pub static REGISTRATION_DEFAULT_QUOTA: Resource = Resource {
    id: "registration_default_quota",
    category: Category::Singleton,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
};
pub static REGISTRATION_QUOTA_USAGE: Resource = Resource {
    id: "registration_quota_usage",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
};
pub static REGISTRATION_USER_QUOTA: Resource = Resource {
    id: "registration_user_quota",
    category: Category::Singleton,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::NotCollection,
};
pub static RESOURCE: Resource = Resource {
    id: "resource",
    category: Category::Versioned,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::ResourceV1,
};
pub static SAVED_QUERIES: Resource = Resource {
    id: "saved_queries",
    category: Category::Mutable,
    owner: "management-http",
    proof: "assets.queries",
    query: QueryPolicy::Pending(2902),
};
pub static SCOPES: Resource = Resource {
    id: "scopes",
    category: Category::Mutable,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::Pending(2902),
};
pub static SELF_ENROLLMENTS: Resource = Resource {
    id: "self_enrollments",
    category: Category::Facts,
    owner: "management-http",
    proof: "enrollment.quotas",
    query: QueryPolicy::FixedWindow,
};
pub static SETTINGS_CATALOG: Resource = Resource {
    id: "settings_catalog",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "settings.first_use",
    query: QueryPolicy::NotCollection,
};
pub static SMTP: Resource = Resource {
    id: "smtp",
    category: Category::Singleton,
    owner: "management-http",
    proof: "installation.smtp",
    query: QueryPolicy::NotCollection,
};
pub static SOFTWARE_SOURCES: Resource = Resource {
    id: "software_sources",
    category: Category::Versioned,
    owner: "management-http",
    proof: "software.catalog",
    query: QueryPolicy::Pending(2902),
};
pub static SOFTWARE_VERSIONS: Resource = Resource {
    id: "software_versions",
    category: Category::Versioned,
    owner: "management-http",
    proof: "software.catalog",
    query: QueryPolicy::Pending(2902),
};
pub static STORAGE_CONNECTIONS: Resource = Resource {
    id: "storage_connections",
    category: Category::Singleton,
    owner: "management-http",
    proof: "installation.storage_reconcile",
    query: QueryPolicy::NotCollection,
};
pub static TASK_TRUST: Resource = Resource {
    id: "task_trust",
    category: Category::Singleton,
    owner: "management-http",
    proof: "execution.agent.task_trust",
    query: QueryPolicy::NotCollection,
};
pub static TASK_TRUST_OPERATIONS: Resource = Resource {
    id: "task_trust_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "execution.agent.task_trust",
    query: QueryPolicy::NotCollection,
};
pub static TELEMETRY_QUERIES: Resource = Resource {
    id: "telemetry_queries",
    category: Category::Command,
    owner: "management-http",
    proof: "telemetry.storage",
    query: QueryPolicy::NotCollection,
};
pub static TENANTS: Resource = Resource {
    id: "tenants",
    category: Category::Mutable,
    owner: "app",
    proof: "installation.tenants",
    query: QueryPolicy::Pending(2906),
};
pub static USER_ATTRIBUTES: Resource = Resource {
    id: "user_attributes",
    category: Category::Mutable,
    owner: "management-http",
    proof: "settings.user_profiles",
    query: QueryPolicy::Pending(2906),
};
pub static USER_ATTRIBUTE_OPERATIONS: Resource = Resource {
    id: "user_attribute_operations",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "settings.user_profiles",
    query: QueryPolicy::NotCollection,
};
pub static USER_GROUPS: Resource = Resource {
    id: "user_groups",
    category: Category::Mutable,
    owner: "management-http",
    proof: "authorization.rules",
    query: QueryPolicy::Pending(2906),
};
pub static USER_PROFILES: Resource = Resource {
    id: "user_profiles",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "settings.user_profiles",
    query: QueryPolicy::NotCollection,
};
pub static WEBHOOK_DELIVERIES: Resource = Resource {
    id: "webhook_deliveries",
    category: Category::Facts,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::Pending(2906),
};
pub static WEBHOOK_HEALTH: Resource = Resource {
    id: "webhook_health",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::NotCollection,
};
pub static WEBHOOK_MATERIALS: Resource = Resource {
    id: "webhook_materials",
    category: Category::Singleton,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::NotCollection,
};
pub static WEBHOOK_SUBSCRIPTIONS: Resource = Resource {
    id: "webhook_subscriptions",
    category: Category::Mutable,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::Pending(2906),
};
pub static WEBHOOK_TYPES: Resource = Resource {
    id: "webhook_types",
    category: Category::Facts,
    owner: "management-http",
    proof: "webhooks.product",
    query: QueryPolicy::FixedWindow,
};
pub static WNS: Resource = Resource {
    id: "wns",
    category: Category::Singleton,
    owner: "windows-channel",
    proof: "windows.push_transport",
    query: QueryPolicy::NotCollection,
};
pub static WORKSPACE: Resource = Resource {
    id: "workspace",
    category: Category::ReadModel,
    owner: "management-http",
    proof: "planning.http",
    query: QueryPolicy::NotCollection,
};
pub static ALL: &[&Resource] = &[
    &DEVICE_ACCESS,
    &RECOVERY_CREDENTIALS,
    &DEVICE_TIMELINE,
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

/// Exact pre-existing operation gaps, retired by the named implementation PBI.
/// A satisfied entry is an error: migration never retains a stale exemption.
pub static GAPS: &[crate::Gap] = &[
    crate::Gap {
        resource: "device_access",
        operation: crate::Operation::Get,
        issue: 2906,
        reason: "binding read currently exists only in device collection",
    },
    crate::Gap {
        resource: "apple_account_bindings",
        operation: crate::Operation::Get,
        issue: 2906,
        reason: "account configuration is embedded in organization List",
    },
    crate::Gap {
        resource: "agent_configurations",
        operation: crate::Operation::List,
        issue: 2902,
        reason: "signed configuration collection has no management List",
    },
    crate::Gap {
        resource: "agent_packages",
        operation: crate::Operation::Get,
        issue: 2902,
        reason: "public package metadata is not a management Get",
    },
    crate::Gap {
        resource: "apple_account_configuration",
        operation: crate::Operation::Get,
        issue: 2906,
        reason: "configuration is embedded in the organization directory",
    },
    crate::Gap {
        resource: "asset_fields",
        operation: crate::Operation::Get,
        issue: 2904,
        reason: "field descriptors are currently read through the catalog",
    },
    crate::Gap {
        resource: "authorization_rules",
        operation: crate::Operation::Get,
        issue: 2906,
        reason: "no independent rule detail route",
    },
    crate::Gap {
        resource: "certificates",
        operation: crate::Operation::Get,
        issue: 2906,
        reason: "entry metadata is currently returned by List and history",
    },
    crate::Gap {
        resource: "compliance_rules",
        operation: crate::Operation::Delete,
        issue: 2902,
        reason: "disable is not rule deletion",
    },
    crate::Gap {
        resource: "software_versions",
        operation: crate::Operation::List,
        issue: 2902,
        reason: "version listing belongs to the Resource aggregate read",
    },
    crate::Gap {
        resource: "user_groups",
        operation: crate::Operation::Get,
        issue: 2906,
        reason: "no independent user-group detail route",
    },
];

/// Browser expectations come from product configuration, never from observed endpoints.
pub fn browser(installation: bool, agent: bool, recovery: bool) -> Vec<&'static Resource> {
    ALL.iter()
        .copied()
        .filter(|r| {
            !matches!(r.id, "protocol_agent_channel" | "download_agent_channel")
                && (agent || r.id != "device_access")
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
    query: QueryPolicy::Pending(2906),
};

pub static RECOVERY_CREDENTIALS: Resource = Resource {
    id: "recovery_credentials",
    category: Category::Facts,
    owner: "management-http",
    proof: "recovery-credentials.http",
    query: QueryPolicy::Pending(2906),
};

pub static DEVICE_TIMELINE: Resource = Resource {
    id: "device_timeline",
    category: Category::Facts,
    owner: "management-http",
    proof: "timeline.http",
    query: QueryPolicy::Pending(2906),
};

pub static PLATFORM_SSO_CONFIGURATION: Resource = Resource {
    id: "platform_sso_configuration",
    category: Category::ReadModel,
    owner: "apple-channel",
    proof: "apple.platform_sso",
    query: QueryPolicy::NotCollection,
};

pub static APPLE_ACCOUNT_BINDINGS: Resource = Resource {
    id: "apple_account_bindings",
    category: Category::Singleton,
    owner: "apple-channel",
    proof: "apple.account_enrollment",
    query: QueryPolicy::Pending(2906),
};
