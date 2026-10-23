//! Current collection contracts, including explicitly incomplete legacy behavior.
//! These describe existing execution; Pending does not imply support for unified query inputs.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Field {
    pub name: &'static str,
    pub value_type: &'static str,
}
const fn f(name: &'static str, value_type: &'static str) -> Field {
    Field { name, value_type }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Paging {
    Keyset,
    Offset,
    Window,
    Unbounded,
    StaticCatalog,
    Snapshot,
    Missing,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Pagination {
    pub mode: Paging,
    pub parameters: &'static [Field],
    pub default_limit: Option<usize>,
    pub max_limit: Option<usize>,
    pub limit_parameter: Option<&'static str>,
    pub continuation: Option<&'static str>,
}
const fn page(
    mode: Paging,
    parameters: &'static [Field],
    default: Option<usize>,
    max: Option<usize>,
    limit: Option<&'static str>,
    next: Option<&'static str>,
) -> Pagination {
    Pagination {
        mode,
        parameters,
        default_limit: default,
        max_limit: max,
        limit_parameter: limit,
        continuation: next,
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Current {
    pub source: &'static str,
    pub pagination: Pagination,
    /// Empty means execution does not guarantee an order, not an implicit ID order.
    pub default_sort: &'static [&'static str],
    pub direction_parameter: Option<&'static str>,
    pub filters: &'static [Field],
    pub sortable: &'static [Field],
    pub output: &'static [Field],
    pub selectable_projection: bool,
    pub note: &'static str,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Description {
    /// The current query decoder and generated documentation consume Resource::FIELDS directly.
    /// Only the ResourceV1 policy may use this owner, never another resource's exemption.
    ResourceOwner,
    Current(Current),
}
macro_rules! describe {
    ($name:ident,$source:literal,$page:expr,$order:expr,$direction:expr,$filters:expr,$sort:expr,$output:expr,$projection:expr,$note:literal) => {
        pub static $name: Description = Description::Current(Current {
            source: $source,
            pagination: $page,
            default_sort: $order,
            direction_parameter: $direction,
            filters: $filters,
            sortable: $sort,
            output: $output,
            selectable_projection: $projection,
            note: $note,
        });
    };
}
pub static RESOURCE: Description = Description::ResourceOwner;
describe!(
    ADE_DEVICES,
    "crates/apple-channel/src/ade/management.rs",
    page(
        Paging::Keyset,
        &[f("after", "string")],
        Some(100),
        Some(100),
        None,
        Some("nextCursor")
    ),
    &["serial"],
    None,
    &[],
    &[],
    &[
        f("serial", "string"),
        f("deleted", "bool"),
        f("profileUuid", "optional uuid"),
        f("observedAt", "i64"),
        f("registration", "string")
    ],
    false,
    "database text collation; organization bound by route"
);
describe!(
    ADE_PROFILES,
    "crates/apple-channel/src/ade/management.rs",
    page(Paging::Window, &[], Some(1000), Some(1000), None, None),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "i64"),
        f("configuration", "object"),
        f("remoteUuid", "optional uuid")
    ],
    false,
    "organization bound by route; excess is Capacity, not a continuation"
);
describe!(
    AGENT_CONFIGURATIONS,
    "crates/management-http/src/agent_enrollment.rs",
    page(Paging::Missing, &[], None, None, None, None),
    &[],
    None,
    &[],
    &[],
    &[],
    false,
    "no collection route; signed metadata Get is not List"
);
describe!(
    AGENT_PACKAGES,
    "crates/software-service/src/agent_packages.rs",
    page(Paging::Unbounded, &[], None, None, None, None),
    &["releaseId"],
    None,
    &[],
    &[],
    &[
        f("releaseId", "uuid"),
        f("tenantId", "uuid"),
        f("target", "enum"),
        f("version", "string"),
        f("format", "enum"),
        f("filename", "string"),
        f("length", "u64"),
        f("installerSha256", "sha256")
    ],
    false,
    "published and currently admitted only; top-level array; no next-page envelope"
);
describe!(
    API_KEYS,
    "crates/authorization-service/src/store.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(100),
        Some(100),
        None,
        Some("nextCursor")
    ),
    &[],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "u64"),
        f("authorityRevision", "u64"),
        f("credentialRevision", "u64"),
        f("metadata", "KeyMetadata"),
        f("createdAt", "i64"),
        f("revoked", "bool")
    ],
    false,
    "snapshot aggregation lacks ordered input; after filtering does not establish stable page order"
);
describe!(
    APPLE_ORGANIZATIONS,
    "crates/apple-channel/src/account_enrollment/management.rs",
    page(Paging::Window, &[], Some(1000), Some(1000), None, None),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("ade", "optional object"),
        f(
            "accountEnrollment",
            "optional AccountEnrollmentConfiguration"
        )
    ],
    false,
    "1001 lookahead rejects excess; each organization also bounds embedded accounts to 1000"
);
describe!(
    ASSET_FIELDS,
    "crates/inventory/src/catalog.rs",
    page(Paging::Window, &[], Some(1024), Some(1024), None, None),
    &["key"],
    None,
    &[],
    &[],
    &[
        f("key", "string"),
        f("version", "u64"),
        f("valueType", "FieldType"),
        f("nullable", "bool"),
        f("manual", "bool"),
        f("searchable", "bool"),
        f("sources", "map"),
        f("platforms", "enum[]"),
        f("sensitivity", "enum"),
        f("unit", "optional string"),
        f("itemKey", "optional string"),
        f("timeSeries", "optional object"),
        f("operations", "Operator[]")
    ],
    false,
    "1024 is catalog admission ceiling; whole catalog returned, not a client-selected page"
);
describe!(
    ASSET_RESULTS,
    "crates/inventory-service/src/assets/query_read.rs",
    page(
        Paging::Keyset,
        &[f("cursor", "string")],
        Some(1000),
        Some(1000),
        Some("limit"),
        Some("nextCursor")
    ),
    &["sort_key", "device"],
    None,
    &[f("criteria", "InventoryCondition")],
    &[f("catalog FieldKey", "typed scalar")],
    &[
        f("collectionScope", "CollectionScope"),
        f("device", "string"),
        f("channels", "string[]"),
        f("fields", "ResolvedFieldMap"),
        f("lists", "ListSummaryMap"),
        f("quality", "QualityRun[]"),
        f("revisions", "map<string,i64>")
    ],
    true,
    "criteria, optional single-field sort and select apply at asynchronous query creation; result pages read immutable stored sort_key/device order"
);
describe!(
    ASSOCIATION_CHANGES,
    "crates/device-service/src/changes.rs",
    page(
        Paging::Keyset,
        &[f("cursor", "string")],
        Some(64),
        Some(64),
        None,
        Some("nextCursor")
    ),
    &["position"],
    None,
    &[],
    &[],
    &[
        f("association", "Association"),
        f("position", "u64"),
        f("action", "string"),
        f("recordedAt", "i64")
    ],
    false,
    "audit scan up to 64 records/8 MiB followed by permission filtering; checkpoint also returned"
);
describe!(
    AUDIT,
    "crates/timeline-service/src/model.rs",
    page(
        Paging::Keyset,
        &[f("cursor", "string")],
        Some(50),
        Some(200),
        Some("limit"),
        Some("nextCursor")
    ),
    &["-recordedAt", "-position"],
    None,
    &[
        f("targetId", "string"),
        f("targetType", "string"),
        f("device", "string"),
        f("actor", "string"),
        f("action", "string"),
        f("operationId", "uuid"),
        f("outcome", "enum"),
        f("from", "i64"),
        f("until", "i64")
    ],
    &[],
    &[
        f("position", "u64"),
        f("recordedAt", "i64"),
        f("observedAt", "i64"),
        f("actor", "string"),
        f("action", "string"),
        f("effect", "string"),
        f("phase", "string"),
        f("target", "object"),
        f("operation", "optional uuid"),
        f("request", "optional uuid"),
        f("registration", "optional uuid"),
        f("supported", "bool")
    ],
    false,
    "device timeline binds path device; source advancement <=64 records/8MiB/5 seconds and fixed index window"
);
describe!(
    AUTHORIZATION_DEPARTMENTS,
    "crates/management-http/src/authorization/http.rs",
    page(Paging::Snapshot, &[], None, None, None, None),
    &["snapshot source order"],
    None,
    &[],
    &[],
    &[
        f("status", "string"),
        f("source", "IdentityDepartmentSource"),
        f("snapshotId", "uuid"),
        f("observedAt", "i64"),
        f("expiresAt", "i64"),
        f("snapshot", "IdentityDepartmentSnapshot")
    ],
    false,
    "no local page/limit; snapshot structure and budgets owned by pinned Identity"
);
describe!(
    AUTHORIZATION_RULES,
    "crates/management-http/src/authorization/http.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(100),
        Some(100),
        None,
        Some("nextCursor")
    ),
    &[],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "u64"),
        f("value", "optional Rule")
    ],
    false,
    "snapshot aggregation lacks ordered input; after filtering does not establish stable page order"
);
describe!(
    BLUEPRINTS,
    "crates/resource/src/blueprints.rs",
    page(Paging::StaticCatalog, &[], None, None, None, None),
    &["catalog construction order"],
    None,
    &[],
    &[],
    &[
        f("id", "string"),
        f("version", "string"),
        f("presentation", "object"),
        f("platform", "enum"),
        f("definition", "BlueprintDefinition")
    ],
    false,
    "compiled catalog concatenation; no ID sort or runtime list limit"
);
describe!(
    CERTIFICATES,
    "crates/certificate-archive-service/src/service.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(50),
        Some(50),
        None,
        Some("nextAfter")
    ),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "i64"),
        f("retired", "bool"),
        f("recommendedVersion", "optional i64"),
        f("latest", "CertificateVersion")
    ],
    false,
    "latest version selected descending within each entry"
);
describe!(
    COMPLIANCE_RULES,
    "crates/inventory-service/src/compliance/mod.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(50),
        Some(50),
        None,
        Some("nextCursor")
    ),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "i64"),
        f("definition", "ComplianceDefinition")
    ],
    false,
    ""
);
describe!(
    DEVICES,
    "crates/registration-service/src/device/directory.rs",
    page(
        Paging::Keyset,
        &[f("after", "string")],
        Some(64),
        Some(1000),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id"],
    Some("descending"),
    &[
        f("status", "device-status enum"),
        f("channel", "Channel"),
        f("source", "ReportSource")
    ],
    &[f("id", "string")],
    &[
        f("id", "string"),
        f("status", "string"),
        f("primaryMdmRegistration", "optional object"),
        f("channels", "object[]"),
        f("enrollments", "object[]"),
        f("inventoryAvailable", "bool")
    ],
    false,
    "C collation"
);
describe!(
    DEVICE_ACCESS,
    "crates/registration-service/src/device_access/storage.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(100),
        Some(100),
        None,
        None
    ),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("registration", "uuid"),
        f("instance", "uuid"),
        f("principal", "uuid"),
        f("policy", "uuid"),
        f("policyVersion", "uuid"),
        f("device", "string"),
        f("bindingGeneration", "i64"),
        f("revision", "i64"),
        f("serverState", "enum"),
        f("account", "AccessAccount"),
        f("accountIntent", "AccountIntent"),
        f("desired", "object"),
        f("effect", "object")
    ],
    false,
    "device path binds authority; top-level array without lookahead or continuation"
);
describe!(
    DEVICE_ASSOCIATIONS,
    "crates/management-http/src/device_views.rs",
    page(Paging::Missing, &[], None, None, None, None),
    &[],
    None,
    &[],
    &[],
    &[],
    false,
    "changes is an audit feed, not the current association directory"
);
describe!(
    DEVICE_TIMELINE,
    "crates/timeline-service/src/model.rs",
    page(
        Paging::Keyset,
        &[f("cursor", "string")],
        Some(50),
        Some(200),
        Some("limit"),
        Some("nextCursor")
    ),
    &["-recordedAt", "-position"],
    None,
    &[
        f("targetId", "string"),
        f("targetType", "string"),
        f("device", "string"),
        f("actor", "string"),
        f("action", "string"),
        f("operationId", "uuid"),
        f("outcome", "enum"),
        f("from", "i64"),
        f("until", "i64")
    ],
    &[],
    &[
        f("position", "u64"),
        f("recordedAt", "i64"),
        f("observedAt", "i64"),
        f("actor", "string"),
        f("action", "string"),
        f("effect", "string"),
        f("phase", "string"),
        f("target", "object"),
        f("operation", "optional uuid"),
        f("request", "optional uuid"),
        f("registration", "optional uuid"),
        f("supported", "bool")
    ],
    false,
    "device timeline binds path device; source advancement <=64 records/8MiB/5 seconds and fixed index window"
);
describe!(
    DEVICE_VIEWS,
    "crates/device-service/src/views.rs",
    page(
        Paging::Keyset,
        &[f("cursor", "string")],
        Some(64),
        Some(100),
        Some("limit"),
        Some("nextCursor")
    ),
    &["object_key"],
    Some("descending"),
    &[
        f("search", "string"),
        f("platform", "enum(windows,macos)"),
        f("status", "string"),
        f("channel", "enum(mdm,agent)"),
        f("source", "string"),
        f("assetState", "AssetState")
    ],
    &[f("object_key", "string")],
    &[
        f("reference", "ObjectRef"),
        f("association", "optional Association"),
        f("endpoints", "DeviceSummary[]")
    ],
    false,
    "object_key is the internal stable association/endpoint identity, C collation"
);
describe!(
    EXECUTIONS,
    "crates/execution-service/src/directory.rs",
    page(
        Paging::Keyset,
        &[
            f("after", "uuid"),
            f("afterKind", "enum(command,action_run)")
        ],
        Some(64),
        Some(1000),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id", "kind"],
    Some("descending"),
    &[
        f("device", "string"),
        f("kind", "enum(command,action_run)"),
        f("policy", "uuid"),
        f("status", "string")
    ],
    &[f("id", "uuid"), f("kind", "enum")],
    &[
        f("id", "uuid"),
        f("registrationId", "uuid"),
        f("kind", "enum"),
        f("device", "string"),
        f("generation", "i64"),
        f("deadline", "i64"),
        f("origin", "enum"),
        f("policy", "optional uuid"),
        f("status", "string"),
        f("evidence", "CommandEvidence or RunEvidence")
    ],
    false,
    "continuation is an id/kind object"
);
describe!(
    GROUPS,
    "crates/inventory-service/src/groups/directory.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(64),
        Some(1000),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id"],
    Some("descending"),
    &[
        f("kind", "enum(static,dynamic,system)"),
        f("assetContext", "enum(endpoint,associated_device)"),
        f("deleted", "bool"),
        f("name", "string"),
        f("referenceableFor", "uuid")
    ],
    &[f("id", "uuid")],
    &[
        f("id", "uuid"),
        f("kind", "enum"),
        f("systemSelector", "optional enum"),
        f("assetContext", "enum"),
        f("presentation", "object"),
        f("revision", "i64"),
        f("calculationRevision", "i64"),
        f("memberVersion", "i64"),
        f("memberCount", "usize"),
        f("ruleVersion", "optional string"),
        f("deleted", "bool")
    ],
    false,
    "name is a case-insensitive literal substring; referenceableFor also applies visibility and dependency checks"
);
describe!(
    POLICIES,
    "crates/flow-service/src/planning/policies/read.rs",
    page(
        Paging::Keyset,
        &[f("cursor", "string")],
        Some(64),
        Some(1000),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id"],
    Some("descending"),
    &[
        f("state", "enum(enabled,disabled,archived)"),
        f("category", "string"),
        f("action", "ActionKind"),
        f("scope", "uuid"),
        f("resource", "string")
    ],
    &[f("id", "uuid")],
    &[
        f("id", "uuid"),
        f("versionId", "uuid"),
        f("revision", "i64"),
        f("version", "i64"),
        f("state", "enum"),
        f("definition", "PolicyDefinition")
    ],
    false,
    "archived excluded when state is absent"
);
describe!(
    PROVISIONINGS,
    "crates/app/src/tenant_http.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(100),
        Some(1000),
        Some("limit"),
        Some("nextAfter")
    ),
    &["operationId"],
    None,
    &[],
    &[],
    &[
        f("operationId", "uuid"),
        f("action", "Action"),
        f("result", "ReceiptResult")
    ],
    false,
    "provisioning receipts only; after rejects nil"
);
describe!(
    PUBLICATIONS,
    "crates/software-service/src/management/publication/service.rs",
    page(
        Paging::Keyset,
        &[f("after", "string")],
        Some(20),
        Some(100),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id"],
    None,
    &[
        f("target", "string"),
        f("resource", "string"),
        f("version", "string"),
        f("operationId", "uuid")
    ],
    &[],
    &[
        f("id", "string"),
        f("target", "string"),
        f("resource", "string"),
        f("version", "string"),
        f("outcome", "string"),
        f("revision", "u64"),
        f("attempt", "u64"),
        f("publication", "sha256"),
        f("contentDigest", "sha256"),
        f("manifestDigest", "sha256"),
        f("targetDigest", "sha256"),
        f("withdrawn", "bool"),
        f("withdrawal", "optional string")
    ],
    false,
    "record ID uses C collation; directory omits the immutable document"
);
describe!(
    PUBLICATION_TARGETS,
    "crates/software-service/src/management/publication/service.rs",
    page(
        Paging::Keyset,
        &[f("after", "string")],
        Some(20),
        Some(100),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id"],
    None,
    &[],
    &[],
    &[f("$item", "PublicationTarget")],
    false,
    "configured services BTreeMap order; Query accepts other publication parameters but targets only uses after/limit"
);
describe!(
    RECOVERY_CREDENTIALS,
    "crates/recovery-credentials/src/service.rs",
    page(
        Paging::Keyset,
        &[f("afterId", "uuid"), f("afterVersion", "i64")],
        Some(100),
        Some(100),
        None,
        None
    ),
    &["id", "version"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("binding", "Binding"),
        f("version", "i64"),
        f("current", "bool"),
        f("escrowed", "bool"),
        f("validity", "enum"),
        f("operation", "uuid"),
        f("createdAt", "i64"),
        f("invalidatedAt", "optional i64")
    ],
    false,
    "both after values required together; version >0; array without lookahead/continuation; no secret"
);
describe!(
    SAVED_QUERIES,
    "crates/inventory-service/src/assets/store.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(100),
        Some(100),
        None,
        Some("next")
    ),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "i64"),
        f("definition", "optional SavedQueryDefinition")
    ],
    false,
    "bound to current tenant, instance and principal"
);
describe!(
    SCOPES,
    "crates/flow-service/src/planning/directory.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(64),
        Some(1000),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id"],
    Some("descending"),
    &[f("deleted", "bool"), f("ready", "bool")],
    &[f("id", "uuid")],
    &[
        f("id", "uuid"),
        f("revision", "i64"),
        f("calculationRevision", "i64"),
        f("resolutionRevision", "i64"),
        f("deleted", "bool"),
        f("resolution", "object")
    ],
    false,
    ""
);
describe!(
    SOFTWARE_SOURCES,
    "crates/software-service/src/management/catalog.rs",
    page(
        Paging::Keyset,
        &[f("after", "JSON pair of strings")],
        Some(20),
        Some(100),
        Some("limit"),
        Some("nextCursor")
    ),
    &["id", "revision"],
    None,
    &[
        f("source", "string"),
        f(
            "protocol",
            "enum(private,winget_rest,winget_community,brew_tap)"
        ),
        f("state", "enum(enabled,disabled)")
    ],
    &[],
    &[
        f("snapshot", "SourceSnapshot"),
        f("source", "Source"),
        f("lifecycle", "SourceLifecycle")
    ],
    false,
    "ID and revision use C collation"
);
describe!(
    SOFTWARE_VERSIONS,
    "crates/management-http/src/software_catalog.rs",
    page(Paging::Missing, &[], None, None, None, None),
    &[],
    None,
    &[],
    &[],
    &[],
    false,
    "no collection route; Resource aggregate owns existing version discovery"
);
describe!(
    TENANTS,
    "crates/app/src/tenant_registry.rs",
    page(Paging::Unbounded, &[], None, None, None, None),
    &["tenantId"],
    None,
    &[],
    &[],
    &[
        f("tenantId", "string"),
        f("management", "bool"),
        f("deletable", "bool"),
        f("initialEpoch", "i64"),
        f("currentEpoch", "i64"),
        f("revision", "i64"),
        f("name", "optional string"),
        f("notes", "optional string")
    ],
    false,
    "deleted excluded; no SQL page limit"
);
describe!(
    USER_ATTRIBUTES,
    "crates/app/src/user_profiles/store.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(128),
        Some(128),
        None,
        Some("nextCursor")
    ),
    &["fieldId"],
    None,
    &[],
    &[],
    &[
        f("fieldId", "uuid"),
        f("revision", "i64"),
        f("collectedAfterMicros", "i64"),
        f("value", "optional DefinitionValue")
    ],
    false,
    "envelope definitions/nextCursor/sources"
);
describe!(
    USER_GROUPS,
    "crates/management-http/src/authorization/http.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(100),
        Some(100),
        None,
        Some("nextCursor")
    ),
    &[],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "u64"),
        f("value", "optional GroupMetadata")
    ],
    false,
    "snapshot aggregation lacks ordered input; after filtering does not establish stable page order"
);
describe!(
    USER_GROUP_MEMBERS,
    "crates/management-http/src/authorization/http.rs",
    page(
        Paging::Offset,
        &[f("offset", "usize"), f("expectedRevision", "u64")],
        Some(100),
        Some(100),
        None,
        Some("nextOffset")
    ),
    &["members source order"],
    None,
    &[],
    &[],
    &[f("$item", "IdentityUser")],
    false,
    "offset at most 10000; nonzero offset requires expectedRevision"
);
describe!(
    WEBHOOK_DELIVERIES,
    "crates/webhook-service/src/storage.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(32),
        Some(32),
        None,
        Some("nextCursor")
    ),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("eventId", "uuid"),
        f("subscriptionId", "uuid"),
        f("targetVersion", "i64"),
        f("recoveryVersion", "i64"),
        f("attempts", "i64"),
        f("sourceDelivery", "optional uuid"),
        f("status", "string"),
        f("redriveWindowOpen", "bool"),
        f("transportObservation", "optional string"),
        f("failureStage", "optional string"),
        f("failureReason", "optional string")
    ],
    false,
    "cursor uses scan position before authorization filtering; empty items can still carry continuation"
);
describe!(
    WEBHOOK_SUBSCRIPTIONS,
    "crates/webhook-service/src/storage.rs",
    page(
        Paging::Keyset,
        &[f("after", "uuid")],
        Some(32),
        Some(32),
        None,
        None
    ),
    &["id"],
    None,
    &[],
    &[],
    &[
        f("id", "uuid"),
        f("revision", "i64"),
        f("targetVersion", "i64"),
        f("enabled", "bool"),
        f("deleted", "bool"),
        f("settings", "SubscriptionSettings")
    ],
    false,
    "deleted excluded; no nextCursor output despite after input"
);
describe!(
    WEBHOOK_TYPES,
    "crates/webhook-service/src/model.rs",
    page(Paging::StaticCatalog, &[], Some(4), Some(4), None, None),
    &["declaration order"],
    None,
    &[],
    &[],
    &[f("$item", "EventType")],
    false,
    "four source-defined event types"
);

pub fn valid(resource: &crate::Resource, gaps: &[crate::Gap]) -> bool {
    use crate::{Category, Operation, QueryPolicy};
    let Some(description) = resource.collection else {
        return !resource.category.required().contains(&Operation::List)
            && resource.query != QueryPolicy::ResourceV1
            && resource.query != QueryPolicy::FixedWindow
            && resource.query != QueryPolicy::SourceCatalog;
    };
    let Description::Current(current) = description else {
        return resource.id == "resource" && resource.query == QueryPolicy::ResourceV1;
    };
    if current.source.is_empty() {
        return false;
    }
    let pagination = &current.pagination;
    if pagination.mode == Paging::Missing {
        return matches!(resource.query,QueryPolicy::Pending(issue) if gaps.iter().any(|g|g.resource==resource.id && g.operation==Operation::List && g.issue==issue))
            && current.output.is_empty()
            && current.default_sort.is_empty();
    }
    if current.output.is_empty()
        || current
            .output
            .iter()
            .chain(current.filters)
            .chain(current.sortable)
            .any(|f| f.name.is_empty() || f.value_type.is_empty())
    {
        return false;
    }
    let bounded =
        matches!((pagination.default_limit,pagination.max_limit),(Some(d),Some(m)) if d>0 && d<=m);
    if matches!(
        pagination.mode,
        Paging::Keyset | Paging::Offset | Paging::Window
    ) && !bounded
    {
        return false;
    }
    if matches!(pagination.mode, Paging::Keyset | Paging::Offset)
        && pagination.parameters.is_empty()
    {
        return false;
    }
    match resource.query {
        QueryPolicy::Pending(_) => true, // current limitations stay explicit until their implementation PBI
        QueryPolicy::FixedWindow => {
            resource.category == Category::Facts
                && pagination.mode == Paging::Window
                && bounded
                && !current.default_sort.is_empty()
        }
        QueryPolicy::SourceCatalog => {
            resource.category == Category::Facts
                && pagination.mode == Paging::StaticCatalog
                && !current.default_sort.is_empty()
        }
        QueryPolicy::ResourceV1 | QueryPolicy::NotCollection | QueryPolicy::Protocol => false,
    }
}
