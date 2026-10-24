//! Collection behavior and owner references, including incomplete legacy behavior.
//! Business field contracts stay with their response/query owner; this module does not copy them.
//! These describe existing execution; Pending does not imply support for unified query inputs.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Parameter {
    pub name: &'static str,
    pub value_type: &'static str,
}
const fn f(name: &'static str, value_type: &'static str) -> Parameter {
    Parameter { name, value_type }
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
    pub parameters: &'static [Parameter],
    pub default_limit: Option<usize>,
    pub max_limit: Option<usize>,
    pub limit_parameter: Option<&'static str>,
    pub continuation: Option<&'static str>,
}
const fn page(
    mode: Paging,
    parameters: &'static [Parameter],
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
    /// Source owner of the actual query/response; not a separate field schema.
    pub source: &'static str,
    pub pagination: Pagination,
    /// Empty means execution does not guarantee an order, not an implicit ID order.
    pub default_sort: &'static [&'static str],
    pub direction_parameter: Option<&'static str>,
    pub selectable_projection: bool,
    pub note: &'static str,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Description {
    /// The current query decoder and generated documentation consume Resource::FIELDS directly.
    /// Only the ResourceV1 policy may use this owner, never another resource's exemption.
    ResourceOwner,
    /// The registered List method supplies its actual query field catalog.
    QueryOwner,
    Current(&'static Current),
}
macro_rules! describe {
    ($name:ident,$source:literal,$page:expr,$order:expr,$direction:expr,$projection:expr,$note:literal) => {
        pub static $name: Description = Description::Current(&Current {
            source: $source,
            pagination: $page,
            default_sort: $order,
            direction_parameter: $direction,
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
    false,
    "database text collation; organization bound by route"
);
describe!(
    ADE_PROFILES,
    "crates/apple-channel/src/ade/management.rs",
    page(Paging::Window, &[], Some(1000), Some(1000), None, None),
    &["id"],
    None,
    false,
    "organization bound by route; excess is Capacity, not a continuation"
);
pub static AGENT_CONFIGURATIONS: Description = Description::QueryOwner;
pub static AGENT_PACKAGES: Description = Description::QueryOwner;
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
    false,
    "snapshot aggregation lacks ordered input; after filtering does not establish stable page order"
);
describe!(
    APPLE_ORGANIZATIONS,
    "crates/apple-channel/src/account_enrollment/management.rs",
    page(Paging::Window, &[], Some(1000), Some(1000), None, None),
    &["id"],
    None,
    false,
    "1001 lookahead rejects excess; each organization also bounds embedded accounts to 1000"
);
pub static ASSET_FIELDS: Description = Description::QueryOwner;
pub static ASSET_RESULTS: Description = Description::QueryOwner;
pub static ASSOCIATION_CHANGES: Description = Description::QueryOwner;
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
    false,
    "device timeline binds path device; source advancement <=64 records/8MiB/5 seconds and fixed index window"
);
describe!(
    AUTHORIZATION_DEPARTMENTS,
    "crates/management-http/src/authorization/http.rs",
    page(Paging::Snapshot, &[], None, None, None, None),
    &["snapshot source order"],
    None,
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
    false,
    "snapshot aggregation lacks ordered input; after filtering does not establish stable page order"
);
describe!(
    BLUEPRINTS,
    "crates/resource/src/blueprints.rs",
    page(Paging::StaticCatalog, &[], None, None, None, None),
    &["catalog construction order"],
    None,
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
    false,
    "latest version selected descending within each entry"
);
pub static COMPLIANCE_RULES: Description = Description::QueryOwner;
pub static DEVICES: Description = Description::QueryOwner;
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
    false,
    "device path binds authority; top-level array without lookahead or continuation"
);
pub static DEVICE_ASSOCIATIONS: Description = Description::QueryOwner;
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
    false,
    "device timeline binds path device; source advancement <=64 records/8MiB/5 seconds and fixed index window"
);
pub static DEVICE_VIEWS: Description = Description::QueryOwner;
pub static EXECUTIONS: Description = Description::QueryOwner;
pub static GROUPS: Description = Description::QueryOwner;
pub static POLICIES: Description = Description::QueryOwner;
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
    false,
    "provisioning receipts only; after rejects nil"
);
pub static PUBLICATIONS: Description = Description::QueryOwner;
pub static PUBLICATION_TARGETS: Description = Description::QueryOwner;
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
    false,
    "both after values required together; version >0; array without lookahead/continuation; no secret"
);
pub static SAVED_QUERIES: Description = Description::QueryOwner;
pub static SCOPES: Description = Description::QueryOwner;
pub static SOFTWARE_SOURCES: Description = Description::QueryOwner;
pub static SOFTWARE_VERSIONS: Description = Description::QueryOwner;
describe!(
    TENANTS,
    "crates/app/src/tenant_registry.rs",
    page(Paging::Unbounded, &[], None, None, None, None),
    &["tenantId"],
    None,
    false,
    "deleted excluded; no SQL page limit"
);
pub static USER_ATTRIBUTES: Description = Description::QueryOwner;
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
    false,
    "deleted excluded; no nextCursor output despite after input"
);
describe!(
    WEBHOOK_TYPES,
    "crates/webhook-service/src/model.rs",
    page(Paging::StaticCatalog, &[], Some(4), Some(4), None, None),
    &["declaration order"],
    None,
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
    if matches!(description, Description::QueryOwner) {
        return resource.query == QueryPolicy::Unified;
    }
    let Description::Current(current) = description else {
        return resource.id == "resource" && resource.query == QueryPolicy::ResourceV1;
    };
    if current.source.is_empty() {
        return false;
    }
    let pagination = &current.pagination;
    if pagination.mode == Paging::Missing {
        return matches!(resource.query,QueryPolicy::Pending(issue) if gaps.iter().any(|g|g.resource==resource.id && g.operation==Operation::List && g.issue==issue))
            && current.default_sort.is_empty();
    }
    if pagination
        .parameters
        .iter()
        .any(|p| p.name.is_empty() || p.value_type.is_empty())
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
        QueryPolicy::Unified
        | QueryPolicy::ResourceV1
        | QueryPolicy::NotCollection
        | QueryPolicy::Protocol => false,
    }
}
