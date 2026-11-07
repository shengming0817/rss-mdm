use super::*;

pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    BINDINGS.schema()
}
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
pub async fn read(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
) -> std::result::Result<rss_mdm_policy::View, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    auth.manage(Permission::PolicyRead)?;
    crate::transaction::inspect(
        &service.runtime,
        service.tenant,
        (&service, &auth, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (s, a, _audit) = *ctx;
                crate::action_admission::current(tx, a).await?.require(
                    a,
                    Permission::PolicyRead,
                    None,
                )?;
                let policy = storage::read_in(s.policy_store.reader(), tx, id)
                    .await?
                    .ok_or(Error::PolicyMissing)?;
                let value = storage::view(&policy);

                Ok(value)
            })
        },
    )
    .await
}

pub async fn list(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    query: &Query,
) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Row>>, Error> {
    query.require_schema(&SCHEMA).map_err(crate::query_error)?;
    auth.manage(Permission::PolicyRead)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    crate::transaction::inspect(
        &service.runtime,
        service.tenant,
        (service, auth, audit, query),
        |ctx, tx| {
            Box::pin(async move {
                let (s, a, _audit, q) = *ctx;
                let snapshot = crate::action_admission::current(tx, a).await?;
                snapshot.require(a, Permission::PolicyRead, None)?;
                let binding = q
                    .binding(&(a.tenant_id(), a.instance_id(), snapshot.query_binding(a)?))
                    .map_err(crate::query_error)?;
                let codec = CursorCodec::from_key(s.cursor_key.clone());
                let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                let items = rss_mdm_policy_postgres::directory::policies_in(
                    profile,
                    tx,
                    q,
                    after.as_ref(),
                    &BINDINGS,
                )
                .await?;
                let items: Vec<Row> = stored(serde_json::from_value(json!(items)))?;
                for item in &items {
                    item.definition.validate()?;
                    if item.action != item.definition.action.kind() {
                        return Err(Error::Malformed.into());
                    }
                }
                a.check_live()?;
                q.page_typed(items, &codec, &binding)
                    .map_err(|e| crate::query_error(e).into())
            })
        },
    )
    .await
}

/// Resolve management addresses without granting self-service execution.
pub async fn resolve(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    selector: &rss_mdm_agent_wire::runtime::CapabilitySelector,
) -> std::result::Result<Resolved, Error> {
    auth.manage(Permission::PolicyRead)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    crate::transaction::inspect(&service.runtime, service.tenant, (service,auth,audit,selector), |ctx,tx| Box::pin(async move {
        let (s,a,audit,selector) = *ctx;
        crate::action_admission::current(tx,a).await?.require(a,Permission::PolicyRead,None)?;
        let id = checked(s.policy_store.reader().resolve_in(tx,selector).await?)?.ok_or(Error::NotFound)?;
        let policy = storage::read_in(s.policy_store.reader(),tx,id).await?.filter(|p| p.state != rss_mdm_policy::State::Archived).ok_or(Error::NotFound)?;
        if let rss_mdm_agent_wire::runtime::CapabilitySelector::Alias { alias } = selector
            && policy.definition.alias.as_ref() != Some(alias) { return Err(Error::NotFound.into()); }
        audit.resource_target(rss_mdm_audit_integration::TargetKind::Policy,&id.to_string());
        let descriptor = rss_mdm_agent_wire::runtime::CapabilityDescriptor {
            id, object_type:rss_mdm_agent_wire::runtime::CapabilityObject::Policy,
            tool_name:rss_mdm_agent_wire::runtime::policy_tool_name(id),alias:policy.definition.alias.clone(),
            scope:policy.definition.scope,instance:a.instance_id().to_owned(),tenant:checked_input(Uuid::parse_str(a.tenant_id()))?,
            revision:policy.revision as u64,version:policy.version,
            operations:vec![rss_mdm_agent_wire::runtime::CapabilityOperation::Read],
            input_schema:json!({"type":"object","properties":{},"additionalProperties":false}),
            output_schema:schemars::generate::SchemaSettings::draft2020_12().for_serialize().into_generator().into_root_schema_for::<rss_mdm_policy::View>().to_value(),
        };
        a.check_live()?;
        Ok(Resolved {capability:descriptor,policy:storage::view(&policy)})
    }),).await
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Resolved {
    pub capability: rss_mdm_agent_wire::runtime::CapabilityDescriptor,
    pub policy: rss_mdm_policy::View,
}

/// Safe original Policy result; current configuration is never used as a substitute.
pub async fn operation_receipt(
    service: &Policies,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error> {
    p.manage(Permission::PolicyRead)?;
    crate::transaction::inspect(
        &service.runtime,
        service.tenant,
        (service, p),
        |(s, p), tx| {
            Box::pin(async move {
                crate::action_admission::current(tx, p).await?.require(
                    p,
                    Permission::PolicyRead,
                    None,
                )?;
                let value = checked(s.policy_store.operation_in(tx, id).await?)?;
                value
                    .map(|v| {
                        let mut s = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                        #[derive(serde::Deserialize)]
                        #[serde(untagged)]
                        enum Original {
                            Changed(Box<rss_mdm_policy::View>),
                            Rerun(crate::management::rerun::Receipt),
                        }
                        match serde_json::from_value::<Original>(v).map_err(|_| Error::Conflict)? {
                            Original::Changed(v) => {
                                s.object = Some(v.id.to_string());
                                s.revision = Some(v.revision);
                            }
                            Original::Rerun(v) => {
                                if v.operation_id != id {
                                    return Err(Error::Conflict.into());
                                }
                                s.object = Some(v.policy_id.to_string());
                                s.accepted = Some(true);
                            }
                        }
                        Ok(s)
                    })
                    .transpose()
            })
        },
    )
    .await
}

pub async fn work_receipt(
    service: &Policies,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error> {
    crate::transaction::inspect(
        &service.runtime,
        service.tenant,
        (service, p),
        |(s, p), tx| {
            Box::pin(async move {
                let grant = crate::action_admission::current(tx, p).await?;
                let (work, complete, failure, _, forwarded) =
                    crate::worker::jobs::read_in(s.profile(), tx, id).await?;
                grant.require(
                    p,
                    if matches!(
                        work,
                        rss_mdm_policy_postgres::work::Work::PolicyScope { .. }
                    ) {
                        Permission::ScopeRead
                    } else {
                        Permission::PolicyRead
                    },
                    None,
                )?;
                let mut value = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                value.object = Some(work.target());
                value.accepted = Some(true);
                value.executions.push(id);
                value.state = Some(
                    if failure.is_some() {
                        "failed"
                    } else if complete {
                        "completed"
                    } else if forwarded {
                        "running"
                    } else {
                        "pending"
                    }
                    .into(),
                );
                p.check_live()?;
                Ok(Some(value))
            })
        },
    )
    .await
}

pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    schema().parse(raw)
}

use rss_mdm_query::directory::Schema;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    use rss_mdm_query::directory::Exclusion;
    Schema::derived::<Row>("policies", &["id"], 64, 1000, &[
        Exclusion { path: "definition.action.parameters", reason: "Dynamic Resource parameter names and fixed values require the Resource's sensitivity/type authority" },
        Exclusion { path: "definition.action.rollout.stages", reason: "Rollout object arrays require same-stage conditions" },
        Exclusion { path: "definition.selfService.access.selectors", reason: "Access selector object arrays require same-selector conditions" },
    ]).and_then(|s| s.no_range("definition.action.resource.version"))
    .expect("Policy public model is fully described")
});

/// The actual SQL directory row, before caller-selected fields are projected away.
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Public directory row before selection removes unrequested output fields.
pub struct Row {
    /// Stable object identity within the tenant.
    pub id: Uuid,
    /// Derived canonical policy tool address.
    #[schemars(schema_with = "rss_mdm_agent_wire::runtime::policy_tool_name_schema")]
    pub tool_name: String,
    /// Optional authored business address.
    pub alias: Option<rss_mdm_agent_wire::runtime::PolicyAlias>,
    /// Optional authored event address.
    pub custom_event: Option<rss_mdm_agent_wire::runtime::PolicyEventName>,
    /// Current compare-and-swap revision.
    pub revision: i64,
    /// Current business version number.
    pub version: i64,
    /// Current immutable version identity.
    pub version_id: Uuid,
    /// Current policy lifecycle state.
    pub state: rss_mdm_policy::State,
    /// Current authored policy definition.
    pub definition: rss_mdm_policy::Definition,
    /// Current action discriminator.
    pub action: rss_mdm_policy::ActionKind,
    /// Associated Scope identity.
    pub scope: Uuid,
    /// Resource selected by the action, when applicable.
    #[schemars(length(max = rss_mdm_policy::RESOURCE_ID_MAX_BYTES))]
    pub resource: Option<String>,
    /// Public self-service category, when configured.
    #[schemars(length(max = rss_mdm_policy::CATEGORY_MAX_BYTES))]
    pub category: Option<String>,
}

static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(&SCHEMA, rss_mdm_policy_postgres::directory::SOURCES)
            .expect("Complete service model binding")
    });
