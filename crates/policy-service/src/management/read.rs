use super::*;
pub use rss_mdm_policy_postgres::directory::{SCHEMA, parse};
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
                let items =
                    rss_mdm_policy_postgres::directory::policies_in(tx, q, after.as_ref()).await?;
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

/// The actual SQL directory row, before caller-selected fields are projected away.
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Row {
    pub id: Uuid,
    pub tool_name: String,
    pub alias: Option<rss_mdm_agent_wire::runtime::PolicyAlias>,
    pub custom_event: Option<rss_mdm_agent_wire::runtime::PolicyEventName>,
    pub revision: i64,
    pub version: i64,
    pub version_id: Uuid,
    pub state: rss_mdm_policy::State,
    pub definition: rss_mdm_policy::Definition,
    pub action: rss_mdm_policy::ActionKind,
    pub scope: Uuid,
    pub resource: Option<String>,
    pub category: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Resolved {
    pub capability: rss_mdm_agent_wire::runtime::CapabilityDescriptor,
    pub policy: rss_mdm_policy::View,
}
