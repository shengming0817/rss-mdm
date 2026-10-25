use super::*;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
pub static SCHEMA: Schema = Schema {
    id: "policies",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("toolName", Kind::Text),
        Field::scalar("alias", Kind::Text),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("version", Kind::Integer),
        Field::scalar("state", Kind::Enum(&["enabled", "disabled", "archived"])),
        Field::scalar(
            "action",
            Kind::Enum(&[
                "device_access",
                "unmanage_device",
                "credential",
                "execution",
                "native_collection",
                "agent_collection",
                "telemetry_profile",
                "configuration",
                "software",
                "ensure_agent_installed",
                "request_mdm_enrollment",
            ]),
        ),
        Field::scalar("scope", Kind::Uuid),
        Field::scalar("resource", Kind::Text),
        Field::scalar("category", Kind::Text),
        Field::output("versionId"),
        Field::output("definition"),
    ],
};
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    SCHEMA.parse(raw)
}
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "toolName" => "('policy_' || replace(id::text,'-','')) COLLATE \"C\"",
        "alias" => "(definition->>'alias') COLLATE \"C\"",
        "revision" => "revision",
        "version" => "version_number",
        "state" => "state COLLATE \"C\"",
        "action" => "(definition->'action'->>'kind') COLLATE \"C\"",
        "scope" => "(definition->>'scope') COLLATE \"C\"",
        "resource" => "(definition->'action'->'resource'->>'id') COLLATE \"C\"",
        "category" => "(definition->'selfService'->'presentation'->>'category') COLLATE \"C\"",
        _ => unreachable!("checked Policy field"),
    }
}
pub async fn read(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
) -> std::result::Result<Value, Error> {
    audit.set_action("management_read");
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
                let (s, a, audit) = *ctx;
                crate::action_admission::current(tx, a).await?.require(
                    a,
                    Permission::PolicyRead,
                    None,
                )?;
                let policy = storage::read_in(s.policy_store.reader(), tx, id)
                    .await?
                    .ok_or(Error::Planning(
                        crate::planning::error::PlanningError::Missing(
                            crate::planning::error::Missing::Policy,
                        ),
                    ))?;
                let value = storage::view(&policy)?;
                audit.require_request_settlement();
                Ok(value)
            })
        },
        TransactionOwner::Planning,
    )
    .await
}

pub async fn list(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    query: &Query,
) -> std::result::Result<Value, Error> {
    query.require_schema(&SCHEMA).map_err(crate::query_error)?;
    auth.manage(Permission::PolicyRead)?;
    audit.set_action("management_read");
    crate::transaction::inspect(&service.runtime,service.tenant,(service,auth,audit,query),|ctx,tx|Box::pin(async move{
  let(s,a,audit,q)=*ctx;let snapshot=crate::action_admission::current(tx,a).await?;
  snapshot.require(a,Permission::PolicyRead,None)?;
  let binding=q.binding(&(a.tenant_id(),a.instance_id(),snapshot.query_binding(a)?)).map_err(crate::query_error)?;
  let codec=CursorCodec::from_key(s.cursor_key.clone());let after=q.after(&codec,&binding).map_err(crate::query_error)?;
  let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'toolName','policy_' || replace(id::text,'-',''),'alias',definition->>'alias','revision',revision,'version',version_number,'versionId',current_version,'state',state,'definition',definition,'action',definition->'action'->>'kind','scope',definition->>'scope','resource',definition->'action'->'resource'->>'id','category',definition->'selfService'->'presentation'->>'category') FROM mdm_policy.policies WHERE tenant_id=");
  sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
  if !q.mentions("state"){sql.push(" AND state<>'archived'");}
  rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(crate::query_error)?;
  let items:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
  for item in &items {let view:rss_mdm_policy::View=stored(serde_json::from_value(json!({"id":item["id"],"revision":item["revision"],"version":item["version"],"versionId":item["versionId"],"state":item["state"],"definition":item["definition"]})))?;view.definition.validate()?;}
  a.check_live()?;audit.require_request_settlement();Ok(json!(q.page(items,&codec,&binding).map_err(crate::query_error)?))
 }),TransactionOwner::Planning).await
}

/// Resolve management addresses without granting self-service execution.
pub async fn resolve(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    selector: &rss_mdm_agent_wire::runtime::CapabilitySelector,
) -> std::result::Result<Value, Error> {
    auth.manage(Permission::PolicyRead)?;
    audit.set_action("management_read");
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
            output_schema:checked_input(serde_json::to_value(schemars::schema_for!(rss_mdm_policy::View)))?,
        };
        a.check_live()?;audit.require_request_settlement();
        Ok(json!({"capability":descriptor,"policy":storage::view(&policy)?}))
    }),TransactionOwner::Planning).await
}
