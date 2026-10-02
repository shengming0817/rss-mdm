use super::*;
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    pub after: Option<Uuid>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub enabled: Option<bool>,
    pub action: Option<String>,
    pub scope: Option<Uuid>,
    pub resource: Option<String>,
}
fn limit() -> usize {
    64
}
pub async fn read(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
) -> std::result::Result<Value, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    auth.manage(Permission::PolicyRead)?;
    run(
        &service.audit_store,
        &service.runtime,
        service.tenant,
        audit,
        (&service, &auth, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (s, a, audit) = *ctx;
                a.manage(Permission::PolicyRead)?;
                let policy = storage::read_in(s.policy_store.reader(), tx, id)
                    .await?
                    .ok_or(Error::Planning(
                        crate::planning::error::PlanningError::Missing(
                            crate::planning::error::Missing::Policy,
                        ),
                    ))?;
                let value = storage::view(&policy)?;
                s.audit_store
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
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
    query: &DirectoryQuery,
) -> std::result::Result<Value, Error> {
    if !(1..=1000).contains(&query.limit)
        || query.after.is_some_and(|v| v.is_nil())
        || query.scope.is_some_and(|v| v.is_nil())
        || query
            .resource
            .as_ref()
            .is_some_and(|v| resource::Id::new(v).is_err())
        || query.action.as_deref().is_some_and(|v| {
            ![
                "execution",
                "configuration",
                "software",
                "ensure_agent_installed",
                "request_mdm_enrollment",
            ]
            .contains(&v)
        })
    {
        return Err(Error::Malformed);
    }
    audit.set_action("management_read");
    auth.manage(Permission::PolicyRead)?;
    run(&service.audit_store,&service.runtime,service.tenant,audit,(&service,&auth,audit,query),|ctx,tx|Box::pin(async move {
        let (s,a,audit,q)=*ctx;a.manage(Permission::PolicyRead)?;
        let tenant=tx.tenant_id().to_string();let query=q.clone();
        let mut ids=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR CASE WHEN $3 THEN id<$2 ELSE id>$2 END) AND ($4::boolean IS NULL OR enabled=$4) AND ($5::text IS NULL OR definition->'action'->>'kind'=$5) AND ($6::uuid IS NULL OR definition->>'scope'=$6::text) AND ($7::text IS NULL OR definition->'action'->'resource'->>'id'=$7) ORDER BY CASE WHEN NOT $3 THEN id END ASC,CASE WHEN $3 THEN id END DESC LIMIT $8")
                .bind(tenant).bind(query.after).bind(query.descending).bind(query.enabled).bind(query.action).bind(query.scope).bind(query.resource).bind((query.limit+1) as i64).fetch_all(c).await
        })).await?;
        let more=ids.len()>q.limit;ids.truncate(q.limit);
        let mut items=Vec::new();for id in &ids {items.push(storage::view(&storage::read_in(s.policy_store.reader(),tx,stored(Uuid::parse_str(id))?).await?.ok_or(Error::Planning(crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Policy)))?)?);}
        s.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"items":items,"nextCursor":if more {ids.last()} else {None}}))
    }),TransactionOwner::Planning).await
}
