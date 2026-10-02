use super::*;
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub after: Option<Uuid>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub resource: Option<String>,
    pub kind: Option<String>,
    pub cancelled: Option<bool>,
}
fn limit() -> usize {
    64
}
pub async fn list(
    s: &ExecutionService,
    a: &AuthorizedPrincipal,
    q: &Query,
    audit: &RequestAudit,
) -> std::result::Result<Value, Error> {
    if !(1..=1000).contains(&q.limit)
        || q.after.is_some_and(|v| v.is_nil())
        || q.resource
            .as_ref()
            .is_some_and(|v| rss_mdm_resource::Id::new(v).is_err())
        || q.kind
            .as_deref()
            .is_some_and(|v| !["script", "configuration"].contains(&v))
    {
        return Err(Error::Malformed);
    }
    a.authorization()?
        .devices_for(a, Permission::OperationRead)?;
    run(&s.audit_store,&s.runtime,s.tenant,audit,(s,a,q,audit),|ctx,tx|Box::pin(async move {
        let (s,a,q,audit)=*ctx;let auth=crate::action_admission::current(tx,a).await?;
        let allowed=auth.devices_for(a,Permission::OperationRead)?.map(|v|v.into_iter().collect::<Vec<_>>());
        let tenant=tx.tenant_id().to_string();let query=q.clone();
        let mut value:Value=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("WITH visible AS (SELECT * FROM mdm_planning.remote_operations o WHERE tenant_id=$1::uuid AND ($2::text[] IS NULL OR (snapshot->>'kind'='devices' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(snapshot->'devices') d WHERE NOT d.value=ANY($2)))) AND ($3::text IS NULL OR resource=$3) AND ($4::text IS NULL OR frozen->>'kind'=CASE WHEN $4='script' THEN 'execution' ELSE 'configuration' END) AND ($5::boolean IS NULL OR cancelled=$5)), page AS (SELECT * FROM visible WHERE ($6::uuid IS NULL OR CASE WHEN $7 THEN id<$6 ELSE id>$6 END) ORDER BY CASE WHEN NOT $7 THEN id END ASC,CASE WHEN $7 THEN id END DESC LIMIT $8) SELECT jsonb_build_object('items',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'resource',resource,'resourceVersion',resource_version,'kind',frozen->>'kind','createdAt',created_at,'deadline',deadline,'cancellationRequested',cancelled,'staged',staged,'detailUrl','/api/v2/remote-operations/'||id::text) ORDER BY CASE WHEN NOT $7 THEN id END ASC,CASE WHEN $7 THEN id END DESC) FROM page),'[]'::jsonb),'statistics',(SELECT jsonb_build_object('total',count(*),'cancellationRequested',count(*) FILTER(WHERE cancelled),'staging',count(*) FILTER(WHERE NOT staged)) FROM visible),'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint)")
                .bind(tenant).bind(allowed).bind(query.resource).bind(query.kind).bind(query.cancelled).bind(query.after).bind(query.descending).bind((query.limit+1) as i64).fetch_one(c).await
        })).await?;
        let items=value["items"].as_array_mut().ok_or(Error::Malformed)?;let more=items.len()>q.limit;items.truncate(q.limit);
        let next=if more{items.last().map(|v|v["id"].clone())}else{None};value["nextCursor"]=next.unwrap_or(Value::Null);
        a.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;Ok(value)
    }),TransactionOwner::Execution).await
}
