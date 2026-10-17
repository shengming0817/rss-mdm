use super::*;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    pub cursor: Option<String>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub state: Option<rss_mdm_policy::State>,
    pub category: Option<String>,
    pub action: Option<rss_mdm_policy::ActionKind>,
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
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
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
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    family: String,
    tenant: String,
    authority: String,
    query: Value,
    after: Uuid,
}
impl DirectoryQuery {
    fn binding(&self) -> std::result::Result<Value, Error> {
        let mut binding = serde_json::to_value(self).map_err(|_| Error::Malformed)?;
        binding
            .as_object_mut()
            .ok_or(Error::Malformed)?
            .remove("cursor");
        binding
            .as_object_mut()
            .ok_or(Error::Malformed)?
            .remove("limit");
        Ok(binding)
    }
}
pub async fn list(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    query: &DirectoryQuery,
) -> std::result::Result<Value, Error> {
    if !(1..=1000).contains(&query.limit)
        || query.scope.is_some_and(|v| v.is_nil())
        || query
            .resource
            .as_ref()
            .is_some_and(|v| resource::Id::new(v).is_err())
        || query
            .category
            .as_ref()
            .is_some_and(|v| v.trim().is_empty() || v.len() > 128)
        || query.cursor.as_ref().is_some_and(|v| v.len() > 4096)
    {
        return Err(Error::Malformed);
    }
    auth.manage(Permission::PolicyRead)?;
    audit.set_action("management_read");
    run(&service.audit_store,&service.runtime,service.tenant,audit,(service,auth,audit,query),|ctx,tx|Box::pin(async move {
        let (s,a,audit,q)=*ctx;
        let snapshot=crate::action_admission::current(tx,a).await?;
        snapshot.require(a,Permission::PolicyRead,None)?;
        let authority=snapshot.query_binding(a)?;let binding=q.binding()?;
        let after=if let Some(token)=&q.cursor {
            let bytes=URL_SAFE_NO_PAD.decode(token).map_err(|_|Error::Malformed)?;
            if bytes.len()<=32 {return Err(Error::Malformed.into())}
            let (body,signature)=bytes.split_at(bytes.len()-32);
            ring::hmac::verify(&s.cursor_key,body,signature).map_err(|_|Error::Conflict)?;
            let cursor:Cursor=serde_json::from_slice(body).map_err(|_|Error::Conflict)?;
            if cursor.family!="policies" || cursor.tenant!=s.tenant.to_string() || cursor.authority!=authority || cursor.query!=binding {return Err(Error::Conflict.into())}
            Some(cursor.after)
        }else{None};
        let tenant=s.tenant.to_string();let query=q.clone();
        let mut items:Vec<Value>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT jsonb_build_object('id',id,'revision',revision,'version',version_number,'versionId',current_version,'state',state,'definition',definition) FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR CASE WHEN $3 THEN id<$2 ELSE id>$2 END) AND CASE WHEN $4::text IS NULL THEN state<>'archived' ELSE state=$4 END AND ($5::text IS NULL OR definition->'action'->>'kind'=$5) AND ($6::uuid IS NULL OR definition->>'scope'=$6::text) AND ($7::text IS NULL OR definition->'action'->'resource'->>'id'=$7) AND ($9::text IS NULL OR definition->'selfService'->>'category'=$9) ORDER BY CASE WHEN NOT $3 THEN id END ASC,CASE WHEN $3 THEN id END DESC LIMIT $8")
            .bind(tenant).bind(after).bind(query.descending).bind(query.state.map(rss_mdm_policy::State::as_str)).bind(query.action.map(rss_mdm_policy::ActionKind::as_str)).bind(query.scope).bind(query.resource).bind((query.limit+1) as i64).bind(query.category).fetch_all(c).await
        })).await?;
        let more=items.len()>q.limit;items.truncate(q.limit);
        for item in &items {let view:rss_mdm_policy::View=stored(serde_json::from_value(item.clone()))?;view.definition.validate()?;}
        let next=if more {
            let after=stored(Uuid::parse_str(items.last().and_then(|v|v["id"].as_str()).ok_or(Error::Conflict)?))?;
            let mut bytes=checked_input(serde_json::to_vec(&Cursor{family:"policies".into(),tenant:s.tenant.to_string(),authority,query:binding,after}))?;
            bytes.extend_from_slice(ring::hmac::sign(&s.cursor_key,&bytes).as_ref());Some(URL_SAFE_NO_PAD.encode(bytes))
        }else{None};
        a.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"items":items,"nextCursor":next}))
    }),TransactionOwner::Planning).await
}
