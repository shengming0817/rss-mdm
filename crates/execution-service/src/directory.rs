//! Cross-device read projections retain the existing command and action-run owners.
use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub after: Option<Uuid>,
    pub after_kind: Option<String>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub device: Option<String>,
    pub kind: Option<String>,
    pub policy: Option<Uuid>,
    pub remote_operation: Option<Uuid>,
    pub status: Option<String>,
}
fn limit() -> usize {
    64
}
impl Query {
    fn validate(&self) -> std::result::Result<(), Error> {
        if self.after.is_some() != self.after_kind.is_some()
            || self
                .after_kind
                .as_deref()
                .is_some_and(|v| !["command", "action_run"].contains(&v))
            || !(1..=1000).contains(&self.limit)
            || self.after.is_some_and(|id| id.is_nil())
            || self.policy.is_some_and(|id| id.is_nil())
            || self.remote_operation.is_some_and(|id| id.is_nil())
            || self
                .device
                .as_ref()
                .is_some_and(|id| rss_observation::Id::new(id).is_err())
            || self
                .kind
                .as_deref()
                .is_some_and(|v| !["command", "action_run"].contains(&v))
            || self
                .status
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 64)
        {
            return Err(Error::Malformed.into());
        }
        Ok(())
    }
}
impl crate::queries::Queries {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        page: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<crate::queries::records::ExecutionDirectory, crate::queries::QueryError>
    {
        page.validate()?;
        proof
            .authorization()?
            .devices_for(proof, Permission::OperationRead)?;
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,page,audit),|ctx,tx|Box::pin(async move {
            let (s,a,page,audit)=*ctx;
            let current=crate::action_admission::current(tx,a).await?;
            let allowed=current.devices_for(a,Permission::OperationRead)?.map(|v|v.into_iter().collect::<Vec<_>>());
            let tenant=tx.tenant_id().to_string();let page=page.clone();
            let mut query=sqlx::QueryBuilder::<sqlx::Postgres>::new("WITH executions AS (SELECT o.id,o.device,'command'::text AS kind,o.registration,o.registration_generation AS generation,o.source_kind,o.policy_version,o.remote_operation,v.policy,o.input_context->>'deadline' AS deadline,coalesce(d.status,'unknown') AS status,jsonb_build_object('commandStatus',d.status) AS evidence FROM mdm_commands.operations o LEFT JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) WHERE o.tenant_id=$1::uuid UNION ALL SELECT r.id,r.device,'action_run',r.registration,r.generation,r.source_kind,r.policy_version,r.remote_operation,v.policy,r.deadline::text,coalesce(r.state->>'execution','unknown'),jsonb_build_object('state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'result',");
            query.push(actions::history::RESULT_SUMMARY_SQL).push(") FROM mdm_commands.action_runs r LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid), visible AS (SELECT * FROM executions WHERE ($2::text[] IS NULL OR device=ANY($2)) AND ($3::text IS NULL OR device=$3) AND ($4::text IS NULL OR kind=$4) AND ($5::uuid IS NULL OR policy=$5) AND ($6::uuid IS NULL OR remote_operation=$6) AND ($7::text IS NULL OR status=$7)), page AS (SELECT * FROM visible WHERE ($8::uuid IS NULL OR CASE WHEN $9 THEN (id,kind)<($8,$11::text) ELSE (id,kind)>($8,$11::text) END) ORDER BY CASE WHEN NOT $9 THEN id END ASC,CASE WHEN $9 THEN id END DESC,CASE WHEN NOT $9 THEN kind END ASC,CASE WHEN $9 THEN kind END DESC LIMIT $10) SELECT jsonb_build_object('items',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'kind',kind,'device',device,'registrationId',registration,'generation',generation,'origin',source_kind,'policy',policy,'remoteOperation',remote_operation,'deadline',deadline::bigint,'status',status,'evidence',evidence) ORDER BY CASE WHEN NOT $9 THEN id END ASC,CASE WHEN $9 THEN id END DESC,CASE WHEN NOT $9 THEN kind END ASC,CASE WHEN $9 THEN kind END DESC) FROM page),'[]'::jsonb),'statistics',(SELECT jsonb_build_object('total',count(*),'commands',count(*) FILTER(WHERE kind='command'),'actionRuns',count(*) FILTER(WHERE kind='action_run'),'unknown',count(*) FILTER(WHERE status='unknown')) FROM visible),'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint)");
            let sql=query.sql().to_owned();
            let mut value:Value=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar(sql).bind(tenant).bind(allowed).bind(page.device).bind(page.kind).bind(page.policy)
                    .bind(page.remote_operation).bind(page.status).bind(page.after).bind(page.descending).bind((page.limit+1) as i64).bind(page.after_kind).fetch_one(c).await
            })).await?;
            let items=value["items"].as_array_mut().ok_or(Error::Malformed)?;let more=items.len()>page.limit;items.truncate(page.limit);
            let next=if more{items.last().map(|v|json!({"id":v["id"],"kind":v["kind"]}))}else{None};value["nextCursor"]=next.unwrap_or(Value::Null);
            for item in value["items"].as_array_mut().ok_or(Error::Malformed)? {
                if item["kind"]=="command" {
                    let id=stored(Uuid::parse_str(item["id"].as_str().ok_or(Error::Malformed)?))?;
                    let op=storage::load(tx,&s.protection,id).await?;let command=s.command_status(tx,&op).await?;
                    let mut observation=super::protocol::observation(tx,&s.protection,s.apple_store.clone(),&op,command).await?;
                    if op.approval.agent_package().is_some(){item["evidence"]["agentInstallation"]=super::native_installation::installation_observation(tx,s.apple_store.clone(),s.agent_store.clone(),&op).await?;}
                    if let Some(receipts) = observation.get_mut("receipts").and_then(Value::as_array_mut) {
                        for receipt in receipts {
                            if let Some(fields) = receipt.as_object_mut()
                                && fields.contains_key("value")
                            {
                                fields.insert("value".into(), Value::Null);
                                fields.insert("redacted".into(), json!(true));
                            }
                        }
                    }
                    item["evidence"]["observation"]=observation;
                    item["evidence"]["dispatchFailure"]=json!(op.dispatch_failure);

                }
            }
            a.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;
            crate::queries::records::decode(value)
        }),crate::transaction::TransactionOwner::Execution).await.map_err(Into::into)
    }

    pub async fn directory_capabilities(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        windows: bool,
        apple: bool,
    ) -> std::result::Result<Vec<crate::queries::records::Capability>, crate::queries::QueryError>
    {
        proof.require(Permission::InventoryRead, Some(device))?;
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, device, windows, apple),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, device, windows, apple) = *ctx;
                    let current=crate::action_admission::current(tx,proof).await?;
                    current.require(proof,Permission::InventoryRead,Some(device))?;
                    let tenant=tx.tenant_id().to_string();let name=device.to_owned();
                    let registrations=tx.with_connection(move|c|Box::pin(async move { sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('registrationId',id,'channel',channel,'status',state) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(name).fetch_all(c).await })).await?;
                    let agent = registrations
                        .iter()
                        .find(|v| v["channel"] == "agent" && v["status"] == "active");
                    let binding = if let Some(agent) = agent {
                        channels::agent_binding_in(
                            tx,
                            s.agent_store.clone(),
                            stored(Uuid::parse_str(
                                agent["registrationId"].as_str().ok_or(Error::Malformed)?,
                            ))?,
                        )
                        .await?
                    } else {
                        None
                    };
                    let mdm = registrations
                        .iter()
                        .any(|v| v["channel"] == "mdm" && v["status"] == "active");
                    let signed = s.signed;
                    let result = [
                        capability(
                            &current,
                            proof,
                            device,
                            (
                                "script",
                                Permission::ScriptExecute,
                                "agent",
                                signed && s.content_available,
                            ),
                            agent_prerequisite(
                                agent.is_some(),
                                binding.as_ref().map(channels::AgentBinding::script),
                            ),
                        ),
                        capability(
                            &current,
                            proof,
                            device,
                            (
                                "software",
                                Permission::SoftwareDeploy,
                                "agent",
                                signed && s.content_available,
                            ),
                            agent_prerequisite(
                                agent.is_some(),
                                binding.as_ref().map(channels::AgentBinding::software),
                            ),
                        ),
                        capability(
                            &current,
                            proof,
                            device,
                            (
                                "configuration",
                                Permission::ConfigurationWrite,
                                "mdm",
                                windows || apple,
                            ),
                            if mdm {
                                ("unknown", Some("capability_unknown"))
                            } else {
                                ("blocked", Some("not_registered"))
                            },
                        ),
                    ];
                    proof.check_live()?;
                    crate::queries::records::decode(json!(result))
                })
            },
            crate::transaction::TransactionOwner::Execution,
        )
        .await.map_err(Into::into)
    }
}
fn agent_prerequisite(
    registered: bool,
    reported: Option<bool>,
) -> (&'static str, Option<&'static str>) {
    match (registered, reported) {
        (false, _) => ("blocked", Some("not_registered")),
        (true, None) => ("unknown", Some("capability_unknown")),
        (true, Some(false)) => ("unsupported", Some("capability_not_supported")),
        (true, Some(true)) => ("ready", None),
    }
}
fn capability(
    current: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    device: &str,
    spec: (&str, Permission, &str, bool),
    prerequisite: (&str, Option<&str>),
) -> Value {
    let (action, permission, channel, supported) = spec;
    let allowed = current.require(proof, permission, Some(device)).is_ok();
    json!({"action":action,"channel":channel,
        "productSupport":{"state":if supported{"supported"}else{"unsupported"},"reason":if supported{None}else{Some("product_not_configured")}},
        "devicePrerequisite":{"state":prerequisite.0,"reason":prerequisite.1},
        "permission":{"allowed":allowed,"reason":if allowed{None}else{Some("permission_denied")}}})
}
