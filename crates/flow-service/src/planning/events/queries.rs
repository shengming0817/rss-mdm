//! Device-scoped batch/member queries use the same directory contract and current read authority.
use super::*;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Schema},
};
pub static BATCHES: Schema = Schema {
    id: "policy_event_batches",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("operationId", Kind::Uuid),
        Field::scalar("event", Kind::Text),
        Field::scalar("createdAt", Kind::Integer),
        Field::output("deadline"),
        Field::output("members"),
        Field::output("admission"),
        Field::output("request"),
        Field::output("processingFailure"),
    ],
};
pub static MEMBERS: Schema = Schema {
    id: "policy_event_members",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("policyId", Kind::Uuid),
        Field::scalar("versionId", Kind::Uuid),
        Field::scalar("state", Kind::Text),
        Field::output("revision"),
        Field::output("decision"),
        Field::output("operations"),
    ],
};
fn batch_column(name: &str) -> &'static str {
    match name {
        "id" => "b.id::text COLLATE \"C\"",
        "operationId" => "b.request::text COLLATE \"C\"",
        "event" => "(b.input->>'event') COLLATE \"C\"",
        "createdAt" => "b.created_at",
        _ => unreachable!("checked batch field"),
    }
}
fn member_column(name: &str) -> &'static str {
    match name {
        "id" => "m.id::text COLLATE \"C\"",
        "policyId" => "m.policy::text COLLATE \"C\"",
        "versionId" => "m.version::text COLLATE \"C\"",
        "state" => "(m.decision->>'state') COLLATE \"C\"",
        _ => unreachable!("checked member field"),
    }
}
const BATCH_SELECT: &str = "SELECT jsonb_build_object('request',b.input,'id',b.id,'operationId',b.request,'event',b.input->>'event','createdAt',b.created_at,'deadline',b.deadline,'processingFailure',(SELECT failure FROM mdm_automation.automation_jobs WHERE tenant_id=b.tenant_id AND id=b.id),'members',(SELECT count(*) FROM mdm_planning.event_members m WHERE(m.tenant_id,m.batch)=(b.tenant_id,b.id)),'admission',(SELECT coalesce(jsonb_object_agg(state,n),'{}'::jsonb) FROM(SELECT decision->>'state' state,count(*) n FROM mdm_planning.event_members WHERE tenant_id=b.tenant_id AND batch=b.id GROUP BY decision->>'state') counts)) FROM mdm_planning.event_batches b WHERE b.tenant_id=";
impl Events {
    pub async fn read_management(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        batch: Option<Uuid>,
        members: bool,
        query: &rss_mdm_query::directory::Query,
        audit: &RequestAudit,
    ) -> std::result::Result<ReadResult, Error> {
        self.read(
            Requester::Management(proof),
            device,
            batch,
            members,
            query,
            audit,
        )
        .await
    }
    pub async fn read_agent(
        &self,
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        batch: Option<Uuid>,
        members: bool,
        query: &rss_mdm_query::directory::Query,
        audit: &RequestAudit,
    ) -> std::result::Result<ReadResult, Error> {
        if p.tenant() != self.planning.tenant {
            return Err(Error::Forbidden);
        }
        self.read(
            Requester::Agent(p),
            p.device(),
            batch,
            members,
            query,
            audit,
        )
        .await
    }
    async fn read(
        &self,
        reader: Requester<'_>,
        device: &str,
        batch: Option<Uuid>,
        members: bool,
        query: &rss_mdm_query::directory::Query,
        audit: &RequestAudit,
    ) -> std::result::Result<ReadResult, Error> {
        let (proof, principal) = match reader {
            Requester::Management(proof) => (Some(proof), None),
            Requester::Agent(principal) => (None, Some(principal)),
        };
        let target = principal.map(|p| Target {
            device: p.device().into(),
            registration: p.registration(),
            generation: p.generation(),
        });
        let agent = target.as_ref();
        let schema = if members { &MEMBERS } else { &BATCHES };
        query.require_schema(schema).map_err(crate::query_error)?;
        audit.set_action(
            "policy_event_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let p = &self.planning;
        crate::transaction::inspect(self.execution.event_runtime(),p.tenant,(self,proof,principal,agent,device,batch,members,&query),|ctx,tx|Box::pin(async move{
            let(s,proof,principal,agent,device,batch,members,q)=*ctx;
            if let Some(principal)=principal {s.execution.verify_event_device_in(tx,principal,None).await?;}
            let identity=if let Some(proof)=proof {
                let snapshot=crate::action_admission::current(tx,proof).await?;
                snapshot.require(proof,Permission::OperationRead,Some(device))?;
                json!(snapshot.query_binding(proof)?)
            }else{
                let target=agent.ok_or(Error::Forbidden)?;
                if !s.execution.event_device_current_in(tx,target).await?{return Err(Error::Forbidden.into());}
                json!(target)
            };
            let binding=q.binding(&(s.planning.tenant.to_string(),identity,device,batch,members)).map_err(crate::query_error)?;
            let codec=CursorCodec::from_key(s.planning.cursor_key.clone());
            let after=q.after(&codec,&binding).map_err(crate::query_error)?;
            if let Some(id)=batch{
                let tenant=tx.tenant_id().to_string();let device=device.to_owned();
                let exists:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.event_batches WHERE tenant_id=$1::uuid AND id=$2 AND device=$3)").bind(tenant).bind(id).bind(device).fetch_one(c).await})).await?;
                if !exists{return Err(Error::NotFound.into());}
            }
            let prefix=if members {"SELECT jsonb_build_object('id',m.id,'policyId',m.policy,'versionId',m.version,'revision',m.revision,'state',m.decision->>'state','decision',m.decision) FROM mdm_planning.event_members m JOIN mdm_planning.event_batches b ON(b.tenant_id,b.id)=(m.tenant_id,m.batch) WHERE b.tenant_id="}else{BATCH_SELECT};
            let mut sql=sqlx::QueryBuilder::new(prefix);sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND b.device=").push_bind(device.to_owned());
            if let Some(batch)=batch{sql.push(" AND b.id=").push_bind(batch);}
            if let Some(target)=agent {sql.push(" AND b.caller->'target'->>'registration'=").push_bind(target.registration.to_string());}
            rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),if members{member_column}else{batch_column}).map_err(crate::query_error)?;
            let items:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
            let result=if members {
                let mut items:Vec<Member>=stored(items.into_iter().map(serde_json::from_value).collect::<std::result::Result<_,_>>())?;
                for item in &mut items {
                    if let wire::PolicyEventDecision::Accepted{operations:refs}=&item.decision {
                        for reference in refs {item.operations.push(s.execution.policy_event_operation_in(tx,reference).await?);}
                    }
                }
                ReadResult::Members(q.page_typed(items,&codec,&binding).map_err(crate::query_error)?)
            } else {
                let items:Vec<Batch>=stored(items.into_iter().map(serde_json::from_value).collect::<std::result::Result<_,_>>())?;
                if batch.is_some() {ReadResult::Batch(Box::new(items.into_iter().next().ok_or(Error::NotFound)?))}
                else {ReadResult::Batches(q.page_typed(items,&codec,&binding).map_err(crate::query_error)?)}
            };
            if let Some(proof)=proof{proof.check_live()?;}
            Ok(result)
        }),TransactionOwner::Planning).await
    }
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub event: wire::PolicyEventName,
    pub created_at: i64,
    pub deadline: i64,
    pub request: wire::PolicyEventRequest,
    pub processing_failure: Option<String>,
    pub members: u64,
    pub admission: std::collections::BTreeMap<DecisionState, u64>,
}
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    Pending,
    Accepted,
    NoChange,
    Rejected,
    Expired,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub revision: i64,
    pub state: DecisionState,
    pub decision: wire::PolicyEventDecision,
    #[serde(skip_deserializing)]
    pub operations: Vec<rss_mdm_execution_service::policy_events::EventOperationProgress>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ReadResult {
    Batch(Box<Batch>),
    Batches(rss_mdm_query::Page<rss_mdm_query::directory::Projection<Batch>>),
    Members(rss_mdm_query::Page<rss_mdm_query::directory::Projection<Member>>),
}

impl ReadResult {
    pub fn batch(self) -> std::result::Result<Batch, Error> {
        match self {
            Self::Batch(value) => Ok(*value),
            _ => Err(Error::Unavailable(Failure::PlanningStorage)),
        }
    }
    pub fn batches(
        self,
    ) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Batch>>, Error>
    {
        match self {
            Self::Batches(value) => Ok(value),
            _ => Err(Error::Unavailable(Failure::PlanningStorage)),
        }
    }
    pub fn members(
        self,
    ) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Member>>, Error>
    {
        match self {
            Self::Members(value) => Ok(value),
            _ => Err(Error::Unavailable(Failure::PlanningStorage)),
        }
    }
}
