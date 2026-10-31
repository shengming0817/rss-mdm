//! A configuration preview validates content, then reads one immutable authorized Scope snapshot.
use super::*;
use crate::authorization::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_policy::pages::{PREVIEW_SCHEMA, Preview};
use rss_mdm_query::{cursor::CursorCodec, window::Query};
use serde_json::json;
use sqlx::Acquire;
use std::time::Duration;
pub struct Previews {
    pub publications: Arc<publication::Publications>,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub read_pool: sqlx::PgPool,
    pub clock: Arc<dyn rss_request_context::Clock>,
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub action: rss_mdm_policy::Action,
    pub scope_result: Uuid,
    pub items: Vec<Target>,
    pub next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub object: rss_mdm_scope_service::channels::ObjectRef,
    pub channel: rss_mdm_inventory::Channel,
    pub availability: rss_mdm_scope_service::channels::Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub eligibility: rss_mdm_scope_service::channels::ScopeAdmission,
    pub task_admission: Option<()>,
}
fn authorize(
    grant: &Snapshot,
    proof: &AuthorizedPrincipal,
    input: &Preview,
) -> std::result::Result<(), Error> {
    grant.require(proof, Permission::PolicyRead, None)?;
    grant.require(proof, Permission::ResourceRead, None)?;
    grant.require_all_devices(proof, Permission::InventoryRead)?;
    crate::management::authorize_policy_snapshot(grant, proof, &input.definition)
}
impl Previews {
    pub async fn preview(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        input: &Preview,
        query: &Query,
        codec: &CursorCodec,
    ) -> std::result::Result<Response, Error> {
        query
            .require_schema(&PREVIEW_SCHEMA)
            .map_err(|_| Error::Malformed)?;
        input.definition.validate()?;
        proof.check_live()?;
        authorize(proof.authorization()?, proof, input)?;
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let rss_mdm_policy::Action::Configuration { resource, exit } = &input.definition.action
        else {
            return Err(Error::Unsupported);
        };
        let verified = self.publications.prepare(resource).await?;
        let expected = crate::transaction::inspect(
            &self.publications.runtime,
            self.publications.tenant,
            (self, proof, input, resource, *exit, &verified),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, input, resource, exit, verified) = *ctx;
                    let grant = crate::action_admission::current(tx, proof).await?;
                    authorize(&grant, proof, input)?;
                    Ok(s.publications
                        .validate_in(tx, resource, exit, Some(verified), proof, &grant)
                        .await?
                        .1)
                })
            },
        )
        .await?;
        let started = self.clock.now();
        let remaining = || {
            Duration::from_secs(6)
                .saturating_sub(self.clock.now().saturating_duration_since(started))
        };
        let deadline = || Error::Unavailable(Failure::RequestDeadline);
        let mut connection = tokio::time::timeout(remaining(), self.read_pool.acquire())
            .await
            .map_err(|_| deadline())?
            .map_err(|_| Error::Unavailable(Failure::PolicyStorage))?;
        let result=tokio::time::timeout(remaining(),async{
   let mut tx=connection.begin().await?;
   sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
   sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(self.publications.tenant.to_string()).bind(remaining().as_millis().max(1).to_string()).execute(&mut *tx).await?;
   let grant=rss_mdm_authorization_service::snapshot_on(&mut tx,proof.tenant_id(),proof.instance_id()).await?;authorize(&grant,proof,input)?;
   let authority=grant.query_binding(proof)?;
   let mut facts=rss_mdm_resource_postgres::version_facts_on(&mut tx,self.publications.tenant,&[(expected.resource().as_str().into(),expected.label().as_str().into())]).await?;
   let(version,state)=facts.versions.pop().flatten().ok_or(Error::Conflict)?;
   if version.digest()!=expected.digest()||state!=rss_mdm_resource::State::Active{return Err(Error::Conflict.into())}
   let scope=input.definition.scope;let channel=rss_mdm_inventory::Channel::Mdm;
   let binding=rss_mdm_scope_service::window::binding_on(&self.source,&mut tx,self.publications.tenant,proof,&authority,PREVIEW_SCHEMA.id,scope,&json!([input.definition,input.scope_result])).await?;
   let after=rss_mdm_scope_service::window::after(codec,query,&binding)?;
   let mut objects=self.source.assignment_objects_on(&mut tx,self.publications.tenant,scope,channel,after.as_deref(),query.limit()).await?;
   let result=self.source.preview_scope_on(&mut tx,self.publications.tenant,scope,channel,None).await?.result;
   if input.scope_result.is_some_and(|r|r!=result){return Err(Error::Conflict.into())}
   let more=objects.len()>query.limit();objects.truncate(query.limit());let next=if more{objects.last().map(|o|o.object.key())}else{None};
   let items=objects.into_iter().map(|o|Target{object:o.object,channel:o.channel,availability:o.availability,reason:o.reason,target:o.target,eligibility:o.admission,task_admission:None}).collect();
   let page=Response{action:input.definition.action.clone(),scope_result:result,items,next_cursor:rss_mdm_scope_service::window::next(codec,&binding,next)?};
   tx.rollback().await?;Ok::<_,Fault>((page,authority))
  }).await;
        let (page, authority) = match result {
            Ok(Ok(v)) => v,
            other => {
                connection.close_on_drop();
                return Err(match other {
                    Ok(Err(Fault::Request(e))) => e,
                    Ok(Err(Fault::Sql(e)))
                        if e.as_database_error()
                            .and_then(|e| e.code())
                            .is_some_and(|c| c == "40001" || c == "40P01") =>
                    {
                        Error::ReadConflict
                    }
                    Ok(Err(_)) => Error::Unavailable(Failure::PolicyStorage),
                    Err(_) => deadline(),
                    Ok(Ok(_)) => unreachable!(),
                });
            }
        };
        drop(connection);
        if remaining().is_zero() {
            return Err(deadline());
        }
        crate::transaction::inspect_budget(
            &self.publications.runtime,
            self.publications.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(remaining()),
            (proof, authority),
            |ctx, tx| {
                Box::pin(async move {
                    let (proof, expected) = ctx;
                    let current = crate::action_admission::current(tx, proof).await?;
                    if current.query_binding(proof)? != *expected {
                        return Err(Error::ReadConflict.into());
                    }
                    proof.check_live()?;
                    Ok(())
                })
            },
        )
        .await?;
        Ok(page)
    }
}
