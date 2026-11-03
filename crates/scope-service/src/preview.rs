//! Request-local samples of a complete Scope draft; never a saved result or an execution plan.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.8.6
use crate::*;
use rss_mdm_audit_integration::{AuditIntent, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_inventory::{AssetCut, Channel};
use rss_mdm_inventory_service::objects::ObjectRef;
use rss_mdm_scope::Reference;
use std::time::Duration;

mod evaluation;
pub const SAMPLE_LIMIT: usize = 1000;
const CANDIDATE_LIMIT: usize = 1000;
const READ_LIMIT: usize = 16000;
const BYTE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Editing { pub scope_id: Uuid, pub expected_revision: u64 }
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Request {
    pub definition: ScopeDefinition,
    pub channel: Channel,
    pub editing: Option<Editing>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all="snake_case")]
pub enum StopReason { Complete, SampleLimit, WorkBudget }
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Source {
    pub reference: Reference,
    pub coordinates: rss_mdm_group::SourceCoordinates,
    pub object_snapshot: Option<Uuid>,
}
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Response {
    #[schemars(length(max=1000))]
    pub items: Vec<ObjectRef>,
    pub channel: Channel,
    pub scan_complete: bool,
    pub stop_reason: StopReason,
    /// Only observations in the inspected part, not a statement about unvisited input.
    pub has_unknown: bool,
    pub input_fingerprint: String,
    pub asset_cut: AssetCut,
    pub sources: Vec<Source>,
    pub as_of: i64,
}
impl Scopes {
    pub async fn preview(&self,proof:&AuthorizedPrincipal,request:&Request,audit:&RequestAudit)
        -> std::result::Result<Response,Error> {
        if proof.tenant_id()!=self.tenant.to_string() || proof.initialization_authority().is_some() { return Err(Error::Forbidden); }
        proof.bind_audit(audit)?;
        proof.manage(Permission::ScopeRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        let grouped=request.definition.references().iter().any(|r|matches!(r,Reference::Group(_)));
        if grouped { proof.manage(Permission::GroupRead)?; }
        audit.set_action("management_read",AuditIntent::Routine);
        if let Some(editing)=&request.editing {
            if editing.scope_id.is_nil() || editing.expected_revision==0 {return Err(Error::Malformed);}
            audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope,&editing.scope_id.to_string());
        }
        let budget=AuditBudget::new(Duration::from_secs(6));
        let cut=rss_mdm_inventory_service::assets::cut::capture(&self.audit_store,self.tenant,&budget).await?;
        let response=transaction::inspect_budget(&self.runtime,self.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(budget.control().total_remaining()),
            (self,proof,request,&budget,&cut,grouped),|ctx,tx|Box::pin(async move {
                let (s,proof,request,budget,cut,grouped)=*ctx;
                let authority=crate::action_admission::current(tx,proof).await?;
                authority.require(proof,Permission::ScopeRead,None)?;
                authority.require_all_devices(proof,Permission::InventoryRead)?;
                if grouped {authority.require(proof,Permission::GroupRead,None)?;}
                let timeout=budget.control().total_remaining().as_millis().max(1).to_string();
                tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("SELECT set_config('statement_timeout',$1,true)").bind(timeout).execute(c).await?;
                    Ok(())
                })).await?;
                if let Some(editing)=&request.editing {
                    let head=s.store.head_in(tx,editing.scope_id,true).await?;
                    if head.revision!=editing.expected_revision {return Err(Error::Conflict.into());}
                }
                s.validate_references_in(tx,&request.definition).await?;
                let frozen=s.capture_definition_in(tx,&request.definition,cut).await?;
                for source in &frozen.sources {
                    if let Reference::Group(id)=source.reference {
                        let source= rss_mdm_group::GroupSource {
                            group:checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                            coordinates:source.coordinates.clone(),
                        };
                        if !group_checked(s.groups.source_ready_in(tx,&source).await?)? {return Err(Error::Conflict.into());}
                    }
                    if let Some(snapshot)=&source.snapshot {
                        let objects=s.objects.clone();let tenant=s.tenant;let snapshot=snapshot.clone();
                        let complete=tx.with_connection(move|c|Box::pin(async move {objects.complete(c,tenant,&snapshot).await})).await?;
                        if !complete {return Err(Error::Conflict.into());}
                    }
                }
                let scan=s.preview_scan_in(tx,request,cut,&frozen,budget).await?;
                proof.check_live()?;
                Ok(Response {
                    items:scan.items,channel:request.channel,scan_complete:scan.reason==StopReason::Complete,
                    stop_reason:scan.reason,has_unknown:scan.has_unknown,
                    input_fingerprint:checked_input(rss_mdm_query::cursor::fingerprint(request))?,
                    asset_cut:cut.clone(),as_of:frozen.as_of,
                    sources:frozen.sources.iter().map(|s|Source{reference:s.reference.clone(),coordinates:s.coordinates.clone(),object_snapshot:s.snapshot.as_ref().map(|s|s.id)}).collect(),
                })
            })).await?;
        proof.check_live()?;
        Ok(response)
    }
}
