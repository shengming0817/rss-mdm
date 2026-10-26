//! Relation changes are read from the existing authoritative audit stream.
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "association_changes",
    default_limit: 64,
    max_limit: 64,
    order: "audit position navigation",
    context: &[],
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    navigation_after: u64,
}

impl Associations {
    /// Ordinary navigation only. Refresh from the first page to observe newly committed facts.
    pub async fn changes(
        &self,
        proof: &AuthorizedPrincipal,
        query: &rss_mdm_query::window::Query,
    ) -> Result<rss_mdm_query::Page<ChangeEntry>> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let token = query.cursor().as_deref();
        query
            .require_schema(&SCHEMA)
            .map_err(|_| Error::Malformed)?;
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit.read(self.tenant,&budget.control(),(self,proof,token,query.limit()),|(service,proof,token,limit),tx|Box::pin(async move {
            let snapshot=tx.with_connection_context(proof,|proof,c|Box::pin(read::authorization(c,proof))).await?;
            snapshot.inventory_devices(proof)?;
            let binding=json!({"kind":"device-association-changes-v2","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":snapshot.query_binding(proof)?});
            let cursor=if let Some(token)=token {
                let decoded=service.decode(token)?;
                if decoded.context["binding"]!=binding{return Err(Error::CursorInvalidated);}
                let position: Position=serde_json::from_value(decoded.context["position"].clone()).map_err(|_|Error::Malformed)?;
                let head=tx.read_page(rss_audit_postgres::Cursor::start(service.tenant),rss_audit_postgres::ReadLimit::new(1,8388608).map_err(|_|Error::Storage)?).await.map_err(|e|Error::Audit(e.into()))?;
                let through=head.next().and_then(|c|c.continuation()).map(|(_,through)|through).or_else(||head.records().last().map(|r|r.position()));
                let Some(through)=through.filter(|through|*through>position.navigation_after) else {
                    proof.check_live()?;
                    return Ok(rss_mdm_query::Page {items:vec![],next_cursor:None});
                };
                rss_audit_postgres::Cursor::resume(service.tenant,position.navigation_after,through).map_err(|_|Error::Malformed)?
            }else{rss_audit_postgres::Cursor::start(service.tenant)};
            let page=tx.read_page(cursor,rss_audit_postgres::ReadLimit::new(*limit as u32,8388608).map_err(|_|Error::Storage)?).await.map_err(|e|Error::Audit(e.into()))?;
            let mut items=Vec::new();
            for record in page.records(){
                let decoded=rss_audit_core::decode_untrusted(record.prepared().canonical_bytes()).map_err(|_|Error::Storage)?;
                let event=decoded.event();
                if event.identity().source().source_id().as_str()!="mdm.business" {continue;}
                let action=match event.facts().action().as_str() {"device_association_confirm"=>ChangeAction::Confirm,"device_association_revoke"=>ChangeAction::Revoke,"device_association_automatic"=>ChangeAction::Automatic,_=>continue};
                let payload:Value=serde_json::from_slice(event.context().payload().as_bytes()).map_err(|_|Error::Storage)?;
                let a:Association=serde_json::from_value(payload.pointer("/details/association").cloned().ok_or(Error::Storage)?).map_err(|_|Error::Storage)?;
                match read::authorize(&snapshot,proof,&a.members,false){Ok(())=>items.push(ChangeEntry {association:a,position:record.position(),action,recorded_at:decoded.recorded_at().unix_seconds()}),Err(Error::Forbidden)=>{},Err(e)=>return Err(e)}
            }
            let next=page.next().and_then(|c|c.continuation()).map(|(after,_)| service.change_token(&binding,Position{navigation_after:after})).transpose()?;
            proof.check_live()?;
            Ok(rss_mdm_query::Page {items,next_cursor:next})
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))
    }
    fn change_token(&self, binding: &Value, position: Position) -> Result<String> {
        self.encode(json!({"binding":binding,"position":position}), 0)
    }
}

#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEntry {
    pub association: Association,
    pub position: u64,
    pub action: ChangeAction,
    pub recorded_at: i64,
}
#[derive(schemars::JsonSchema, Serialize)]
pub enum ChangeAction {
    #[serde(rename = "device_association_confirm")]
    Confirm,
    #[serde(rename = "device_association_revoke")]
    Revoke,
    #[serde(rename = "device_association_automatic")]
    Automatic,
}
