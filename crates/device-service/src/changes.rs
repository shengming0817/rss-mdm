//! Relation changes are read from the existing authoritative audit stream.
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Position {
    Page { after: u64, through: u64 },
    Poll { after: Option<u64> },
}

impl Associations {
    /// A nextCursor continues one fixed window; a terminal checkpoint starts the next window.
    /// Both tokens are passed back through the same cursor input.
    pub async fn changes(&self, proof: &AuthorizedPrincipal, token: Option<&str>) -> Result<Value> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit.read(self.tenant,&budget.control(),(self,proof,token),|(service,proof,token),tx|Box::pin(async move {
            let snapshot=tx.with_connection_context(proof,|proof,c|Box::pin(read::authorization(c,proof))).await?;
            snapshot.inventory_devices(proof)?;
            let binding=json!({"kind":"device-association-changes","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":cursor::digest(&snapshot.effective(proof)?)?});
            let position=if let Some(token)=token {
                let decoded=service.decode(token)?;
                if decoded.context["binding"]!=binding{return Err(Error::CursorInvalidated);}
                serde_json::from_value(decoded.context["position"].clone()).map_err(|_|Error::Malformed)?
            }else{Position::Poll{after:None}};
            let (cursor,previous)=match position {
                Position::Page{after,through}=>(rss_audit_postgres::Cursor::resume(service.tenant,after,through).map_err(|_|Error::Malformed)?,Some(after)),
                Position::Poll{after:None}=>(rss_audit_postgres::Cursor::start(service.tenant),None),
                Position::Poll{after:Some(after)}=>{
                    // Like the timeline consumer, discover a fresh upper bound using one public
                    // Audit page. Reading then resumes after the checkpoint, never rescans history.
                    let head=tx.read_page(rss_audit_postgres::Cursor::start(service.tenant),rss_audit_postgres::ReadLimit::new(1,131072).map_err(|_|Error::Storage)?).await.map_err(|e|Error::Audit(e.into()))?;
                    let through=head.next().and_then(|c|c.continuation()).map(|(_,through)|through)
                        .or_else(||head.records().last().map(|r|r.position())).ok_or(Error::Storage)?;
                    if through<after{return Err(Error::Storage);}
                    if through==after {
                        proof.check_live()?;
                        return Ok(json!({"items":[],"nextCursor":null,"checkpoint":service.change_token(&binding,Position::Poll{after:Some(after)})?}));
                    }
                    (rss_audit_postgres::Cursor::resume(service.tenant,after,through).map_err(|_|Error::Storage)?,Some(after))
                }
            };
            let page=tx.read_page(cursor,rss_audit_postgres::ReadLimit::new(64,8388608).map_err(|_|Error::Storage)?).await.map_err(|e|Error::Audit(e.into()))?;
            let mut items=Vec::new();
            for record in page.records(){
                let decoded=rss_audit_core::decode_untrusted(record.prepared().canonical_bytes()).map_err(|_|Error::Storage)?;
                let event=decoded.event();
                if event.identity().source().source_id().as_str()!="mdm.business" || !["device_association_confirm","device_association_revoke","device_association_automatic"].contains(&event.facts().action().as_str()){continue;}
                let payload:Value=serde_json::from_slice(event.context().payload().as_bytes()).map_err(|_|Error::Storage)?;
                let a:Association=serde_json::from_value(payload.pointer("/details/association").cloned().ok_or(Error::Storage)?).map_err(|_|Error::Storage)?;
                match read::authorize(&snapshot,proof,&a.members,false){Ok(())=>items.push(json!({"association":a,"position":record.position(),"action":event.facts().action().as_str(),"recordedAt":decoded.recorded_at().unix_seconds()})),Err(Error::Forbidden)=>{},Err(e)=>return Err(e)}
            }
            let (next,checkpoint)=if let Some((after,through))=page.next().and_then(|c|c.continuation()) {
                (Some(service.change_token(&binding,Position::Page{after,through})?),None)
            }else{
                let after=page.records().last().map(|r|r.position()).or(previous);
                (None,Some(service.change_token(&binding,Position::Poll{after})?))
            };
            proof.check_live()?;
            Ok(json!({"items":items,"nextCursor":next,"checkpoint":checkpoint}))
        })).await.fold(|v|Ok(v.into_value()),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))
    }
    fn change_token(&self, binding: &Value, position: Position) -> Result<String> {
        self.encode(json!({"binding":binding,"position":position}), 0)
    }
}
