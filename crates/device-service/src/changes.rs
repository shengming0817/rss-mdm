//! Relation changes are read from the existing authoritative audit stream.
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use serde_json::{Value, json};
use std::time::Duration;
impl Associations {
    pub async fn changes(&self, proof: &AuthorizedPrincipal, token: Option<&str>) -> Result<Value> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit.read(self.tenant,&budget.control(),(self,proof,token),|(service,proof,token),tx|Box::pin(async move {
            let snapshot=tx.with_connection_context(proof,|proof,c|Box::pin(read::authorization(c,proof))).await?;
            snapshot.inventory_devices(proof)?;
            let context=json!({"kind":"device-association-changes","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":cursor::digest(&snapshot.effective(proof)?)?});
            let cursor=if let Some(token)=token {
                let decoded=service.decode(token)?;
                if decoded.context["binding"]!=context{return Err(Error::CursorInvalidated);}
                rss_audit_postgres::Cursor::resume(service.tenant,decoded.context["after"].as_u64().ok_or(Error::Malformed)?,decoded.context["through"].as_u64().ok_or(Error::Malformed)?).map_err(|_|Error::Malformed)?
            }else{rss_audit_postgres::Cursor::start(service.tenant)};
            let page=tx.read_page(cursor,rss_audit_postgres::ReadLimit::new(64,8388608).map_err(|_|Error::Storage)?).await.map_err(|e|Error::Audit(e.into()))?;
            let mut items=Vec::new();
            for record in page.records(){
                let decoded=rss_audit_core::decode_untrusted(record.prepared().canonical_bytes()).map_err(|_|Error::Storage)?;
                let event=decoded.event();
                if event.identity().source().source_id().as_str()!="mdm.business" || !["device_association_confirm","device_association_revoke","device_association_automatic"].contains(&event.facts().action().as_str()){continue;}
                let payload:Value=serde_json::from_slice(event.context().payload().as_bytes()).map_err(|_|Error::Storage)?;
                let a:Association=serde_json::from_value(payload.pointer("/details/association").cloned().ok_or(Error::Storage)?).map_err(|_|Error::Storage)?;
                match read::authorize(&snapshot,proof,&a.members,false){Ok(())=>items.push(json!({"association":a,"action":event.facts().action().as_str(),"recordedAt":decoded.recorded_at().unix_seconds()})),Err(Error::Forbidden)=>{},Err(e)=>return Err(e)}
            }
            let next=page.next().and_then(|c|c.continuation()).map(|(after,through)|service.encode(json!({"binding":context,"after":after,"through":through}),0)).transpose()?;
            proof.check_live()?;
            Ok(json!({"items":items,"nextCursor":next}))
        })).await.fold(|v|Ok(v.into_value()),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))
    }
}
