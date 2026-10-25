use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{cursor::CursorCodec, window::Query};
pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "devices",
    default_limit: 64,
    max_limit: 1000,
    order: "group identity",
    context: &[],
};
impl Groups {
    pub async fn memberships(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        query: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if !(1..=1000).contains(&query.limit) {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        let authority = proof.authorization()?.query_binding(proof)?;
        audit.target_device(device);
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        crate::transaction::inspect(&self.runtime, self.tenant,(self,proof,device,query,audit,authority),|ctx,tx|Box::pin(async move {
            let (s,p,device,q,_audit,authority)=ctx;
            let tenant=p.tenant_id().to_owned();let instance=p.instance_id().to_owned();
            let current=tx.with_connection(move|c|Box::pin(async move {
                rss_mdm_authorization_service::lock_on(c,&tenant,&instance).await.map_err(|_|sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(rss_mdm_authorization_service::snapshot_on(c,&tenant,&instance).await)
            })).await??;
            current.require(p,Permission::GroupRead,None)?;current.require_all_devices(p,Permission::InventoryRead)?;
            let current_binding=current.query_binding(p)?;
            if current_binding!=*authority {return Err(Error::Conflict.into())}

            require_device(tx,device).await?;
            let tenant=s.tenant;
            let objects=s.objects.clone();let device_owned=device.to_string();
            let resolved=tx.with_connection(move|c|Box::pin(async move {objects.memberships(c,tenant,&device_owned).await})).await?;
            let watermark=tx.with_connection(move|c|Box::pin(async move {rss_mdm_inventory_postgres::watermark_in(c,tenant).await.map_err(|_|sqlx::Error::Protocol("inventory watermark".into()))})).await?;
            let stamp=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Value>("SELECT jsonb_build_array(coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0))").bind(tenant.to_string()).fetch_one(c).await})).await?;
            let codec=CursorCodec::from_key(s.cursor_key.clone());
            let binding=checked_input(rss_mdm_query::cursor::fingerprint(&("device-groups",p.tenant_id(),p.instance_id(),p.principal_id(),*device,&*authority,watermark,stamp)))?;
            let after=q.cursor.as_ref().map(|token| -> Result<Uuid> {codec.decode(&checked_input(rss_contract::PageCursor::parse(token))?,&binding).map_err(|_|Error::Conflict.into())}).transpose()?;
            let keys=resolved.objects.iter().map(crate::objects::ObjectRef::key).collect::<Vec<_>>();
            let mut items=group_checked(s.groups.memberships_in(tx,device,&keys,after,q.limit).await?)?;
            let more=items.len()>q.limit;items.truncate(q.limit);
            for item in &mut items {
                let context: rss_mdm_group_postgres::AssetContext=checked_input(serde_json::from_value(item["assetContext"].clone()))?;
                let objects=item["objects"].as_array().ok_or(Error::Conflict)?.iter().map(|v|group_checked(crate::objects::ObjectRef::from_key(context,v.as_str().ok_or(Error::Conflict)?))).collect::<Result<Vec<_>>>()?;
                item["objects"]=checked_input(serde_json::to_value(objects))?;
                let associated=context==rss_mdm_group_postgres::AssetContext::AssociatedDevice;
                let input=item["inputVersion"].as_str().ok_or(Error::Conflict)?;
                let input_current=if let Some(snapshot)=crate::objects::ObjectSnapshot::from_group_input(input).map_err(|_|Error::Conflict)? {
                    let objects=s.objects.clone();tx.with_connection(move|c|Box::pin(async move {objects.current(c,tenant,&snapshot).await})).await?
                } else if item["kind"]=="static" {true} else {input.strip_prefix("assets:").and_then(|v|v.parse::<i64>().ok())==Some(watermark)};
                item["associationCurrent"]=if associated {serde_json::json!(resolved.current)}else{Value::Null};
                item["inputCurrent"]=serde_json::json!(input_current);
                item["evaluation"]=serde_json::json!(if item["ruleCurrent"]==true && input_current && (!associated || resolved.current) {"current"}else{"stale"});
            }
            let next=if more {
                let after=checked_input(Uuid::parse_str(items.last().and_then(|i|i["id"].as_str()).ok_or(Error::Conflict)?))?;
                Some(checked_input(codec.encode(&binding,&after))?.as_str().to_owned())
            } else {None};
            p.check_live()?;
            Ok(serde_json::json!({"items":items,"nextCursor":next,"associationCurrent":resolved.current}))
        }),TransactionOwner::Assets).await
    }
}
