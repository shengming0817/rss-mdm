use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    #[serde(default = "limit")]
    pub limit: usize,
    pub cursor: Option<String>,
}
fn limit() -> usize {
    64
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    family: String,
    tenant: String,
    device: String,
    authority: String,
    after: Uuid,
}
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
        let after = if let Some(token) = &query.cursor {
            if token.len() > 4096 {
                return Err(Error::Malformed);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| Error::Malformed)?;
            if bytes.len() <= 32 {
                return Err(Error::Malformed);
            }
            let (body, signature) = bytes.split_at(bytes.len() - 32);
            ring::hmac::verify(&self.cursor_key, body, signature).map_err(|_| Error::Conflict)?;
            let cursor: Cursor = serde_json::from_slice(body).map_err(|_| Error::Conflict)?;
            if cursor.family != "device_groups"
                || cursor.tenant != self.tenant.to_string()
                || cursor.device != device
                || cursor.authority != authority
            {
                return Err(Error::Conflict);
            }
            Some(cursor.after)
        } else {
            None
        };
        audit.target_device(device);
        audit.set_action("management_read");
        run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,device,query,audit,authority),|ctx,tx|Box::pin(async move {
            let (s,p,device,q,audit,authority)=ctx;
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
                let mut bytes=checked_input(serde_json::to_vec(&Cursor{family:"device_groups".into(),tenant:tenant.to_string(),device:device.to_string(),authority:authority.clone(),after}))?;
                bytes.extend_from_slice(ring::hmac::sign(&s.cursor_key,&bytes).as_ref());Some(URL_SAFE_NO_PAD.encode(bytes))
            } else {None};
            p.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(serde_json::json!({"items":items,"nextCursor":next,"associationCurrent":resolved.current}))
        }),TransactionOwner::Assets).await
    }
}
