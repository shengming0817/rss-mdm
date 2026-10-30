use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{cursor::CursorCodec, window::Query};
pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "device_groups",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
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
    ) -> std::result::Result<Memberships, Error> {
        query
            .require_schema(&SCHEMA)
            .map_err(|_| Error::Malformed)?;
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        let authority = proof.authorization()?.query_binding(proof)?;
        audit.target_device(device);
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
        let mut connection =
            tokio::time::timeout(budget.control().total_remaining(), self.read_pool.acquire())
                .await
                .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?
                .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
        let read=tokio::time::timeout(budget.control().total_remaining(),async {
            use sqlx::Acquire;
            let mut tx=connection.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true)")
                .bind(self.tenant.to_string()).bind(budget.control().total_remaining().as_millis().max(1).to_string()).execute(&mut *tx).await?;
            let current=rss_mdm_authorization_service::snapshot_on(&mut tx,proof.tenant_id(),proof.instance_id()).await?;
            current.require(proof,Permission::GroupRead,None)?;
            current.require_all_devices(proof,Permission::InventoryRead)?;
            if current.query_binding(proof)?!=authority {return Err(Error::Conflict.into());}
            let result=self.memberships_on(&mut tx,proof,device,query,&authority).await?;
            tx.rollback().await?;
            Ok::<_,crate::transaction::Fault>(result)
        }).await;
        let result = match read {
            Ok(Ok(result)) => result,
            other => {
                connection.close_on_drop();
                return Err(match other {
                    Ok(Err(crate::transaction::Fault::Request(e))) => e,
                    _ => Error::Unavailable(Failure::AssetsStorage),
                });
            }
        };
        drop(connection);
        // Release the page connection before revalidating current authority.
        self.audit_store
            .read(
                self.tenant,
                &budget.control(),
                (proof, &authority),
                |ctx, tx| {
                    Box::pin(async move {
                        let (proof, expected) = *ctx;
                        tx.with_connection_context(
                            &mut (proof, expected),
                            |(proof, expected), c| {
                                Box::pin(async move {
                                    let current = rss_mdm_authorization_service::snapshot_on(
                                        c,
                                        proof.tenant_id(),
                                        proof.instance_id(),
                                    )
                                    .await
                                    .map_err(|_| {
                                        sqlx::Error::Protocol("authorization read".into())
                                    })?;
                                    Ok::<_, sqlx::Error>(
                                        current
                                            .query_binding(proof)
                                            .is_ok_and(|binding| binding == **expected),
                                    )
                                })
                            },
                        )
                        .await
                        .map_err(rss_mdm_audit_integration::Error::from)
                    })
                },
            )
            .await
            .fold(
                |same| if same { Ok(()) } else { Err(Error::Conflict) },
                |_| Err(Error::Unavailable(Failure::AssetsStorage)),
                |_| Err(Error::Unavailable(Failure::AssetsStorage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::Unavailable(Failure::AssetsStorage)),
                |_| Err(Error::Unavailable(Failure::AssetsStorage)),
            )?;
        proof.check_live()?;
        Ok(result)
    }
    async fn memberships_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &AuthorizedPrincipal,
        device: &str,
        q: &Query,
        authority: &str,
    ) -> Result<Memberships> {
        if device.is_empty() || device.len() > 255 {
            return Err(Error::Malformed.into());
        }
        if !crate::device::read::registered(c, self.tenant.to_string(), device.to_owned()).await? {
            return Err(Error::Group(GroupMissing::Device).into());
        }
        let resolved = self.objects.memberships(c, self.tenant, device).await?;
        let codec = CursorCodec::from_key(self.cursor_key.clone());
        let binding = checked_input(rss_mdm_query::cursor::fingerprint(&(
            "device-groups",
            p.tenant_id(),
            p.instance_id(),
            p.principal_id(),
            device,
            authority,
        )))?;
        let after = q
            .cursor()
            .as_ref()
            .map(|token| -> Result<Uuid> {
                codec
                    .decode(
                        &checked_input(rss_contract::PageCursor::parse(token))?,
                        &binding,
                    )
                    .map_err(|_| Error::Conflict.into())
            })
            .transpose()?;
        let keys = resolved
            .objects
            .iter()
            .map(crate::objects::ObjectRef::key)
            .collect::<Vec<_>>();
        let mut items = group_checked(
            self.groups
                .memberships_on(c, device, &keys, after, q.limit())
                .await?,
        )?;
        let more = items.len() > q.limit();
        items.truncate(q.limit());
        for item in &mut items {
            let context: rss_mdm_group::AssetContext =
                stored(serde_json::from_value(item["assetContext"].clone()))?;
            let objects = item["objects"]
                .as_array()
                .ok_or(Error::Conflict)?
                .iter()
                .map(|v| {
                    group_checked(crate::objects::ObjectRef::from_key(
                        context,
                        v.as_str().ok_or(Error::Conflict)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            item["objects"] = json(&objects)?;
            let associated = context == rss_mdm_group::AssetContext::AssociatedDevice;
            let input = item["inputVersion"].as_str().ok_or(Error::Conflict)?;
            let (cut, complete) = if let Some(snapshot) =
                crate::objects::ObjectSnapshot::from_group_input(input)
                    .map_err(|_| Error::Conflict)?
            {
                let complete = self.objects.complete(c, self.tenant, &snapshot).await?;
                (snapshot.asset_cut, complete)
            } else {
                (
                    stored(rss_mdm_inventory::AssetCut::from_input_version(input))?,
                    true,
                )
            };
            let id = item["id"].as_str().ok_or(Error::Conflict)?;
            let dirty:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=$1::uuid AND NOT mdm.asset_visible($2::jsonb,e.revision) AND (e.kind IN('device','registration','source','credential') OR EXISTS(SELECT FROM mdm_assets.group_fields f WHERE f.tenant_id=e.tenant_id AND f.group_id=$3::uuid AND f.field=ANY(e.fields))))")
                .bind(self.tenant.to_string()).bind(cut.to_json()).bind(id).fetch_one(&mut *c).await?;
            let input_current = complete && !dirty;
            item["associationCurrent"] = if associated {
                serde_json::json!(resolved.current)
            } else {
                Value::Null
            };
            item["inputCurrent"] = serde_json::json!(input_current);
            item["evaluation"] = serde_json::json!(if item["ruleCurrent"] == true
                && input_current
                && (!associated || resolved.current)
            {
                "current"
            } else {
                "stale"
            });
        }
        let next = if more {
            let after = stored(Uuid::parse_str(
                items
                    .last()
                    .and_then(|v| v["id"].as_str())
                    .ok_or(Error::Conflict)?,
            ))?;
            Some(
                checked_input(codec.encode(&binding, &after))?
                    .as_str()
                    .to_owned(),
            )
        } else {
            None
        };
        let items = stored(
            items
                .into_iter()
                .map(serde_json::from_value::<Membership>)
                .collect::<std::result::Result<Vec<_>, _>>(),
        )?;
        Ok(Memberships {
            items,
            next_cursor: next,
            association_current: resolved.current,
        })
    }
}

#[derive(Debug, schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Memberships {
    pub items: Vec<Membership>,
    pub next_cursor: Option<String>,
    pub association_current: bool,
}
#[derive(Debug, schemars::JsonSchema, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub id: Uuid,
    #[schemars(extend("x-rss-extension"="Group presentation metadata"))]
    pub presentation: serde_json::Map<String, Value>,
    pub kind: rss_mdm_group_postgres::GroupKind,
    pub asset_context: rss_mdm_group::AssetContext,
    pub revision: i64,
    pub member_version: i64,
    pub calculation_revision: i64,
    pub member_set: Uuid,
    pub current_rule_version: Option<String>,
    pub evaluated_rule_version: Option<String>,
    pub input_version: String,
    pub as_of: i64,
    pub rule_current: bool,
    pub objects: Vec<crate::objects::ObjectRef>,
    pub association_current: Option<bool>,
    pub input_current: bool,
    pub evaluation: Evaluation,
}
#[derive(Debug, schemars::JsonSchema, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evaluation {
    Current,
    Stale,
}
