use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    pub referenceable_for: Option<Uuid>,
    pub after: Option<Uuid>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub kind: Option<rss_mdm_group_postgres::GroupKind>,
    pub asset_context: Option<rss_mdm_group_postgres::AssetContext>,
    #[serde(default)]
    pub deleted: bool,
    pub name: Option<String>,
}
fn limit() -> usize {
    64
}
impl DirectoryQuery {
    fn selection(&self) -> rss_mdm_group_postgres::directory::DirectoryQuery {
        rss_mdm_group_postgres::directory::DirectoryQuery {
            after: self.after,
            limit: self.limit,
            descending: self.descending,
            kind: self.kind,
            asset_context: self.asset_context,
            deleted: self.deleted,
            name: self.name.clone(),
        }
    }
}

impl Groups {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &DirectoryQuery,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if q.referenceable_for.is_some_and(|id| id.is_nil()) {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,q,audit),|ctx,tx|Box::pin(async move {
            let (s,p,q,audit)=*ctx;p.manage(Permission::GroupRead)?;p.require_all_devices(Permission::InventoryRead)?;
            let mut query=q.selection();
            let mut graph=if q.referenceable_for.is_some() {Some(dependencies::graph_in(tx).await?)}else{None};
            if let Some(id)=q.referenceable_for {
                let gid=checked_input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
                let group=group_checked(s.groups.lock_reference_target_in(tx,gid).await?)?;
                if query.deleted || query.asset_context.is_some_and(|c|c!=group.asset_context) {return Err(Error::Malformed.into());}
                query.asset_context=Some(group.asset_context);
            }
            let selecting=query.asset_context.is_some();
            let sensitive=assets::ReadScope::from_proof(p)?.sensitive;
            let mut groups=Vec::new();let mut scanned=0;
            loop {
                let page=group_checked(s.groups.directory_in(tx,&query).await?)?;
                if page.is_empty() {break;}
                let count=page.len();let last=page.last().map(|g|stored(Uuid::parse_str(&g.id.to_string()))).transpose()?;
                for group in page {
                    scanned+=1;
                    if scanned>dependencies::MAX_GRAPH {return Err(Error::Malformed.into());}
                    let id=stored(Uuid::parse_str(&group.id.to_string()))?;
                    if let (Some(owner),Some(graph))=(q.referenceable_for,graph.as_mut()) {
                        let previous=graph.insert(owner,[id].into());
                        let valid=dependencies::validate_graph(graph).is_ok();
                        if let Some(previous)=previous {graph.insert(owner,previous);}else{graph.remove(&owner);}
                        if !valid {continue;}
                    }
                    if selecting && let Some(version)=&group.rule_version {
                        let rule=group_checked(s.groups.rule_in(tx,group.id,version).await?)?.ok_or(Error::Conflict)?;
                        let catalog=assets::catalog_in(tx,s.tenant,i64::MAX).await?;
                        match assets::filter::require_visible_rule(&catalog,&rule,sensitive) {
                            Err(Fault::Request(Error::Forbidden))=>continue,
                            result=>result?,
                        }
                        match s.validate_references_in(tx,id,group.asset_context,&rule,sensitive).await {
                            Err(Fault::Request(Error::Forbidden))=>continue,
                            result=>{result?;},
                        }
                    }
                    groups.push(group);
                    if groups.len()>q.limit {break;}
                }
                if groups.len()>q.limit || count<=query.limit {break;}
                query.after=last;
            }
            let more=groups.len()>q.limit;groups.truncate(q.limit);let next=if more{groups.last().map(|g|g.id.to_string())}else{None};
            let items=groups.iter().map(|g|serde_json::json!({"id":g.id,"kind":g.kind,"assetContext":g.asset_context,"presentation":g.presentation,"revision":g.revision,"calculationRevision":g.calculation_revision,"memberVersion":g.member_version,"memberCount":g.member_count,"ruleVersion":g.rule_version,"deleted":g.deleted})).collect::<Vec<_>>();
            p.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(serde_json::json!({"items":items,"nextCursor":next}))
        }),crate::transaction::TransactionOwner::Assets).await
    }
}
