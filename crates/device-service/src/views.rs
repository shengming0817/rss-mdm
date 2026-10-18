use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::{
    EndpointSourceFact, FieldKey, Scalar, Sensitivity, State as FieldState, ValueType,
};
pub use rss_mdm_inventory_service::objects::ObjectRef as ViewRef;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ViewQuery {
    pub cursor: Option<String>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub status: Option<String>,
    pub channel: Option<String>,
    pub source: Option<String>,
}
fn limit() -> usize {
    64
}
struct Group {
    reference: ViewRef,
    association: Option<Association>,
    endpoints: Vec<Value>,
}
impl Group {
    fn key(&self) -> String {
        match &self.reference {
            ViewRef::Endpoint(id) => format!("endpoint:{id}"),
            ViewRef::Association(id) => format!("association:{id}"),
        }
    }
    fn ids(&self) -> Result<Vec<String>> {
        self.endpoints
            .iter()
            .map(|v| v["id"].as_str().map(str::to_owned).ok_or(Error::Storage))
            .collect()
    }
    fn summary(&self) -> Value {
        json!({"reference":self.reference,"association":self.association,"endpoints":self.endpoints})
    }
}
async fn groups(
    c: &mut PgConnection,
    tenant: &str,
    allowed: Option<BTreeSet<String>>,
    world: &identity::World,
) -> Result<Vec<Group>> {
    let mut after = None;
    let mut rows = BTreeMap::new();
    loop {
        let page = rss_mdm_registration_service::device::directory::page_on(
            c,
            tenant,
            allowed.clone().map(|v| v.into_iter().collect()),
            after,
        )
        .await?;
        let items = page["items"].as_array().ok_or(Error::Storage)?;
        for item in items {
            rows.insert(
                item["id"].as_str().ok_or(Error::Storage)?.to_owned(),
                item.clone(),
            );
        }
        if items.len() < 1000 {
            break;
        }
        after = items
            .last()
            .and_then(|v| v["id"].as_str())
            .map(str::to_owned);
    }
    let mut result = Vec::new();
    for a in &world.associations {
        if a.state == State::Revoked || !a.members.iter().all(|m| rows.contains_key(&m.device)) {
            continue;
        }
        let endpoints = a
            .members
            .iter()
            .map(|m| rows.remove(&m.device).ok_or(Error::Storage))
            .collect::<Result<Vec<_>>>()?;
        result.push(Group {
            reference: ViewRef::Association(a.id),
            association: Some(world.effective(a.clone())),
            endpoints,
        });
    }
    for (id, endpoint) in rows {
        result.push(Group {
            reference: ViewRef::Endpoint(id),
            association: None,
            endpoints: vec![endpoint],
        });
    }
    result.sort_by_key(Group::key);
    Ok(result)
}
fn scope(snapshot: &Snapshot, proof: &AuthorizedPrincipal) -> Result<(bool, String)> {
    let sensitive = match snapshot.require(proof, Permission::InventorySensitiveRead, None) {
        Ok(()) => true,
        Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => false,
        Err(e) => return Err(e.into()),
    };
    Ok((sensitive, snapshot.query_binding(proof)?))
}
impl Associations {
    pub async fn views(&self, proof: &AuthorizedPrincipal, query: &ViewQuery) -> Result<Value> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        if !(1..=100).contains(&query.limit)
            || query
                .channel
                .as_deref()
                .is_some_and(|c| !["mdm", "agent"].contains(&c))
            || query.status.as_deref().is_some_and(|s| {
                ![
                    "active",
                    "pending",
                    "revoked",
                    "superseded",
                    "registered",
                    "cancelled",
                    "expired",
                ]
                .contains(&s)
            })
        {
            return Err(Error::Malformed);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        self.audit.write(self.tenant,&budget.control(),(self,proof,query),|(service,proof,query),tx|Box::pin(async move {
            tx.with_connection_context(&mut (*service,*proof,*query),|(service,proof,query),c|Box::pin(async move {
                let snapshot=read::authorization(c,proof).await?;
                let (_,grants)=scope(&snapshot,proof)?;
                let world=identity::world(c,service.tenant).await?;
                let mut groups=groups(c,proof.tenant_id(),snapshot.inventory_devices(proof)?,&world).await?;
                let version=cursor::digest(&groups.iter().map(|g|g.summary()).collect::<Vec<_>>())?;
                let context=json!({"kind":"device-directory","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":grants,"watermark":world.watermark,"version":version,"query":{"status":query.status,"channel":query.channel,"source":query.source,"descending":query.descending}});
                let offset=if let Some(cursor)=&query.cursor {let cursor=service.decode(cursor)?;if cursor.context!=context{return Err(Error::CursorInvalidated);}cursor.offset}else{0};
                groups.retain(|g|g.endpoints.iter().any(|e|matches_query(e,query)));
                if query.descending{groups.reverse();}
                let count=groups.len();let endpoints:usize=groups.iter().map(|g|g.endpoints.len()).sum();
                if offset>count{return Err(Error::CursorInvalidated);}
                let items=groups.iter().skip(offset).take(query.limit).map(Group::summary).collect::<Vec<_>>();
                let next=if offset+items.len()<count {Some(service.encode(context,offset+items.len())?)}else{None};
                proof.check_live()?;
                Ok(json!({"items":items,"statistics":{"endpointCount":endpoints,"deviceViewCount":count},"nextCursor":next}))
            })).await
        })).await.fold(|v|Ok(v.into_value()),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))
    }
    pub async fn view(&self, proof: &AuthorizedPrincipal, reference: &ViewRef) -> Result<Value> {
        self.read_view(proof, reference, None).await
    }
    pub async fn list_items(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        field: FieldKey,
        cursor: &str,
        limit: usize,
    ) -> Result<Value> {
        if !(1..=200).contains(&limit) {
            return Err(Error::Malformed);
        }
        self.read_view(proof, reference, Some((field, cursor, limit)))
            .await
    }
    async fn read_view(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        list: Option<(FieldKey, &str, usize)>,
    ) -> Result<Value> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        self.audit.write(self.tenant,&budget.control(),(self,proof,reference,list),|(service,proof,reference,list),tx|Box::pin(async move {
            tx.with_connection_context(&mut (*service,*proof,*reference,*list),|(service,proof,reference,list),c|Box::pin(async move {
                let snapshot=read::authorization(c,proof).await?;
                let (sensitive,grants)=scope(&snapshot,proof)?;
                let world=identity::world(c,service.tenant).await?;
                let mut groups=groups(c,proof.tenant_id(),snapshot.inventory_devices(proof)?,&world).await?;
                // Explicit endpoint reads retain their original semantics, even when both are visible.
                let group=match reference {
                    ViewRef::Association(_)=>groups.into_iter().find(|g|g.reference==**reference).ok_or(Error::NotFound)?,
                    ViewRef::Endpoint(id)=>{
                        let endpoint=groups.iter_mut().flat_map(|g|g.endpoints.drain(..)).find(|e|e["id"]==*id).ok_or(Error::NotFound)?;
                        Group{reference:(*reference).clone(),association:None,endpoints:vec![endpoint]}
                    }
                };
                let ids=group.ids()?;
                for id in &ids {snapshot.require(proof,Permission::InventoryRead,Some(id))?;}
                let catalog=rss_mdm_inventory_postgres::catalog_at_in(c,service.tenant,world.watermark).await.map_err(|_|Error::Storage)?;
                let raw=rss_mdm_inventory_service::assets::planning::SnapshotReader{tenant:service.tenant}.devices_on(c,world.watermark,&ids,&catalog,sensitive).await.map_err(|_|Error::Storage)?;
                let context=json!({"kind":"device-inventory-list","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":grants,"watermark":world.watermark,"view":group.summary()});
                let mut fields=BTreeMap::new();let mut lists=BTreeMap::new();
                for definition in catalog.fields().filter(|d|sensitive||d.sensitivity==Sensitivity::Standard) {
                    let sources=raw.iter().flat_map(|e|e.fields.get(&definition.key).into_iter().flat_map(|f|f.sources.iter().cloned().map(|fact|EndpointSourceFact{endpoint:e.device.clone(),fact}))).collect();
                    let resolved=rss_mdm_inventory::resolve_device(definition,sources).map_err(|_|Error::Storage)?;
                    if matches!(definition.value_type,ValueType::Array{..}) {
                        if let Some((field,token,limit))=list && *field==definition.key {
                            let cursor=service.decode(token)?;
                            if cursor.context["view"]!=context || cursor.context["field"]!=json!(field){return Err(Error::CursorInvalidated);}
                            let selected=cursor.context["source"].as_u64().ok_or(Error::Malformed)? as usize;
                            let source=resolved.sources.get(selected).ok_or(Error::CursorInvalidated)?;
                            let values=match &source.fact.state {FieldState::Known(Scalar::Array(v))=>v,_=>return Err(Error::Conflict)};
                            if cursor.offset>values.len(){return Err(Error::CursorInvalidated);}
                            let items=values.iter().skip(cursor.offset).take(*limit).collect::<Vec<_>>();
                            let next=if cursor.offset+items.len()<values.len(){Some(service.encode(cursor.context,cursor.offset+items.len())?)}else{None};
                            proof.check_live()?;
                            return Ok(json!({"reference":reference,"field":field,"source":source.fact.evidence,"endpoint":source.endpoint,"total":values.len(),"items":items,"nextCursor":next}));
                        }
                        let sources=resolved.sources.iter().enumerate().map(|(i,s)|Ok(json!({"endpoint":s.endpoint,"evidence":s.fact.evidence,"state":list_state(&s.fact.state)?,"lastKnown":s.fact.last_known.as_ref().map(|v|json!({"state":list_state(&FieldState::Known(v.value.clone())).ok(),"evidence":v.evidence})),"cursor":service.encode(json!({"view":context,"field":definition.key,"source":i}),0)?}))).collect::<Result<Vec<_>>>()?;
                        lists.insert(definition.key,json!({"state":list_state(&resolved.state)?,"sources":sources,"itemKey":definition.item_key}));
                    } else {fields.insert(definition.key,resolved);}
                }
                if list.is_some(){return Err(Error::NotFound);}
                let provenance=raw.iter().map(|e|json!({"endpoint":e.device,"quality":e.quality,"revisions":e.revisions})).collect::<Vec<_>>();
                let mut value=group.summary();value["fields"]=serde_json::to_value(fields).map_err(|_|Error::Storage)?;value["lists"]=serde_json::to_value(lists).map_err(|_|Error::Storage)?;value["inventorySources"]=json!(provenance);
                proof.check_live()?;Ok(value)
            })).await
        })).await.fold(|v|Ok(v.into_value()),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))
    }
}
fn list_state(state: &FieldState) -> Result<Value> {
    Ok(match state {
        FieldState::Known(Scalar::Array(v)) => {
            json!({"kind":"known","count":v.len(),"digest":cursor::digest(v)?})
        }
        FieldState::Known(_) => return Err(Error::Storage),
        s => serde_json::to_value(s).map_err(|_| Error::Storage)?,
    })
}

fn matches_query(endpoint: &Value, query: &ViewQuery) -> bool {
    let sources = endpoint["channels"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(endpoint["enrollments"].as_array().into_iter().flatten())
        .filter_map(|item| item["source"].as_str())
        .collect::<Vec<_>>();
    query
        .status
        .as_deref()
        .is_none_or(|status| endpoint["status"] == status)
        && query
            .source
            .as_deref()
            .is_none_or(|source| sources.contains(&source))
        && query.channel.as_deref().is_none_or(|channel| {
            sources.iter().any(|source| {
                rss_mdm_inventory::ReportSource::parse(source)
                    .is_ok_and(|source| source.channel().as_str() == channel)
            })
        })
}
