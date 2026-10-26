use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::{
    ArrayState, EndpointArrayFact, EndpointSourceFact, FieldKey, Sensitivity, ValueType,
};
pub use rss_mdm_inventory_service::objects::ObjectRef as ViewRef;
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
pub(super) struct Group {
    pub(super) reference: ViewRef,
    pub(super) association: Option<Association>,
    pub(super) endpoints: Vec<Value>,
}
impl Group {
    pub(super) fn key(&self) -> String {
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
    pub(super) fn summary(&self) -> Value {
        json!({"reference":self.reference,"association":self.association,"endpoints":self.endpoints})
    }
}
pub(super) async fn groups(
    c: &mut PgConnection,
    tenant: &str,
    selected: &BTreeSet<String>,
    world: &identity::World,
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
) -> Result<(Vec<Group>, crate::presentation::Bindings)> {
    let page = rss_mdm_registration_service::device::directory::page_on(
        c,
        tenant,
        &selected.iter().cloned().collect::<Vec<_>>(),
    )
    .await?;
    let mut rows = page["items"]
        .as_array()
        .ok_or(Error::Storage)?
        .iter()
        .map(|item| {
            Ok((
                item["id"].as_str().ok_or(Error::Storage)?.to_owned(),
                item.clone(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let states: Vec<(String, String)> = sqlx::query_as(
        "SELECT device,state FROM mdm_devices.asset_states WHERE tenant_id=$1::uuid AND device=ANY($2)",
    ).bind(tenant).bind(rows.keys().cloned().collect::<Vec<_>>()).fetch_all(&mut *c).await?;
    let states = states.into_iter().collect::<BTreeMap<_, _>>();
    for (id, endpoint) in &mut rows {
        endpoint["assetState"] = json!(states.get(id).map(String::as_str).unwrap_or("active"));
    }
    let mut projected = rows.into_values().collect::<Vec<_>>();
    let bindings = crate::presentation::endpoints(
        c,
        TenantId::parse(tenant).map_err(|_| Error::Storage)?,
        world.watermark,
        snapshot,
        proof,
        &mut projected,
    )
    .await?;
    let mut rows = projected
        .into_iter()
        .map(|e| (e["id"].as_str().unwrap().to_owned(), e))
        .collect::<BTreeMap<_, _>>();
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
    Ok((result, bindings))
}
pub(super) fn scope(snapshot: &Snapshot, proof: &AuthorizedPrincipal) -> Result<(bool, String)> {
    let sensitive = match snapshot.require(proof, Permission::InventorySensitiveRead, None) {
        Ok(()) => true,
        Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => false,
        Err(e) => return Err(e.into()),
    };
    Ok((sensitive, snapshot.query_binding(proof)?))
}
impl Associations {
    pub async fn views(
        &self,
        proof: &AuthorizedPrincipal,
        query: &rss_mdm_query::directory::Query,
        personnel: &crate::personnel::Reader<'_>,
    ) -> Result<Value> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        self.directory_page(proof, query, personnel).await
    }
    pub async fn view(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        personnel: &crate::personnel::Reader<'_>,
    ) -> Result<Value> {
        self.read_view(proof, reference, None, personnel).await
    }
    pub async fn list_items(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        field: FieldKey,
        cursor: &str,
        limit: usize,
        personnel: &crate::personnel::Reader<'_>,
    ) -> Result<Value> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Malformed);
        }
        self.read_view(proof, reference, Some((field, cursor, limit)), personnel)
            .await
    }
    async fn read_view(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        list: Option<(FieldKey, &str, usize)>,
        personnel: &crate::personnel::Reader<'_>,
    ) -> Result<Value> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        let (mut value, bindings, sensitive, grants, observed) = self.audit.write(self.tenant,&budget.source_control(),(self,proof,reference,list),|(service,proof,reference,list),tx|Box::pin(async move {
            tx.with_connection_context(&mut (*service,*proof,*reference,*list),|(service,proof,reference,list),c|Box::pin(async move {
                rss_mdm_inventory_postgres::lock_watermark_in(c,service.tenant).await?;
                let snapshot=read::authorization(c,proof).await?;
                let (sensitive,grants)=scope(&snapshot,proof)?;
                let (ids,associations)=match reference {
                    ViewRef::Endpoint(id)=>{
                        snapshot.require(proof,Permission::InventoryRead,Some(id)).map_err(|e|match e {
                            rss_mdm_authorization_service::error::AuthorizationError::Forbidden=>Error::NotFound,
                            other=>other.into(),
                        })?;
                        (vec![id.clone()],vec![])
                    },
                    ViewRef::Association(id)=>{
                        let association=read::load(c,proof.tenant_id(),*id).await?;
                        if association.state==State::Revoked {return Err(Error::NotFound);}
                        read::authorize(&snapshot,proof,&association.members,false).map_err(|e|match e {Error::Forbidden=>Error::NotFound,other=>other})?;
                        (association.members.iter().map(|m|m.device.clone()).collect(),vec![*id])
                    },
                };
                let world=identity::local_world(c,service.tenant,&ids,&associations).await?;
                let (mut groups,bindings)=groups(c,proof.tenant_id(),&ids.into_iter().collect(),&world,&snapshot,proof).await?;
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
                let raw=rss_mdm_inventory_service::assets::planning::SnapshotReader{tenant:service.tenant}.summary_devices_on(c,world.watermark,&ids,&catalog).await.map_err(|_|Error::Storage)?;
                let observed=crate::directory::read_generation(c,proof.tenant_id()).await?;
                let context=rss_mdm_query::cursor::fingerprint(&json!({"generation":observed,"kind":"device-inventory-list","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":grants,"watermark":world.watermark,"view":group.reference})).map_err(|_|Error::Storage)?;
                let mut fields=BTreeMap::new();let mut lists=BTreeMap::new();
                for definition in catalog.fields().filter(|d|d.sensitivity!=Sensitivity::Secret) {
                    if matches!(definition.value_type,ValueType::Array{..}) {
                        let sources=raw.iter().flat_map(|e|e.arrays.get(&definition.key).into_iter().flat_map(|f|f.sources.iter().cloned().map(|fact|EndpointArrayFact{endpoint:e.scalars.device.clone(),fact}))).collect();
                        let resolved=rss_mdm_inventory::resolve_device_array(definition,sources).map_err(|_|Error::Storage)?;
                        if let Some((field,token,limit))=list && *field==definition.key {
                            let cursor=service.decode(token)?;
                            if cursor.context["view"]!=context || cursor.context["field"]!=json!(field){return Err(Error::CursorInvalidated);}
                            let selected=cursor.context["source"].as_str().ok_or(Error::Malformed)?;
                            let mut source=None;
                            for candidate in &resolved.sources {if source_key(candidate)?==selected{source=Some(candidate);break;}}
                            let source=source.ok_or(Error::CursorInvalidated)?;
                            let ArrayState::Known(value)=&source.fact.state else { return Err(Error::Conflict); };
                            if cursor.context["version"]!=value.version {return Err(Error::CursorInvalidated);}
                            let page=rss_mdm_inventory_postgres::arrays::page(c,service.tenant,&value.version,cursor.offset,*limit,16*1024*1024).await.map_err(|_|Error::Storage)?;
                            let next=page.next.map(|offset|service.encode(cursor.context,offset)).transpose()?;
                            proof.check_live()?;
                            return Ok((json!({"reference":reference,"field":field,"source":source.fact.evidence,"endpoint":source.endpoint,"total":value.count,"items":page.items,"nextCursor":next}),bindings,sensitive,grants,observed));
                        }
                        let sources=resolved.sources.iter().map(|s| {
                            let version=match &s.fact.state {ArrayState::Known(value)=>Some(&value.version),_=>None};
                            Ok(json!({"endpoint":s.endpoint,"evidence":s.fact.evidence,"state":list_state(&s.fact.state)?,"lastKnown":s.fact.last_known.as_ref().map(|v|json!({"state":{"kind":"known","count":v.value.count,"digest":v.value.digest},"evidence":v.evidence})),"cursor":service.encode(json!({"view":context,"field":definition.key,"source":source_key(s)?,"version":version}),0)?}))
                        }).collect::<Result<Vec<_>>>()?;
                        lists.insert(definition.key,json!({"state":list_state(&resolved.state)?,"sources":sources,"itemKey":definition.item_key}));
                    } else {
                        let sources=raw.iter().flat_map(|e|e.scalars.fields.get(&definition.key).into_iter().flat_map(|f|f.sources.iter().cloned().map(|fact|EndpointSourceFact{endpoint:e.scalars.device.clone(),fact}))).collect();
                        fields.insert(definition.key,rss_mdm_inventory::resolve_device(definition,sources).map_err(|_|Error::Storage)?);
                    }
                }
                if list.is_some(){return Err(Error::NotFound);}
                let provenance=raw.iter().map(|e|json!({"endpoint":e.scalars.device,"quality":e.scalars.quality,"revisions":e.scalars.revisions})).collect::<Vec<_>>();
                let mut value=group.summary();value["fields"]=serde_json::to_value(fields).map_err(|_|Error::Storage)?;value["lists"]=serde_json::to_value(lists).map_err(|_|Error::Storage)?;value["inventorySources"]=json!(provenance);
                proof.check_live()?;Ok((value,bindings,sensitive,grants,observed))
            })).await
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))?;
        if let Some(rows) = value.get_mut("endpoints").and_then(Value::as_array_mut) {
            personnel.current_users(proof, rows, &bindings).await?;
            personnel.project(proof, sensitive, rows.iter_mut()).await?;
        }
        self.confirm_scope(proof, &grants, &observed, &budget)
            .await?;
        Ok(value)
    }
    /// Fence permission changes that occurred while Identity resolved outside the product transaction.
    async fn confirm_scope(
        &self,
        proof: &AuthorizedPrincipal,
        grants: &str,
        observed: &Value,
        budget: &AuditBudget,
    ) -> Result<()> {
        self.audit
            .read(
                self.tenant,
                &budget.control(),
                (proof, grants, observed),
                |(proof, grants, observed), tx| {
                    Box::pin(async move {
                        tx.with_connection_context(
                            &mut (*proof, *grants, *observed),
                            |(proof, grants, observed), c| {
                                Box::pin(async move {
                                    let snapshot = read::authorization(c, proof).await?;
                                    if snapshot.query_binding(proof)? != *grants {
                                        return Err(Error::Forbidden);
                                    }
                                    if crate::directory::read_generation(c, proof.tenant_id())
                                        .await?
                                        != **observed
                                    {
                                        return Err(Error::CursorInvalidated);
                                    }
                                    proof.check_live()?;
                                    Ok(())
                                })
                            },
                        )
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(model::transaction_error(e)),
                |e| Err(model::transaction_error(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(model::transaction_error(e)),
            )
    }
}
fn list_state(state: &ArrayState) -> Result<Value> {
    Ok(match state {
        ArrayState::Known(v) => json!({"kind":"known","count":v.count,"digest":v.digest}),
        s => serde_json::to_value(s).map_err(|_| Error::Storage)?,
    })
}

fn source_key(source: &EndpointArrayFact) -> Result<String> {
    rss_mdm_query::cursor::fingerprint(&(&source.endpoint, &source.fact.evidence))
        .map_err(|_| Error::Storage)
}
