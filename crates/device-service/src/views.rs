use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::{
    ArrayState, EndpointArrayFact, EndpointSourceFact, FieldKey, Sensitivity, ValueType,
};
pub use rss_mdm_inventory_service::objects::ObjectRef as ViewRef;
use serde_json::{Value, json};
use sqlx::{Arguments, Row, postgres::PgArguments};
use std::{collections::BTreeMap, time::Duration};

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
    pub(super) fn summary(&self) -> Value {
        json!({"reference":self.reference,"association":self.association,"endpoints":self.endpoints})
    }
}
pub(super) fn scope(snapshot: &Snapshot, proof: &AuthorizedPrincipal) -> Result<(bool, String)> {
    let sensitive = match snapshot.require(proof, Permission::InventorySensitiveRead, None) {
        Ok(()) => true,
        Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => false,
        Err(e) => return Err(e.into()),
    };
    Ok((sensitive, snapshot.query_binding(proof)?))
}
const DETAIL: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people_display AS (SELECT principal_id,active,login,source,status,display_name,username FROM identity_personnel)",
    include_str!("detail.sql"),
    include_str!("snapshot.sql")
);
const REFERENCES: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people_display AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS source,NULL::text AS status,NULL::text AS display_name,NULL::text AS username WHERE false)",
    include_str!("detail.sql"),
    include_str!("snapshot.sql")
);

impl Associations {
    pub async fn views(
        &self,
        proof: &AuthorizedPrincipal,
        query: &rss_mdm_query::directory::Query,
        personnel: &personnel::Reader<'_>,
    ) -> Result<crate::view_response::Directory> {
        self.directory_page(proof, query, personnel).await
    }
    pub async fn view(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        personnel: &personnel::Reader<'_>,
    ) -> Result<crate::view_response::Detail> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        let access = self.directory_access(proof, &budget).await?;
        let mut args = PgArguments::default();
        args.add(proof.tenant_id().to_owned())
            .map_err(|_| Error::Storage)?;
        args.add(access.allowed.clone())
            .map_err(|_| Error::Storage)?;
        args.add(access.sensitive.clone())
            .map_err(|_| Error::Storage)?;
        args.add(access.owners.clone())
            .map_err(|_| Error::Storage)?;
        args.add(serde_json::to_value(reference).map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        args.add(proof.instance_id().to_owned())
            .map_err(|_| Error::Storage)?;
        args.add(personnel.platform_configuration()?)
            .map_err(|_| Error::Storage)?;
        let (identity, rows) = personnel
            .query(
                proof,
                if proof.session().is_ok() {
                    DETAIL
                } else {
                    REFERENCES
                },
                args,
                1,
            )
            .await?;
        let value: Value = rows.first().ok_or(Error::Storage)?.try_get("value")?;
        let read = crate::snapshot::decode(proof, &access.snapshot, identity, &value)?;
        let group = read
            .groups
            .into_iter()
            .find(|g| &g.reference == reference)
            .ok_or(Error::NotFound)?;
        let (sensitive, _) = scope(&access.snapshot, proof)?;
        let mut fields = BTreeMap::new();
        let mut lists = BTreeMap::new();
        for definition in read.catalog.fields().filter(|d| {
            d.sensitivity != Sensitivity::Secret
                && (sensitive || d.sensitivity == Sensitivity::Standard)
        }) {
            if matches!(definition.value_type, ValueType::Array { .. }) {
                let sources = read
                    .assets
                    .iter()
                    .flat_map(|e| {
                        e.arrays.get(&definition.key).into_iter().flat_map(|f| {
                            f.sources.iter().cloned().map(|fact| EndpointArrayFact {
                                endpoint: e.scalars.device.clone(),
                                fact,
                            })
                        })
                    })
                    .collect();
                let resolved = rss_mdm_inventory::resolve_device_array(definition, sources)
                    .map_err(|_| Error::Storage)?;
                let sources=resolved.sources.iter().map(|source| {
                    let cursor=self.array_cursor(proof,&access.binding,&group,definition.key,source)?;
                    Ok(json!({"endpoint":source.endpoint,"evidence":source.fact.evidence,"state":list_state(&source.fact.state)?,"lastKnown":source.fact.last_known.as_ref().map(|v|json!({"state":{"kind":"known","count":v.value.count,"digest":v.value.digest},"evidence":v.evidence})),"cursor":cursor}))
                }).collect::<Result<Vec<_>>>()?;
                lists.insert(definition.key,json!({"state":list_state(&resolved.state)?,"sources":sources,"itemKey":definition.item_key}));
            } else {
                let sources = read
                    .assets
                    .iter()
                    .flat_map(|e| {
                        e.scalars
                            .fields
                            .get(&definition.key)
                            .into_iter()
                            .flat_map(|f| {
                                f.sources.iter().cloned().map(|fact| EndpointSourceFact {
                                    endpoint: e.scalars.device.clone(),
                                    fact,
                                })
                            })
                    })
                    .collect();
                fields.insert(
                    definition.key,
                    rss_mdm_inventory::resolve_device(definition, sources)
                        .map_err(|_| Error::Storage)?,
                );
            }
        }
        let mut provenance = Vec::new();
        for mut entry in read.assets {
            let visible = |key: &FieldKey| {
                read.catalog.definition(*key).is_ok_and(|d| {
                    d.sensitivity != Sensitivity::Secret
                        && (sensitive || d.sensitivity == Sensitivity::Standard)
                })
            };
            entry.scalars.revisions.retain(|key, _| visible(key));
            for quality in &mut entry.scalars.quality {
                quality.fields.retain(|f| visible(&f.field));
            }
            provenance.push(json!({"endpoint":entry.scalars.device,"quality":entry.scalars.quality,"revisions":entry.scalars.revisions}));
        }
        let mut value = group.summary();
        value["fields"] = serde_json::to_value(fields).map_err(|_| Error::Storage)?;
        value["lists"] = serde_json::to_value(lists).map_err(|_| Error::Storage)?;
        value["inventorySources"] = json!(provenance);
        #[cfg(feature = "integration")]
        self.read_checkpoint().await?;
        let subject = personnel.revalidate(proof).await?;
        self.confirm_scope(proof, &access.binding, subject.as_ref(), &budget)
            .await?;
        crate::view_response::decode(value)
    }
    pub(crate) async fn confirm_scope(
        &self,
        proof: &AuthorizedPrincipal,
        grants: &str,
        subject: Option<&rss_identity_postgres::RevalidatedSession>,
        budget: &AuditBudget,
    ) -> Result<()> {
        let current = self.directory_access(proof, budget).await?;
        let binding = match subject {
            Some(facts) => current.snapshot.query_binding_revalidated(proof, facts)?,
            None => current.binding,
        };
        if binding != grants {
            return Err(Error::ReadConflict);
        }
        proof.check_live()?;
        Ok(())
    }
}
fn list_state(state: &ArrayState) -> Result<Value> {
    Ok(match state {
        ArrayState::Known(v) => json!({"kind":"known","count":v.count,"digest":v.digest}),
        s => serde_json::to_value(s).map_err(|_| Error::Storage)?,
    })
}
