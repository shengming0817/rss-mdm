//! Complete direct field blockers. Target management grants reveal identities, never documents.
use super::*;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    Page,
    cursor::{CursorCodec, fingerprint},
    window,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
pub static SCHEMA: window::Schema = window::Schema {
    id: "field_references",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "kind, id, version, instance, owner",
    purpose: rss_mdm_query::window::Purpose::References,
    reason: "Authorized reference traversal retains owner identity and version coordinates",
    context: &[],
};
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Source {
    Group {
        id: Uuid,
        revision: i64,
    },
    ResourceVersion {
        id: String,
        version: String,
    },
    ComplianceRule {
        id: Uuid,
        revision: i64,
    },
    SavedQuery {
        instance: Uuid,
        owner: Uuid,
        id: Uuid,
        revision: i64,
    },
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    GroupCondition,
    CollectionMapping,
    TelemetryMapping,
    ComplianceCondition,
    SavedQuery,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Release {
    EditOrDeleteReferencingObject,
    ArchiveReferencingVersion,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub source: Source,
    pub role: Role,
    pub release: Release,
}
type Position = (i32, String, String, String, String);
impl Entry {
    fn position(&self) -> Position {
        match &self.source {
            Source::Group { id, .. } => (
                0,
                id.to_string(),
                String::new(),
                String::new(),
                String::new(),
            ),
            Source::ResourceVersion { id, version } => {
                (1, id.clone(), version.clone(), String::new(), String::new())
            }
            Source::ComplianceRule { id, .. } => (
                2,
                id.to_string(),
                String::new(),
                String::new(),
                String::new(),
            ),
            Source::SavedQuery {
                instance,
                owner,
                id,
                ..
            } => (
                3,
                id.to_string(),
                String::new(),
                instance.to_string(),
                owner.to_string(),
            ),
        }
    }
}
// These current rows are already the field owner's retirement inputs. Resource and
// Compliance continue to supply their own facts; no second relationship store is introduced.
fn local_facts() -> String {
    format!(
        r#"SELECT 0 AS kind,g.group_id::text AS id,''::text AS version,''::text AS instance,''::text AS owner,
        jsonb_build_object('kind','group','id',g.group_id,'revision',h.revision) AS source,'group_condition'::text AS role
        FROM mdm_assets.group_fields g JOIN mdm_group.groups h ON(h.tenant_id,h.id)=(g.tenant_id,g.group_id)
        WHERE g.tenant_id=$1::uuid AND g.field=$2
        UNION ALL SELECT 2,c.id::text,'','','',jsonb_build_object('kind','compliance_rule','id',c.id,'revision',c.revision),'compliance_condition'
        FROM ({}) c
        UNION ALL SELECT 3,id::text,'',instance::text,owner::text,jsonb_build_object('kind','saved_query','instance',instance,'owner',owner,'id',id,'revision',revision),'saved_query'
        FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND document IS NOT NULL AND
        (jsonb_path_exists(document,'$.query.**.field ? (@ == $field || @ starts with $prefix)',jsonb_build_object('field',$2::text,'prefix',$2::text||'.'))
         OR jsonb_path_exists(document,'$.query.fields[*] ? (@ == $field)',jsonb_build_object('field',$2::text)))"#,
        rss_mdm_compliance_postgres::FIELD_REFERENCE_FACTS_SQL
    )
}
impl AssetService {
    pub(super) async fn field_used_in(
        &self,
        tx: &mut PgTransaction<'_>,
        field: FieldKey,
    ) -> Result<bool> {
        let resource =
            rss_mdm_resource_postgres::FieldReferences::bind(self.runtime.clone(), self.tenant);
        if resource.used_in(tx, field.as_str()).await? {
            return Ok(true);
        }
        let sql = format!("SELECT EXISTS(SELECT FROM ({}) facts)", local_facts());
        let tenant = self.tenant.to_string();
        let field = field.as_str().to_owned();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()))
                        .bind(tenant)
                        .bind(field)
                        .fetch_one(c)
                        .await
                })
            })
            .await?)
    }
    pub async fn field_references(
        &self,
        proof: &AuthorizedPrincipal,
        field: FieldKey,
        q: &window::Query,
    ) -> std::result::Result<Page<Entry>, Error> {
        q.require_schema(&SCHEMA).map_err(crate::query_error)?;
        proof.manage(Permission::InventoryFieldsWrite)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        crate::transaction::inspect(&self.runtime,self.tenant,(self,proof,field,q),|ctx,tx|Box::pin(async move{
            let(s,p,field,q)=*ctx;let current=query_authority(tx,p).await?;
            current.require(p,Permission::InventoryFieldsWrite,None)?;
            catalog_in(tx,s.tenant).await?.definition(field).map_err(|_|Error::NotFound)?;
            let binding=fingerprint(&(SCHEMA.id,s.tenant.to_string(),p.instance_id(),p.principal_id(),current.query_binding(p)?,field,q.limit())).map_err(crate::query_error)?;
            let codec=CursorCodec::from_key(s.asset_cursor_key.clone());
            let after:Option<Position>=q.cursor().as_ref().map(|token|{
                let token=rss_contract::PageCursor::parse(token).map_err(|_|Error::Malformed)?;
                codec.decode(&token,&binding).map_err(crate::query_error)
            }).transpose()?;
            let sql=format!(r#"SELECT source,role FROM ({}) facts WHERE ($3::integer IS NULL OR
              (kind,id COLLATE "C",version COLLATE "C",instance COLLATE "C",owner COLLATE "C")>($3,$4,$5,$6,$7))
              ORDER BY kind,id COLLATE "C",version COLLATE "C",instance COLLATE "C",owner COLLATE "C" LIMIT $8"#,local_facts());
            let tenant=s.tenant.to_string();let key=field.as_str().to_owned();let position=after.clone();let limit=q.limit()+1;
            let rows=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query(sqlx::AssertSqlSafe(sql.as_str())).bind(tenant).bind(key)
                  .bind(position.as_ref().map(|p|p.0)).bind(position.as_ref().map(|p|&p.1))
                  .bind(position.as_ref().map(|p|&p.2)).bind(position.as_ref().map(|p|&p.3)).bind(position.as_ref().map(|p|&p.4))
                  .bind(limit as i64).fetch_all(c).await
            })).await?;
            let mut items=Vec::new();
            for row in rows {
                items.push(Entry{source:stored(serde_json::from_value(row.try_get("source")?))?,
                    role:stored(serde_json::from_value(Value::String(row.try_get("role")?)))?,release:Release::EditOrDeleteReferencingObject});
            }
            if after.as_ref().is_none_or(|p|p.0<=1) {
                let key=after.as_ref().filter(|p|p.0==1).map(|p|(p.1.clone(),p.2.clone()));
                for row in rss_mdm_resource_postgres::FieldReferences::bind(s.runtime.clone(),s.tenant).blockers_in(tx,field.as_str(),key,limit as u16).await? {
                    if row.state==rss_mdm_resource::State::Archived {return Err(Error::Unavailable(Failure::AssetsStorage).into());}
                    items.push(Entry{source:Source::ResourceVersion{id:row.resource,version:row.version},
                        role:if row.telemetry{Role::TelemetryMapping}else{Role::CollectionMapping},release:Release::ArchiveReferencingVersion});
                }
            }
            items.sort_by_key(Entry::position);
            let more=items.len()>q.limit();items.truncate(q.limit());
            let next_cursor=if more{Some(codec.encode(&binding,&items.last().ok_or(Error::Conflict)?.position()).map_err(crate::query_error)?.as_str().to_owned())}else{None};
            p.check_live()?;Ok(Page{items,next_cursor})
        }),crate::transaction::TransactionOwner::Assets).await
    }
}
