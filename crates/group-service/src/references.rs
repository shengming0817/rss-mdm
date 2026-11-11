//! Direct deletion blockers; recursive influence is owned by the separate impacts query.
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
    id: "group_references",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "kind, id",
    purpose: rss_mdm_query::window::Purpose::References,
    reason: "Authorized reference traversal retains owner identity and version coordinates",
    context: &[],
};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Group,
    Scope,
    ComplianceRule,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    GroupCondition,
    Target,
    Limitation,
    Exclusion,
    ComplianceTarget,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Release {
    EditOrDeleteReferencingObject,
    EditPolicyScopeOrRetireOwner,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub kind: Kind,
    pub id: Uuid,
    pub revision: i64,
    pub policy: Option<Uuid>,
    pub stage: Option<Uuid>,
    pub roles: Vec<Role>,
    pub release: Release,
}
type Position = (i32, Uuid);
impl Entry {
    fn position(&self) -> Position {
        (
            match self.kind {
                Kind::Group => 0,
                Kind::Scope => 1,
                Kind::ComplianceRule => 2,
            },
            self.id,
        )
    }
}
fn facts_sql() -> String {
    format!(
        r#"SELECT 0 AS kind,g.id,g.revision,ARRAY['group_condition']::text[] AS roles,NULL::uuid AS policy_id,NULL::uuid AS stage_id
      FROM mdm_group.groups g JOIN mdm_group.rules r ON(r.tenant_id,r.group_id,r.version)=(g.tenant_id,g.id,g.rule_version)
      WHERE g.tenant_id=$1::uuid AND NOT g.deleted AND r.group_ids @> ARRAY[$2::uuid]
      UNION ALL SELECT 1,s.id,s.revision,s.roles,s.policy_id,s.stage_id FROM ({}) s
      UNION ALL SELECT 2,c.id,c.revision,ARRAY['compliance_target']::text[],NULL::uuid,NULL::uuid FROM ({}) c"#,
        rss_mdm_scope_postgres::group_blocker_facts_sql(
            rss_mdm_install_support::StorageProfile::Mdm
        ),
        rss_mdm_compliance_postgres::GROUP_BLOCKER_FACTS_SQL
    )
}

impl Groups {
    pub(crate) async fn references_used_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<bool> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let sql = format!("SELECT EXISTS(SELECT FROM ({}) facts)", facts_sql());
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()))
                        .bind(tenant)
                        .bind(id)
                        .fetch_one(c)
                        .await
                })
            })
            .await?)
    }
    pub async fn references(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        q: &window::Query,
    ) -> std::result::Result<Page<Entry>, Error> {
        q.require_schema(&SCHEMA).map_err(|_| Error::Malformed)?;
        proof.manage(Permission::GroupRead)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        transaction::inspect(&self.runtime,self.tenant,(self,proof,id,q),|ctx,tx|Box::pin(async move {
            let (s,p,id,q)=*ctx;
            let authority=transaction::query_authority(tx,p).await?;
            authority.require(p,Permission::GroupRead,None)?;
            let gid=checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
            group_checked(s.groups.get_in(tx,gid).await?)?.filter(|g|!g.deleted).ok_or(Error::Group(GroupMissing::Group))?;
            let binding=checked_input(fingerprint(&(SCHEMA.id,s.tenant.to_string(),p.instance_id(),p.principal_id(),authority.query_binding(p)?,id,q.limit())))?;
            let codec=CursorCodec::from_key(s.cursor_key.clone());
            let after:Option<Position>=q.cursor().as_ref().map(|token|{
                let token=rss_contract::PageCursor::parse(token).map_err(|_|Error::Malformed)?;
                codec.decode(&token,&binding).map_err(|_|Error::Conflict)
            }).transpose()?;
            let sql=format!("SELECT * FROM ({}) facts WHERE ($3::integer IS NULL OR (kind,id)>($3,$4::uuid)) ORDER BY kind,id LIMIT $5",facts_sql());
            let tenant=s.tenant.to_string(); let limit=q.limit()+1;
            let rows=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(sql.as_str())).bind(tenant).bind(id).bind(after.map(|p|p.0)).bind(after.map(|p|p.1)).bind(limit as i64).fetch_all(c).await
            })).await?;
            let mut items=Vec::new();
            for row in rows {
                let kind=match row.try_get::<i32,_>("kind")? {0=>Kind::Group,1=>Kind::Scope,2=>Kind::ComplianceRule,_=>return Err(Error::Unavailable(Failure::GroupStorage).into())};
                let roles:Vec<String>=row.try_get("roles")?;
                items.push(Entry {kind,id:row.try_get("id")?,revision:row.try_get("revision")?,policy:row.try_get("policy_id")?,stage:row.try_get("stage_id")?,roles:stored(serde_json::from_value(serde_json::json!(roles)))?,release:match kind {Kind::Scope=>Release::EditPolicyScopeOrRetireOwner,_=>Release::EditOrDeleteReferencingObject}});
            }
            let more=items.len()>q.limit(); items.truncate(q.limit());
            let next_cursor=if more {Some(checked_input(codec.encode(&binding,&items.last().ok_or(Error::Conflict)?.position()))?.as_str().to_owned())}else{None};
            p.check_live()?;
            Ok(Page {items,next_cursor})
        })).await
    }
}
