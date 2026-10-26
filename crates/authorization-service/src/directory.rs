//! Management reads use the existing authority transaction and product SQL query adapter.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0
use crate::{Error, Permission, context::AuthorizedPrincipal, database::db};
use rss_mdm_audit_integration::{AuditStore, budget::AuditBudget};
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::Value;
use uuid::Uuid;

pub static RULES: Schema = Schema {
    id: "authorization_rules",
    keys: &["id"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar("subjectKind", Kind::Text),
        Field::output("value"),
    ],
};
pub static GROUPS: Schema = Schema {
    id: "user_groups",
    keys: &["id"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar("name", Kind::Text),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("memberCount", Kind::Integer),
        Field::output("value"),
    ],
};
pub static MEMBERS: Schema = Schema {
    id: "user_group_members",
    keys: &["principalId"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("principalId", Kind::Uuid),
        Field::output("tenantId"),
        Field::output("instanceId"),
    ],
};
pub static KEYS: Schema = Schema {
    id: "api_keys",
    keys: &["id"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("name", Kind::Text),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("revoked", Kind::Boolean),
        Field::scalar("createdAt", Kind::Integer),
        Field::scalar("expiresAt", Kind::Integer),
        Field::output("metadata"),
        Field::output("createdBy"),
        Field::output("authorityRevision"),
        Field::output("credentialRevision"),
    ],
};
#[derive(Clone, Copy)]
pub enum Directory {
    Rules,
    Groups,
    Members(Uuid),
    Keys,
}
impl Directory {
    pub fn schema(self) -> &'static Schema {
        match self {
            Self::Rules => &RULES,
            Self::Groups => &GROUPS,
            Self::Members(_) => &MEMBERS,
            Self::Keys => &KEYS,
        }
    }
    fn permission(self) -> Permission {
        match self {
            Self::Rules | Self::Keys => Permission::AuthorizationRead,
            _ => Permission::UserGroupRead,
        }
    }
}
fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
fn column(name: &str) -> &'static str {
    match name {
        "id" => "(row->>'id') COLLATE \"C\"",
        "principalId" => "(row->>'principalId') COLLATE \"C\"",
        "revision" => "(row->>'revision')::bigint",
        "memberCount" => "(row->>'memberCount')::bigint",
        "createdAt" => "(row->>'createdAt')::bigint",
        "expiresAt" => "(row->>'expiresAt')::bigint",
        "deleted" => "(row->>'deleted')::boolean",
        "enabled" => "(row->>'enabled')::boolean",
        "revoked" => "(row->>'revoked')::boolean",
        "name" => "(row->>'name') COLLATE \"C\"",
        "subjectKind" => "(row->>'subjectKind') COLLATE \"C\"",
        _ => unreachable!("validated authorization field"),
    }
}
pub async fn list(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    codec: &CursorCodec,
    kind: Directory,
    q: &Query,
) -> Result<Option<DirectoryPage>, Error> {
    q.require_schema(kind.schema()).map_err(error)?;
    if matches!(kind, Directory::Keys) {
        p.user()?;
    }
    let tenant =
        rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Malformed)?;
    let budget = AuditBudget::new(std::time::Duration::from_secs(3));
    store.read(tenant,&budget.control(),(p,codec,kind,q),|ctx,tx|Box::pin(async move {
        tx.with_connection_context(ctx,|(p,codec,kind,q),c|Box::pin(async move {
            crate::lock_on(c,p.tenant_id(),p.instance_id()).await?;
            let current=crate::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
            current.require(p,kind.permission(),None)?;
            let group=match kind {Directory::Members(id)=>match current.groups.iter().find(|r|r.id==*id && r.value.is_some()) { Some(g)=>Some(g), None=>return Ok(None) },_=>None};
            let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?,group.map(|g|(g.id,g.revision)))).map_err(error)?;
            let after=q.after(codec,&binding).map_err(error)?;
            let (projection,table)=match kind {
                Directory::Rules=>("jsonb_build_object('id',id,'revision',revision,'deleted',document IS NULL,'subjectKind',document->'subject'->>'kind','value',document)","mdm_access.authorization_rules"),
                Directory::Groups=>("jsonb_build_object('id',id,'revision',revision,'deleted',document IS NULL,'name',document->'name','enabled',document->'enabled','memberCount',jsonb_array_length(document->'members'),'value',CASE WHEN document IS NULL THEN NULL ELSE jsonb_build_object('name',document->'name','enabled',document->'enabled','memberCount',jsonb_array_length(document->'members')) END)","mdm_access.user_groups"),
                Directory::Members(_)=>("member","mdm_access.user_groups CROSS JOIN LATERAL jsonb_array_elements(document->'members') member"),
                Directory::Keys=>("jsonb_build_object('id',id,'revision',revision,'authorityRevision',authority_revision,'credentialRevision',credential_revision,'name',metadata->'name','enabled',enabled,'expiresAt',expires_at,'metadata',metadata,'createdBy',created_by,'createdAt',created_at,'revoked',revoked)","mdm_access.api_keys")
            };
            let mut sql=sqlx::QueryBuilder::new(format!("SELECT row FROM (SELECT {projection} AS row FROM {table} WHERE tenant_id="));
            sql.push_bind(p.tenant_id().to_owned()).push("::uuid AND instance=").push_bind(p.instance_id().to_owned()).push("::uuid");
            if let Directory::Members(id)=kind {sql.push(" AND id=").push_bind(*id);}
            sql.push(") records WHERE true");
            rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(error)?;
            let rows:Vec<Value>=sql.build_query_scalar().fetch_all(c).await.map_err(db)?;
            p.check_live()?;
            fn typed<T:serde::de::DeserializeOwned>(rows:Vec<Value>)->Result<Vec<T>,Error> {rows.into_iter().map(serde_json::from_value).collect::<Result<_,_>>().map_err(|_|Error::Corrupt)}
            let page=match kind {
                Directory::Rules=>DirectoryPage::Rules(q.page_typed(typed::<RuleRow>(rows)?,codec,&binding).map_err(error)?),
                Directory::Groups=>DirectoryPage::Groups(q.page_typed(typed::<GroupRow>(rows)?,codec,&binding).map_err(error)?),
                Directory::Keys=>DirectoryPage::Keys(q.page_typed(typed::<KeyRow>(rows)?,codec,&binding).map_err(error)?),
                Directory::Members(_)=>{
                    let g=group.ok_or(Error::Corrupt)?;
                    let page=q.page_typed(typed::<crate::User>(rows)?,codec,&binding).map_err(error)?;
                    DirectoryPage::Members(GroupMembers {id:g.id,revision:g.revision,items:page.items,next_cursor:page.next_cursor})
                },
            };
            Ok(Some(page))
        })).await
    })).await.fold(Ok,|e|Err(crate::operations::transaction_error(e)),|e|Err(crate::operations::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(crate::operations::transaction_error(e)))
}
pub async fn detail(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    group: bool,
    id: Uuid,
) -> Result<Option<Detail>, Error> {
    let tenant =
        rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Malformed)?;
    let budget = AuditBudget::new(std::time::Duration::from_secs(3));
    store
        .read(tenant, &budget.control(), (p, group, id), |ctx, tx| {
            Box::pin(async move {
                tx.with_connection_context(ctx, |(p, group, id), c| {
                    Box::pin(async move {
                        crate::lock_on(c, p.tenant_id(), p.instance_id()).await?;
                        let current = crate::snapshot_on(c, p.tenant_id(), p.instance_id()).await?;
                        current.require(
                            p,
                            if *group {
                                Permission::UserGroupRead
                            } else {
                                Permission::AuthorizationRead
                            },
                            None,
                        )?;
                        let value = if *group {
                            current
                                .groups
                                .iter()
                                .find(|r| r.id == *id)
                                .cloned()
                                .map(Detail::Group)
                        } else {
                            current
                                .rules
                                .iter()
                                .find(|r| r.id == *id)
                                .cloned()
                                .map(Detail::Rule)
                        };
                        p.check_live()?;
                        Ok(value)
                    })
                })
                .await
            })
        })
        .await
        .fold(
            Ok,
            |e| Err(crate::operations::transaction_error(e)),
            |e| Err(crate::operations::transaction_error(e)),
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |e| Err(crate::operations::transaction_error(e)),
        )
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleRow {
    pub id: Uuid,
    pub revision: u64,
    pub deleted: bool,
    pub subject_kind: Option<String>,
    pub value: Option<crate::Rule>,
}
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub name: String,
    pub enabled: bool,
    pub member_count: u64,
}
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupRow {
    pub id: Uuid,
    pub revision: u64,
    pub deleted: bool,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub member_count: Option<u64>,
    pub value: Option<GroupSummary>,
}
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KeyRow {
    #[serde(flatten)]
    pub record: crate::api_key::KeyRecord,
    pub name: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembers {
    pub id: Uuid,
    pub revision: u64,
    pub items: Vec<rss_mdm_query::directory::Projection<crate::User>>,
    pub next_cursor: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum DirectoryPage {
    Rules(rss_mdm_query::Page<rss_mdm_query::directory::Projection<RuleRow>>),
    Groups(rss_mdm_query::Page<rss_mdm_query::directory::Projection<GroupRow>>),
    Keys(rss_mdm_query::Page<rss_mdm_query::directory::Projection<KeyRow>>),
    Members(GroupMembers),
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Detail {
    Rule(crate::Revision<crate::Rule>),
    Group(crate::Revision<crate::UserGroup>),
}
impl DirectoryPage {
    pub fn rules(
        self,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<RuleRow>>, Error> {
        match self {
            Self::Rules(value) => Ok(value),
            _ => Err(Error::Corrupt),
        }
    }
}
impl DirectoryPage {
    pub fn groups(
        self,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<GroupRow>>, Error> {
        match self {
            Self::Groups(value) => Ok(value),
            _ => Err(Error::Corrupt),
        }
    }
}
impl DirectoryPage {
    pub fn keys(
        self,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<KeyRow>>, Error> {
        match self {
            Self::Keys(value) => Ok(value),
            _ => Err(Error::Corrupt),
        }
    }
}
impl DirectoryPage {
    pub fn members(self) -> Result<GroupMembers, Error> {
        match self {
            Self::Members(value) => Ok(value),
            _ => Err(Error::Corrupt),
        }
    }
}
impl Detail {
    pub fn rule(self) -> Result<crate::Revision<crate::Rule>, Error> {
        match self {
            Self::Rule(value) => Ok(value),
            _ => Err(Error::Corrupt),
        }
    }
}
impl Detail {
    pub fn group(self) -> Result<crate::Revision<crate::UserGroup>, Error> {
        match self {
            Self::Group(value) => Ok(value),
            _ => Err(Error::Corrupt),
        }
    }
}
