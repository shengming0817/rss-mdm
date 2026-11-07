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

pub static RULES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema {
    id: "authorization_rules",
    keys: &["id"],
    default_limit: 100,
    max_limit: 1000,
    fields: vec![
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar("subjectKind", Kind::Text),
        Field::output("value"),
    ],
});
pub static GROUPS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<GroupRow>("user_groups", &["id"], 100, 1000, &[])
        .expect("User group model is fully described")
});
pub static MEMBERS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::User>("user_group_members", &["principalId"], 100, 1000, &[])
        .expect("User group member model is fully described")
});
pub static KEYS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<KeyRow>(
        "api_keys",
        &["id"],
        100,
        1000,
        &[rss_mdm_query::directory::Exclusion {
            path: "metadata.grants",
            reason: "Grant object arrays require operation and scope to match the same grant",
        }],
    )
    .expect("API key public model is fully described")
});
static GROUP_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(
            &GROUPS,
            &[
                Source::column("id", "(row->>'id') COLLATE \"C\""),
                Source::column("revision", "(row->>'revision')::bigint"),
                Source::column("deleted", "(row->>'deleted')::boolean"),
                Source::column("name", "(row->>'name') COLLATE \"C\""),
                Source::column("enabled", "(row->>'enabled')::boolean"),
                Source::column("memberCount", "(row->>'memberCount')::bigint"),
                Source::column("value.name", "(row->'value'->>'name') COLLATE \"C\""),
                Source::column("value.enabled", "(row->'value'->>'enabled')::boolean"),
                Source::column(
                    "value.memberCount",
                    "(row->'value'->>'memberCount')::bigint",
                ),
            ],
        )
        .expect("Every synthesized group summary field has a storage expression")
    });
static MEMBER_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &MEMBERS,
            &[rss_mdm_query_postgres::Source::json("", "row")],
        )
        .expect("Stored User member owns the complete JSON root")
    });
static KEY_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(
            &KEYS,
            &[
                Source::column("id", "(row->>'id') COLLATE \"C\""),
                Source::column("revision", "(row->>'revision')::bigint"),
                Source::column("authorityRevision", "(row->>'authorityRevision')::bigint"),
                Source::column("credentialRevision", "(row->>'credentialRevision')::bigint"),
                Source::column("name", "(row->>'name') COLLATE \"C\""),
                Source::column("enabled", "(row->>'enabled')::boolean"),
                Source::column("expiresAt", "(row->>'expiresAt')::bigint"),
                Source::column("createdAt", "(row->>'createdAt')::bigint"),
                Source::column("revoked", "(row->>'revoked')::boolean"),
                Source::json("metadata", "row->'metadata'"),
                Source::json("createdBy", "row->'createdBy'"),
            ],
        )
        .expect("Every synthesized API key field has a storage expression")
    });
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
            Self::Groups => GROUP_BINDINGS.schema(),
            Self::Members(_) => MEMBER_BINDINGS.schema(),
            Self::Keys => KEY_BINDINGS.schema(),
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
            crate::lock_on(p.authority_profile(), c,p.tenant_id(),p.instance_id()).await?;
            let current=crate::snapshot_on(p.authority_profile(), c,p.tenant_id(),p.instance_id()).await?;
            current.require(p,kind.permission(),None)?;
            let group=match kind {Directory::Members(id)=>match current.groups.iter().find(|r|r.id==*id && r.value.is_some()) { Some(g)=>Some(g), None=>return Ok(None) },_=>None};
            let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?,group.map(|g|(g.id,g.revision)))).map_err(error)?;
            let after=q.after(codec,&binding).map_err(error)?;
            let (projection,table)=match kind {
                Directory::Rules=>("jsonb_build_object('id',id,'revision',revision,'deleted',document IS NULL,'subjectKind',document->'subject'->>'kind','value',document)",crate::storage_profile::sql(p.authority_profile()).directory_list_1),
                Directory::Groups=>("jsonb_build_object('id',id,'revision',revision,'deleted',document IS NULL,'name',document->'name','enabled',document->'enabled','memberCount',jsonb_array_length(document->'members'),'value',CASE WHEN document IS NULL THEN NULL ELSE jsonb_build_object('name',document->'name','enabled',document->'enabled','memberCount',jsonb_array_length(document->'members')) END)",crate::storage_profile::sql(p.authority_profile()).directory_list_2),
                Directory::Members(_)=>("member",crate::storage_profile::sql(p.authority_profile()).directory_list_3),
                Directory::Keys=>("jsonb_build_object('id',id,'revision',revision,'authorityRevision',authority_revision,'credentialRevision',credential_revision,'name',metadata->'name','enabled',enabled,'expiresAt',expires_at,'metadata',metadata,'createdBy',created_by,'createdAt',created_at,'revoked',revoked)",crate::storage_profile::sql(p.authority_profile()).directory_list_4)
            };
            let mut sql=sqlx::QueryBuilder::new(format!("SELECT row FROM (SELECT {projection} AS row FROM {table} WHERE tenant_id="));
            sql.push_bind(p.tenant_id().to_owned()).push("::uuid AND instance=").push_bind(p.instance_id().to_owned()).push("::uuid");
            if let Directory::Members(id)=kind {sql.push(" AND id=").push_bind(*id);}
            sql.push(") records WHERE true");
            match kind {
                Directory::Rules => rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column),
                Directory::Groups => rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*GROUP_BINDINGS),
                Directory::Members(_) => rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*MEMBER_BINDINGS),
                Directory::Keys => rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*KEY_BINDINGS),
            }.map_err(error)?;
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
                        crate::lock_on(p.authority_profile(), c, p.tenant_id(), p.instance_id())
                            .await?;
                        let current = crate::snapshot_on(
                            p.authority_profile(),
                            c,
                            p.tenant_id(),
                            p.instance_id(),
                        )
                        .await?;
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
