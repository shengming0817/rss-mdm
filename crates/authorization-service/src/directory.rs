//! Management reads use the existing authority transaction and product SQL query adapter.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0
use crate::{Error, Permission, context::AuthorizedPrincipal, database::db};
use rss_mdm_audit_integration::{AuditStore, budget::AuditBudget};
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::{Value, json};
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
) -> Result<Option<Value>, Error> {
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
            let page=q.page(rows,codec,&binding).map_err(error)?;
            Ok(Some(match group {Some(g)=>json!({"id":g.id,"revision":g.revision,"items":page.items,"nextCursor":page.next_cursor}),None=>serde_json::to_value(page).map_err(|_|Error::Corrupt)?}))
        })).await
    })).await.fold(Ok,|e|Err(crate::operations::transaction_error(e)),|e|Err(crate::operations::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(crate::operations::transaction_error(e)))
}
pub async fn detail(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    group: bool,
    id: Uuid,
) -> Result<Option<Value>, Error> {
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
                                .map(serde_json::to_value)
                        } else {
                            current
                                .rules
                                .iter()
                                .find(|r| r.id == *id)
                                .map(serde_json::to_value)
                        }
                        .transpose()
                        .map_err(|_| Error::Corrupt)?;
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
