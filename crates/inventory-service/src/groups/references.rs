//! Authorized dependency pagination over current owner facts, with no durable query cache.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Group,
    Scope,
    Policy,
    ComplianceRule,
}
impl Kind {
    pub fn permission(self) -> Permission {
        match self {
            Self::Group => Permission::GroupRead,
            Self::Scope => Permission::ScopeRead,
            Self::Policy => Permission::PolicyRead,
            Self::ComplianceRule => Permission::ComplianceRuleRead,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    Direct,
    Indirect,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Object {
    pub kind: Kind,
    pub id: Uuid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Current,
    Pending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Active,
    Enabled,
    Disabled,
    Archived,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub source: Object,
    pub revision: i64,
    pub relation: Relation,
    pub roles: Vec<String>,
    pub via: Vec<Object>,
    pub lifecycle_state: Lifecycle,
    pub freshness: Freshness,
    pub effective: bool,
    pub blocks_deletion: bool,
}
impl Entry {
    pub fn key(&self) -> (Kind, Uuid, Relation) {
        (self.source.kind, self.source.id, self.relation)
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub kind: Option<Kind>,
    #[serde(default = "all")]
    pub relation: String,
    #[serde(default = "limit")]
    pub limit: usize,
    pub cursor: Option<String>,
}
fn all() -> String {
    "all".into()
}
fn limit() -> usize {
    64
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant: String,
    root: Uuid,
    kind: Option<Kind>,
    relation: String,
    authority: String,
    view: String,
    instance: String,
    principal: String,
    expires_at: i64,
    after: (Kind, Uuid, Relation),
}
pub struct PageRequest {
    pub kind: Option<Kind>,
    pub relation: String,
    pub allowed: Vec<Kind>,
    pub after: Option<(Kind, Uuid, Relation)>,
    pub limit: usize,
}
pub struct Page {
    pub items: Vec<Entry>,
    pub generation: String,
    pub blocked: bool,
}
impl Groups {
    pub async fn references(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        q: &Query,
        audit: &rss_mdm_audit_integration::RequestAudit,
        flow: &dyn Flow,
    ) -> std::result::Result<Value, Error> {
        if !(1..=1000).contains(&q.limit)
            || !matches!(q.relation.as_str(), "direct" | "indirect" | "all")
        {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        let cursor = if let Some(token) = &q.cursor {
            if token.len() > 4096 {
                return Err(Error::Malformed);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| Error::Malformed)?;
            if bytes.len() <= 32 {
                return Err(Error::Malformed);
            }
            let (body, signature) = bytes.split_at(bytes.len() - 32);
            ring::hmac::verify(&self.cursor_key, body, signature).map_err(|_| Error::Conflict)?;
            Some(serde_json::from_slice::<Cursor>(body).map_err(|_| Error::Conflict)?)
        } else {
            None
        };
        audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Group,
            &id.to_string(),
        );
        crate::transaction::inspect(&self.runtime, self.tenant,(self,proof,q,audit,flow,cursor),|ctx,tx|Box::pin(async move {
            let (s,p,q,_audit,flow,cursor)=ctx;
            let tenant=p.tenant_id().to_owned();let instance=p.instance_id().to_owned();
            let authority=tx.with_connection(move|c|Box::pin(async move {
                rss_mdm_authorization_service::lock_on(c,&tenant,&instance).await.map_err(|_|sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(rss_mdm_authorization_service::snapshot_on(c,&tenant,&instance).await)
            })).await??;
            authority.require(p,Permission::GroupRead,None)?;authority.require_all_devices(p,Permission::InventoryRead)?;
            if let Some(kind)=q.kind {authority.require(p,kind.permission(),None)?;}
            crate::transaction::lock(tx).await?;
            let gid=checked_input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
            group_checked(s.groups.lock_reference_target_in(tx,gid).await?)?;
            let binding=authority.query_binding(p)?;
            let now=s.clock.unix_seconds().ok_or(Error::Unavailable(Failure::Clock))?;
            let after=if let Some(c)=cursor {
                if c.tenant!=s.tenant.to_string()||c.root!=id||c.kind!=q.kind||c.relation!=q.relation||c.authority!=binding||c.instance!=p.instance_id()||c.principal!=p.principal_id()||now>=c.expires_at {return Err(Error::Conflict.into());}
                Some(c.after)
            }else{None};
            let allowed=[Kind::Group,Kind::Scope,Kind::Policy,Kind::ComplianceRule].into_iter().filter(|kind|authority.require(p,kind.permission(),None).is_ok()).collect();
            let page=flow.references(tx,id,PageRequest{kind:q.kind,relation:q.relation.clone(),allowed,after,limit:q.limit+1}).await?;
            if cursor.as_ref().is_some_and(|c|c.view!=page.generation) {return Err(Error::Conflict.into());}
            let blocked=page.blocked;
            let mut visible=page.items;
            let more=visible.len()>q.limit;visible.truncate(q.limit);
            let next=if more {
                let expires_at=cursor.as_ref().map_or(now+60,|c|c.expires_at);
                let mut bytes=checked_input(serde_json::to_vec(&Cursor {tenant:s.tenant.to_string(),root:id,kind:q.kind,relation:q.relation.clone(),authority:binding,view:page.generation,instance:p.instance_id().into(),principal:p.principal_id().into(),expires_at,after:visible.last().ok_or(Error::Conflict)?.key()}))?;
                bytes.extend_from_slice(ring::hmac::sign(&s.cursor_key,&bytes).as_ref());Some(URL_SAFE_NO_PAD.encode(bytes))
            }else{None};
            p.check_live()?;
            Ok(serde_json::json!({"items":visible,"nextCursor":next,"deletionBlocked":blocked}))
        }),TransactionOwner::Assets).await
    }
}
