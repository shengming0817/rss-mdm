//! Minimal direct Policy blockers of Scope deletion.
use super::*;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    Page,
    cursor::{CursorCodec, fingerprint},
    window,
};
pub static SCHEMA: window::Schema = window::Schema {
    id: "scope_references",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "id",
    context: &[],
};
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Policy,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    PolicyScope,
    RolloutStage,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Release {
    EditReferencingPolicy,
    RetainedArchivedPolicy,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub kind: Kind,
    pub id: Uuid,
    pub version: Uuid,
    pub revision: i64,
    pub roles: Vec<Role>,
    pub release: Release,
}
impl Scopes {
    pub async fn references(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        q: &window::Query,
    ) -> std::result::Result<Page<Entry>, Error> {
        q.require_schema(&SCHEMA).map_err(query_error)?;
        proof.manage(Permission::ScopeRead)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, id, q),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, id, q) = *ctx;
                    let current = crate::action_admission::current(tx, p).await?;
                    current.require(p, Permission::ScopeRead, None)?;
                    s.store.head_in(tx, id, false).await?;
                    let binding = fingerprint(&(
                        SCHEMA.id,
                        s.tenant.to_string(),
                        p.instance_id(),
                        p.principal_id(),
                        current.query_binding(p)?,
                        id,
                        q.limit(),
                    ))
                    .map_err(query_error)?;
                    let codec = CursorCodec::from_key(s.cursor_key.clone());
                    let after: Option<Uuid> = q
                        .cursor()
                        .as_ref()
                        .map(|token| {
                            let token = rss_contract::PageCursor::parse(token)
                                .map_err(|_| Error::Malformed)?;
                            codec.decode(&token, &binding).map_err(query_error)
                        })
                        .transpose()?;
                    let mut items = s
                        .dependents
                        .references_in(tx, id, after, q.limit() + 1)
                        .await?;
                    let more = items.len() > q.limit();
                    items.truncate(q.limit());
                    let next_cursor = if more {
                        Some(
                            codec
                                .encode(&binding, &items.last().ok_or(Error::Conflict)?.id)
                                .map_err(query_error)?
                                .as_str()
                                .to_owned(),
                        )
                    } else {
                        None
                    };
                    p.check_live()?;
                    Ok(Page { items, next_cursor })
                })
            },
        )
        .await
    }
}
