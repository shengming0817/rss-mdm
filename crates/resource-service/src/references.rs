//! Minimal archive blockers. Reading this page never grants archive permission.
use super::*;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{Page, cursor::fingerprint, window};

/// Fixed, bounded order over the exact target's live blocker facts.
pub static SCHEMA: window::Schema = window::Schema {
    id: "resource_references",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "kind, id, version",
    purpose: rss_mdm_query::window::Purpose::References,
    reason: "Authorized reference traversal retains owner identity and version coordinates",
    context: &[],
};
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    PolicyVersion,
    SoftwarePublication,
    SoftwareCatalog,
    CollectionProfile,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    PolicyAction,
    PublicationSubject,
    CatalogVersion,
    CollectionTemplate,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    CurrentVersion,
    HistoricalVersion,
    RetainedRecord,
    UnarchivedVersion,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Release {
    RetainedImmutable,
    ArchiveReferencingVersion,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub kind: Kind,
    pub id: String,
    pub version: Option<String>,
    pub role: Role,
    pub retention: Retention,
    /// Supported lifecycle, not an authorization or a promise of success.
    pub release: Release,
}
pub type Position = (Kind, String, String);
impl Entry {
    pub fn position(&self) -> Position {
        (
            self.kind,
            self.id.clone(),
            self.version.clone().unwrap_or_default(),
        )
    }
}
impl ResourceCatalog {
    pub async fn references(
        &self,
        proof: &AuthorizedPrincipal,
        resource: &str,
        version: &str,
        q: &window::Query,
    ) -> std::result::Result<Page<Entry>, Error> {
        q.require_schema(&SCHEMA).map_err(query_error)?;
        proof.manage(Permission::ResourceRead)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let rid = id(resource).map_err(|_| Error::Malformed)?;
        let vid = id(version).map_err(|_| Error::Malformed)?;
        transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, resource, version, q, rid, vid),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, resource, version, q, rid, vid) = ctx;
                    let authority = transaction::current(tx, p).await?;
                    authority.require(p, Permission::ResourceRead, None)?;
                    let stored = checked(s.resources.get_in(tx, rid).await?)?
                        .ok_or(Error::Resource(error::ResourceError::Missing))?;
                    stored
                        .resource
                        .version(vid)
                        .map_err(|_| Error::Resource(error::ResourceError::Missing))?;
                    let binding = fingerprint(&(
                        SCHEMA.id,
                        s.tenant.to_string(),
                        p.instance_id(),
                        p.principal_id(),
                        authority.query_binding(p)?,
                        *resource,
                        *version,
                        q.limit(),
                    ))
                    .map_err(query_error)?;
                    let after: Option<Position> = q
                        .cursor()
                        .as_ref()
                        .map(|token| {
                            let token = rss_contract::PageCursor::parse(token)
                                .map_err(|_| Error::Malformed)?;
                            s.directory_cursor
                                .decode(&token, &binding)
                                .map_err(query_error)
                        })
                        .transpose()?;
                    let mut items = s
                        .references
                        .page_in(tx, resource, version, after.as_ref(), q.limit() + 1)
                        .await?;
                    let more = items.len() > q.limit();
                    items.truncate(q.limit());
                    let next_cursor = if more {
                        Some(
                            s.directory_cursor
                                .encode(&binding, &items.last().ok_or(Error::Conflict)?.position())
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
fn query_error(error: rss_mdm_query::Error) -> Error {
    match error {
        rss_mdm_query::Error::CursorInvalidated => Error::ResourceCursorInvalidated,
        _ => Error::Malformed,
    }
}
