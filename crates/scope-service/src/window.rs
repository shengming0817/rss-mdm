//! Scope-backed read continuations use authoritative revisions, never a scan of the result set.
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid scope window")]
    Malformed,
    #[error("scope window changed")]
    Conflict,
    #[error(transparent)]
    Source(#[from] crate::channels::SourceError),
}
use rss_mdm_query::cursor::{CursorCodec, fingerprint};
use serde_json::Value;
use uuid::Uuid;

pub async fn binding_on(
    source: &crate::channels::ChannelTargets,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    proof: &AuthorizedPrincipal,
    authority: &str,
    purpose: &str,
    scope: Uuid,
    input: &Value,
) -> Result<String, Error> {
    let coordinate = source
        .query_coordinate_on(c, tenant, scope)
        .await
        .map_err(Error::from)?;
    Ok(binding(
        proof,
        authority,
        purpose,
        scope,
        input,
        &coordinate,
    )?)
}
pub fn binding(
    proof: &AuthorizedPrincipal,
    authority: &str,
    purpose: &str,
    scope: Uuid,
    input: &Value,
    coordinate: &str,
) -> Result<String, Error> {
    fingerprint(&(
        purpose,
        proof.tenant_id(),
        proof.instance_id(),
        proof.principal_id(),
        authority,
        scope,
        input,
        coordinate,
    ))
    .map_err(|_| Error::Malformed)
}
pub fn after(
    codec: &CursorCodec,
    query: &rss_mdm_query::window::Query,
    binding: &str,
) -> Result<Option<String>, Error> {
    query
        .cursor()
        .as_ref()
        .map(|c| {
            codec
                .decode(
                    &rss_contract::PageCursor::parse(c).map_err(|_| Error::Malformed)?,
                    binding,
                )
                .map_err(|_| Error::Conflict)
        })
        .transpose()
}
pub fn next(
    codec: &CursorCodec,
    binding: &str,
    position: Option<String>,
) -> Result<Option<String>, Error> {
    position
        .map(|p| {
            codec
                .encode(binding, &p)
                .map(|c| c.as_str().to_owned())
                .map_err(|_| Error::Malformed)
        })
        .transpose()
}
