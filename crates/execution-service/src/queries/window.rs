//! Scope-backed read continuations use authoritative revisions, never a scan of the result set.
use crate::{Error, authorization::context::AuthorizedPrincipal};
use rss_mdm_query::cursor::{CursorCodec, fingerprint};
use serde_json::Value;
use uuid::Uuid;

pub async fn binding_on(
    service: &super::Queries,
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    authority: &str,
    purpose: &str,
    scope: Uuid,
    input: &Value,
) -> crate::transaction::Result<String> {
    let coordinate = service
        .source
        .query_coordinate_on(c, service.tenant, scope)
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
