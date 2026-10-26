//! Scope-backed read continuations use authoritative revisions, never a scan of the result set.
use crate::{Error, authorization::context::AuthorizedPrincipal};
use rss_mdm_query::cursor::{CursorCodec, fingerprint};
use serde_json::Value;
use uuid::Uuid;

pub async fn binding_on(
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    authority: &str,
    purpose: &str,
    scope: Uuid,
    input: &Value,
) -> Result<String, Error> {
    let stamp: Value = sqlx::query_scalar("SELECT jsonb_build_array(s.revision,s.resolution,coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=s.tenant_id),0),coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=s.tenant_id),0),coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=s.tenant_id),0)) FROM mdm_planning.scopes s WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted")
        .bind(proof.tenant_id()).bind(scope).fetch_optional(c).await.map_err(|_|Error::Unavailable(crate::Failure::CommandStorage))?.ok_or(Error::NotFound)?;
    fingerprint(&(
        purpose,
        proof.tenant_id(),
        proof.instance_id(),
        proof.principal_id(),
        authority,
        scope,
        input,
        stamp,
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
