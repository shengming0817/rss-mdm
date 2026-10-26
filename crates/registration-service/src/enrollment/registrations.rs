//! Device registration directory: current authorization and complete SQL candidates precede paging.
use crate::{Error, Store, database::db};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::Value;

pub static SCHEMA: Schema = Schema {
    id: "device_registrations",
    keys: &["registrationId"],
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    fields: &[
        Field::scalar("registrationId", Kind::Uuid),
        Field::scalar("source", Kind::Text),
        Field::scalar("generation", Kind::Integer),
        Field::scalar("status", Kind::Text),
        Field::output("userContextId"),
        Field::output("enrollmentId"),
        Field::output("agentGrantId"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "registrationId" => "r.id::text COLLATE \"C\"",
        "source" => "coalesce(q.source,'agent.builtin') COLLATE \"C\"",
        "generation" => "r.generation",
        "status" => "r.state COLLATE \"C\"",
        _ => unreachable!("checked registration field"),
    }
}
fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
pub async fn list(
    database: &Store,
    proof: &AuthorizedPrincipal,
    device: &str,
    query: &Query,
    codec: &CursorCodec,
) -> Result<Page<Value>, Error> {
    query.require_schema(&SCHEMA).map_err(error)?;
    rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
    proof.credentials(device)?;
    let mut tx = database.begin(proof.tenant_id()).await?;
    rss_mdm_authorization_service::lock_on(&mut tx, proof.tenant_id(), proof.instance_id()).await?;
    let current =
        rss_mdm_authorization_service::snapshot_on(&mut tx, proof.tenant_id(), proof.instance_id())
            .await?;
    current
        .require(proof, Permission::Credentials, Some(device))
        .map_err(rss_mdm_authorization_service::Error::from)?;
    let before = crate::device_access::directory::context(&mut tx, proof).await?;
    let binding = query
        .binding(&(
            proof.tenant_id(),
            proof.instance_id(),
            proof.principal_id(),
            device,
            &before,
        ))
        .map_err(error)?;
    let after = query.after(codec, &binding).map_err(error)?;
    let mut sql = sqlx::QueryBuilder::new(
        "SELECT jsonb_build_object('registrationId',r.id,'userContextId',CASE WHEN q.windows_profile='Full' THEN r.id END,'enrollmentId',r.request_id,'agentGrantId',r.agent_grant_id,'source',coalesce(q.source,'agent.builtin'),'generation',r.generation,'status',r.state) FROM mdm_access.registrations r LEFT JOIN mdm_access.requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=",
    );
    sql.push_bind(proof.tenant_id().to_owned())
        .push("::uuid AND r.device=")
        .push_bind(device.to_owned());
    rss_mdm_query_postgres::append(&mut sql, query, after.as_ref(), column).map_err(error)?;
    let rows = sql
        .build_query_scalar::<Value>()
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
    if before != crate::device_access::directory::context(&mut tx, proof).await? {
        return Err(Error::Conflict);
    }
    proof.check_live()?;
    let page = query.page(rows, codec, &binding).map_err(error)?;
    tx.rollback().await.map_err(db)?;
    Ok(page)
}
