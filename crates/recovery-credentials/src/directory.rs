//! Recovery metadata only; sealed bytes and keys never enter a directory projection.
use crate::Error;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::Value;
use sqlx::PgConnection;
pub static SCHEMA: Schema = Schema {
    id: "recovery_credentials",
    keys: &["id", "version"],
    default_limit: 64,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("version", Kind::Integer),
        Field::scalar("current", Kind::Boolean),
        Field::scalar(
            "validity",
            Kind::Enum(&["unverified", "verified", "revoked", "unknown", "superseded"]),
        ),
        Field::scalar("escrowed", Kind::Boolean),
        Field::scalar("operation", Kind::Uuid),
        Field::scalar("createdAt", Kind::Integer),
        Field::scalar("invalidatedAt", Kind::Integer),
        Field::output("binding"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "e.id::text COLLATE \"C\"",
        "version" => "v.version",
        "current" => "coalesce(e.current_version=v.version,false)",
        "validity" => "v.validity COLLATE \"C\"",
        "escrowed" => "(v.sealed IS NOT NULL)",
        "operation" => "v.operation::text COLLATE \"C\"",
        "createdAt" => "v.created_at",
        "invalidatedAt" => "v.invalidated_at",
        _ => unreachable!("checked recovery field"),
    }
}
pub(crate) fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
async fn context(c: &mut PgConnection, p: &AuthorizedPrincipal) -> Result<(String, i64), Error> {
    let authority = rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await?
        .query_binding(p)?;
    let revision=sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm_access.directory_revisions WHERE tenant_id=$1::uuid),0)").bind(p.tenant_id()).fetch_one(c).await?;
    Ok((authority, revision))
}
pub(crate) async fn read(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
    q: &Query,
    codec: &CursorCodec,
) -> Result<Page<rss_mdm_query::directory::Projection<crate::Material>>, Error> {
    q.require_schema(&SCHEMA).map_err(error)?;
    let before = context(c, p).await?;
    let binding = q
        .binding(&(
            p.tenant_id(),
            p.instance_id(),
            p.principal_id(),
            device,
            &before,
        ))
        .map_err(error)?;
    let after = q.after(codec, &binding).map_err(error)?;
    let mut sql = sqlx::QueryBuilder::new(
        "SELECT jsonb_build_object('id',e.id,'binding',jsonb_build_object('device',e.device,'registration',e.registration,'generation',e.generation,'subject',e.subject),'version',v.version,'current',coalesce(e.current_version=v.version,false),'validity',v.validity,'escrowed',v.sealed IS NOT NULL,'operation',v.operation,'createdAt',v.created_at,'invalidatedAt',v.invalidated_at) FROM mdm_recovery.entries e JOIN mdm_recovery.versions v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=",
    );
    sql.push_bind(p.tenant_id().to_owned())
        .push("::uuid AND ((e.subject->>'kind'<>'filevault' AND e.device=")
        .push_bind(device.to_owned())
        .push(") OR mdm_recovery.filevault_accessible(e.subject,")
        .push_bind(device.to_owned())
        .push("))");
    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(error)?;
    let rows: Vec<Value> = sql.build_query_scalar().fetch_all(&mut *c).await?;
    let rows = rows
        .into_iter()
        .map(|row| serde_json::from_value::<crate::Material>(row).map_err(|_| Error::Integrity))
        .collect::<Result<Vec<_>, _>>()?;
    if before != context(c, p).await? {
        return Err(Error::Conflict);
    }
    q.page_typed(rows, codec, &binding).map_err(error)
}
