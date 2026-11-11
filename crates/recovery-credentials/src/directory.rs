//! Recovery metadata only; sealed bytes and keys never enter a directory projection.
use crate::Error;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Query, Schema},
};
use serde_json::Value;
use sqlx::PgConnection;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<crate::Material>("recovery_credentials", &["id", "version"], 64, 100, &[]).expect("Public directory model"));
pub(crate) fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Malformed,
    }
}
pub(crate) async fn read(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
    grant: &str,
    q: &Query,
    codec: &CursorCodec,
) -> Result<Page<rss_mdm_query::directory::Projection<crate::Material>>, Error> {
    q.require_schema(&SCHEMA).map_err(error)?;
    let binding = q
        .binding(&(
            p.tenant_id(),
            p.instance_id(),
            p.principal_id(),
            device,
            grant,
        ))
        .map_err(error)?;
    let after = q.after(codec, &binding).map_err(error)?;
    let mut sql = sqlx::QueryBuilder::new(crate::storage_profile::sql(profile).directory_read_1);
    sql.push_bind(p.tenant_id().to_owned())
        .push("::uuid AND ((e.subject->>'kind'<>'filevault' AND e.device=")
        .push_bind(device.to_owned())
        .push(crate::storage_profile::sql(profile).directory_read_2)
        .push_bind(device.to_owned())
        .push("))");
    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*BINDINGS).map_err(error)?;
    let rows: Vec<Value> = sql.build_query_scalar().fetch_all(&mut *c).await?;
    let rows = rows
        .into_iter()
        .map(|row| serde_json::from_value::<crate::Material>(row).map_err(|_| Error::Integrity))
        .collect::<Result<Vec<_>, _>>()?;
    q.page_typed(rows, codec, &binding).map_err(error)
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&SCHEMA, &[rss_mdm_query_postgres::Source::required_column("id", "e.id::text COLLATE \"C\""),
rss_mdm_query_postgres::Source::required_column("version", "v.version"),
rss_mdm_query_postgres::Source::column("current", "coalesce(e.current_version=v.version,false)"),
rss_mdm_query_postgres::Source::column("validity", "v.validity COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("escrowed", "(v.sealed IS NOT NULL)"),
rss_mdm_query_postgres::Source::column("operation", "v.operation::text COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("createdAt", "v.created_at"),
rss_mdm_query_postgres::Source::column("invalidatedAt", "v.invalidated_at"),
rss_mdm_query_postgres::Source::column("binding.device", "e.device COLLATE \"C\""),
rss_mdm_query_postgres::Source::json("binding.subject", "e.subject")]).expect("Complete public model storage binding"));
