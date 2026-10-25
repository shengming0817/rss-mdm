//! Public metadata only; material disclosure remains a separate audited action.
use crate::Error;
use rss_mdm_query::directory::{Field, Kind, Schema};
pub static SCHEMA: Schema = Schema {
    id: "certificates",
    keys: &["id"],
    default_limit: 50,
    max_limit: 200,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("retired", Kind::Boolean),
        Field::scalar("recommendedVersion", Kind::Integer),
        Field::output("latest"),
    ],
};
pub static HISTORY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "certificate_versions",
    default_limit: 50,
    max_limit: 200,
    order: "version DESC",
    context: &[],
};
pub(crate) fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
pub(crate) fn column(n: &str) -> &'static str {
    match n {
        "id" => "e.id::text COLLATE \"C\"",
        "revision" => "e.revision",
        "retired" => "e.retired",
        "recommendedVersion" => "e.recommended_version",
        _ => unreachable!("checked archive field"),
    }
}
pub(crate) const SELECT: &str = "SELECT e.id::text,e.revision,e.retired,e.recommended_version,v.entry_id::text,v.version,v.actor::text,v.instance::text,v.operation_id::text,v.created_at,v.metadata::text,v.facts::text,v.request_entry_id::text,v.request_version,v.source FROM mdm_certificate_archive.entries e JOIN LATERAL(SELECT entry_id,version,actor,instance,operation_id,created_at,metadata,facts,request_entry_id,request_version,source FROM mdm_certificate_archive.versions x WHERE x.tenant_id=e.tenant_id AND x.entry_id=e.id ORDER BY x.version DESC LIMIT 1)v ON true WHERE e.tenant_id=";
pub(crate) fn entry(r: &sqlx::postgres::PgRow) -> Result<crate::Entry, Error> {
    use sqlx::Row;
    Ok(crate::Entry {
        id: r
            .try_get::<String, _>("id")?
            .parse()
            .map_err(|_| Error::Integrity)?,
        revision: r.try_get("revision")?,
        retired: r.try_get("retired")?,
        recommended_version: r.try_get("recommended_version")?,
        latest: crate::store::decode_version(r)?,
    })
}
