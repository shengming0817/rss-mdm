//! Public metadata only; material disclosure remains a separate audited action.
use crate::Error;
use rss_mdm_query::directory::{Exclusion, Schema};
use rss_mdm_query_postgres::{Bindings, Source};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::Entry>(
    "certificates", &["id"], 50, 200,
    &[Exclusion { path: "latest.facts", reason: "Material/certificate object arrays require same-element conditions; public facts remain available in output" }],
).expect("Certificate directory model is fully described")
});
pub(crate) static BINDINGS: std::sync::LazyLock<Bindings> = std::sync::LazyLock::new(|| {
    Bindings::new(
        &SCHEMA,
        &[
            Source::column("id", "e.id::text COLLATE \"C\""),
            Source::column("revision", "e.revision"),
            Source::column("retired", "e.retired"),
            Source::column("recommendedVersion", "e.recommended_version"),
            Source::column("latest.entryId", "v.entry_id::text COLLATE \"C\""),
            Source::column("latest.version", "v.version"),
            Source::column("latest.actor", "v.actor::text COLLATE \"C\""),
            Source::column("latest.instance", "v.instance::text COLLATE \"C\""),
            Source::column("latest.operationId", "v.operation_id::text COLLATE \"C\""),
            Source::column("latest.createdAt", "v.created_at"),
            Source::column("latest.source", "v.source COLLATE \"C\""),
            Source::column(
                "latest.requestVersion.entryId",
                "v.request_entry_id::text COLLATE \"C\"",
            ),
            Source::column("latest.requestVersion.version", "v.request_version"),
            Source::json("latest.metadata", "v.metadata"),
        ],
    )
    .expect("Certificate storage binds every public scalar")
});
pub fn schema() -> &'static Schema {
    BINDINGS.schema()
}
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

/// Public model with every executable selector checked by this storage owner.
pub fn execution() -> &'static rss_mdm_query::directory::Execution { BINDINGS.execution() }
