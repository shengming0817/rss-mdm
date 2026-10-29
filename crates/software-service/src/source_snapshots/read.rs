use super::*;
use rss_mdm_query::{
    Page,
    directory::{Field, Kind, Projection, Query, Schema},
};
use sqlx::Row;
use uuid::Uuid;
pub static SOURCES: Schema = Schema {
    id: "software_source_snapshots",
    keys: &["source"],
    default_limit: 20,
    max_limit: 100,
    fields: &[
        Field::scalar("source", Kind::Text),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("entryCount", Kind::Integer),
        Field::scalar("importedAt", Kind::Integer),
        Field::output("documentSha256"),
        Field::output("extraction"),
    ],
};
pub static ENTRIES: Schema = Schema {
    id: "software_source_entries",
    keys: &["entryId"],
    default_limit: 20,
    max_limit: 100,
    fields: &[
        Field::scalar("entryId", Kind::Uuid),
        Field::scalar("source", Kind::Text),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("packageId", Kind::Text),
        Field::scalar("name", Kind::Text),
        Field::scalar("version", Kind::Text),
    ],
};
fn source_column(field: &str) -> &'static str {
    match field {
        "source" => "source COLLATE \"C\"",
        "revision" => "revision",
        "entryCount" => "entry_count",
        "importedAt" => "imported_at",
        _ => unreachable!("checked source directory field"),
    }
}
fn entry_column(field: &str) -> &'static str {
    match field {
        "entryId" => "e.id",
        "source" => "e.source COLLATE \"C\"",
        "revision" => "s.revision",
        "packageId" => "e.package_id COLLATE \"C\"",
        "name" => "e.name COLLATE \"C\"",
        "version" => "e.version COLLATE \"C\"",
        _ => unreachable!("checked entry directory field"),
    }
}
fn read_audit(proof: &AuthorizedPrincipal, audit: &RequestAudit) -> Result<(), Error> {
    proof.require(Permission::SoftwareRead, None)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(())
}
pub async fn sources<C: ManagementContentPort>(
    app: &Access<C>,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    query: Query,
) -> Result<Page<Projection<Snapshot>>, Error> {
    read_audit(proof, audit)?;
    query
        .require_schema(&SOURCES)
        .map_err(crate::management::query_error)?;
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, proof, query),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, query) = ctx;
                let current = authorize(tx, proof, Permission::SoftwareRead).await?;
                let binding = query
                    .binding(&(
                        proof.tenant_id(),
                        proof.instance_id(),
                        current.query_binding(proof)?,
                    ))
                    .map_err(crate::management::query_error)?;
                let after = query
                    .after(&app.cursor, &binding)
                    .map_err(crate::management::query_error)?;
                let mut sql = sqlx::QueryBuilder::new(format!(
                    "SELECT {} FROM mdm_software_snapshots.current WHERE tenant_id=",
                    storage::SNAPSHOT_COLUMNS
                ));
                sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
                rss_mdm_query_postgres::append(&mut sql, query, after.as_ref(), source_column)
                    .map_err(crate::management::query_error)?;
                let rows = tx
                    .with_connection(move |c| {
                        Box::pin(async move { sql.build().fetch_all(c).await })
                    })
                    .await?;
                let rows = rows
                    .iter()
                    .map(storage::snapshot_row)
                    .collect::<transaction::Result<Vec<_>>>()?;
                proof.check_live()?;
                query
                    .page_typed(rows, &app.cursor, &binding)
                    .map_err(|e| crate::management::query_error(e).into())
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
pub async fn entries<C: ManagementContentPort>(
    app: &Access<C>,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    source: String,
    query: Query,
) -> Result<Page<Projection<Entry>>, Error> {
    read_audit(proof, audit)?;
    source_id(&source)?;
    query
        .require_schema(&ENTRIES)
        .map_err(crate::management::query_error)?;
    transaction::inspect(&app.runtime, app.tenant, (app, proof, source, query), |ctx, tx| Box::pin(async move {
        let (app, proof, source, query) = ctx;
        let current = authorize(tx, proof, Permission::SoftwareRead).await?;
        storage::lock(tx, source, true).await?;
        let snapshot = storage::current(tx, source).await?;
        let binding = query.binding(&(proof.tenant_id(), proof.instance_id(), current.query_binding(proof)?, &snapshot.source, snapshot.revision))
            .map_err(crate::management::query_error)?;
        let after = query.after(&app.cursor, &binding).map_err(crate::management::query_error)?;
        let mut sql = sqlx::QueryBuilder::new("SELECT e.id,e.source,s.revision,e.package_id,e.name,e.version FROM mdm_software_snapshots.entries e JOIN mdm_software_snapshots.current s USING(tenant_id,source) WHERE e.tenant_id=");
        sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND e.source=").push_bind(source.clone());
        rss_mdm_query_postgres::append(&mut sql, query, after.as_ref(), entry_column)
            .map_err(crate::management::query_error)?;
        let rows = tx.with_connection(move |c| Box::pin(async move { sql.build().fetch_all(c).await })).await?;
        let rows = rows.iter().map(storage::entry_row).collect::<transaction::Result<Vec<_>>>()?;
        proof.check_live()?;
        query.page_typed(rows, &app.cursor, &binding).map_err(|e| crate::management::query_error(e).into())
    }), TransactionOwner::SoftwareCatalog).await
}
pub async fn snapshot<C: ManagementContentPort>(
    app: &Access<C>,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    source: String,
) -> Result<SnapshotDetail, Error> {
    read_audit(proof, audit)?;
    source_id(&source)?;
    transaction::inspect(&app.runtime, app.tenant, (proof, source), |ctx, tx| Box::pin(async move {
        let (proof, source) = ctx;
        authorize(tx, proof, Permission::SoftwareRead).await?;
        let tenant = tx.tenant_id().to_string();
        let source = source.clone();
        let sql = "SELECT source,revision,document_sha256,entry_count,imported_at,extraction,document FROM mdm_software_snapshots.current WHERE tenant_id=$1::uuid AND source=$2";
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query(sql).bind(tenant).bind(source).fetch_optional(c).await
        })).await?.ok_or(Error::ResourceMissing)?;
        proof.check_live()?;
        Ok(SnapshotDetail { snapshot: storage::snapshot_row(&row)?, document: row.try_get("document")? })
    }), TransactionOwner::SoftwareCatalog).await
}
pub async fn entry<C: ManagementContentPort>(
    app: &Access<C>,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    source: String,
    id: Uuid,
) -> Result<EntryDetail, Error> {
    read_audit(proof, audit)?;
    source_id(&source)?;
    transaction::inspect(&app.runtime, app.tenant, (proof, source, id), |ctx, tx| Box::pin(async move {
        let (proof, source, id) = ctx;
        authorize(tx, proof, Permission::SoftwareRead).await?;
        let tenant = tx.tenant_id().to_string();
        let source = source.clone();
        let id = *id;
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT e.id,e.source,s.revision,e.package_id,e.name,e.version,s.document_sha256,s.document#>e.path AS data FROM mdm_software_snapshots.entries e JOIN mdm_software_snapshots.current s USING(tenant_id,source) WHERE e.tenant_id=$1::uuid AND e.source=$2 AND e.id=$3")
                .bind(tenant).bind(source).bind(id).fetch_optional(c).await
        })).await?.ok_or(Error::ResourceMissing)?;
        proof.check_live()?;
        Ok(EntryDetail {
            entry: storage::entry_row(&row)?,
            document_sha256: row.try_get::<Vec<u8>,_>("document_sha256")?.try_into().map_err(|_| invariant())?,
            data: row.try_get("data")?,
        })
    }), TransactionOwner::SoftwareCatalog).await
}
pub async fn operation<C: ManagementContentPort>(
    app: &Access<C>,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    source: String,
    id: Uuid,
) -> Result<Receipt, Error> {
    read_audit(proof, audit)?;
    source_id(&source)?;
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (proof, source, id),
        |ctx, tx| {
            Box::pin(async move {
                let (proof, source, id) = ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let receipt = storage::receipt(tx, source, *id, &write::actor(proof), None)
                    .await?
                    .ok_or(Error::ResourceMissing)?;
                proof.check_live()?;
                Ok(receipt)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
