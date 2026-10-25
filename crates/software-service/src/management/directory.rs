use super::*;
use catalog::Access;
use content::ManagementContentPort;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::directory::{Field, Kind, Query, Schema};
use serde_json::{Value, json};
pub static SOURCES: Schema = Schema {
    id: "software_sources",
    keys: &["id", "revision"],
    default_limit: 20,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Text),
        Field::scalar("revision", Kind::Text),
        Field::scalar(
            "protocol",
            Kind::Enum(&["private", "winget_rest", "winget_community", "brew_tap"]),
        ),
        Field::scalar("state", Kind::Enum(&["enabled", "disabled"])),
        Field::output("snapshot"),
        Field::output("source"),
        Field::output("lifecycle"),
    ],
};
fn source_column(name: &str) -> &'static str {
    match name {
        "id" => "id COLLATE \"C\"",
        "revision" => "revision COLLATE \"C\"",
        "protocol" => "(definition->'protocol'->>'kind') COLLATE \"C\"",
        "state" => "(lifecycle->>'state') COLLATE \"C\"",
        _ => unreachable!("checked source field"),
    }
}
pub async fn sources<C: ManagementContentPort>(
    app: &Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<Value, Error> {
    q.require_schema(&SOURCES).map_err(query_error)?;
    p.manage(Permission::SoftwareRead)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, p, audit, q),
        |ctx, tx| {
            Box::pin(async move {
                let (app, p, _audit, q) = ctx;
                let current = transaction::current(tx, p).await?;
                current.require(p, Permission::SoftwareRead, None)?;
                let binding = q
                    .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
                    .map_err(query_error)?;
                let after = q.after(&app.cursor, &binding).map_err(query_error)?;
                let mut sql = sqlx::QueryBuilder::new(
                    "SELECT id,revision FROM mdm_software.sources WHERE tenant_id=",
                );
                sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
                rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), source_column)
                    .map_err(query_error)?;
                let keys: Vec<(String, String)> = tx
                    .with_connection(move |c| {
                        Box::pin(async move { sql.build_query_as().fetch_all(c).await })
                    })
                    .await?;
                let mut rows = Vec::new();
                for (id, revision) in keys {
                    let mut row = app
                        .catalog
                        .reader()
                        .source_read_in(tx, &id, &revision)
                        .await?;
                    row["id"] = json!(id);
                    row["revision"] = json!(revision);
                    row["protocol"] = row["source"]["protocol"]["kind"].clone();
                    row["state"] = row["lifecycle"]["state"].clone();
                    rows.push(row);
                }
                p.check_live()?;

                Ok(json!(
                    q.page(rows, &app.cursor, &binding).map_err(query_error)?
                ))
            })
        },
        transaction::TransactionOwner::SoftwareCatalog,
    )
    .await
}
pub async fn versions<C: ManagementContentPort>(
    app: &Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    q: Query,
) -> Result<Value, Error> {
    q.require_schema(&rss_mdm_resource::directory::VERSION_SCHEMA)
        .map_err(query_error)?;
    rss_mdm_resource::Id::new(id).map_err(|_| Error::Malformed)?;
    p.manage(Permission::SoftwareRead)?;
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, p, audit, id, q),
        |ctx, tx| {
            Box::pin(async move {
                let (app, p, _audit, id, q) = ctx;
                let current = transaction::current(tx, p).await?;
                current.require(p, Permission::SoftwareRead, None)?;
                let binding = q
                    .binding(&(
                        p.tenant_id(),
                        p.instance_id(),
                        current.query_binding(p)?,
                        *id,
                    ))
                    .map_err(query_error)?;
                let after = q.after(&app.cursor, &binding).map_err(query_error)?;
                let rows = app
                    .resources
                    .version_directory_in(tx, id, q, after.as_ref())
                    .await?
                    .map_err(|_| Error::ResourceMissing)?;
                p.check_live()?;

                Ok(json!(
                    q.page(rows, &app.cursor, &binding).map_err(query_error)?
                ))
            })
        },
        transaction::TransactionOwner::SoftwareCatalog,
    )
    .await
}
