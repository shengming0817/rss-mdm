use super::*;
use catalog::Access;
use content::ManagementContentPort;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::directory::{Query, Schema};

pub static SOURCES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<SourceRow>("software_sources", &["id", "revision"], 20, 100, &[]).expect("Public directory model"));
pub async fn sources<C: ManagementContentPort>(
    app: &Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<SourceRow>>, Error> {
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
                rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*SOURCE_BINDINGS)
                    .map_err(query_error)?;
                let keys: Vec<(String, String)> = tx
                    .with_connection(move |c| {
                        Box::pin(async move { sql.build_query_as().fetch_all(c).await })
                    })
                    .await?;
                let mut rows = Vec::new();
                for (id, revision) in keys {
                    let view: crate::catalog::SourceView = super::projection(
                        app.catalog
                            .reader()
                            .source_read_in(tx, &id, &revision)
                            .await?,
                    )?;
                    let protocol = match &view.source.protocol {
                        crate::catalog::SourceProtocol::Private => ProtocolKind::Private,
                        crate::catalog::SourceProtocol::WingetRest { .. } => {
                            ProtocolKind::WingetRest
                        }
                        crate::catalog::SourceProtocol::WingetCommunity { .. } => {
                            ProtocolKind::WingetCommunity
                        }
                        crate::catalog::SourceProtocol::BrewTap { .. } => ProtocolKind::BrewTap,
                    };
                    let state = view.lifecycle.state.clone();
                    rows.push(SourceRow {
                        id,
                        revision,
                        protocol,
                        state,
                        view,
                    });
                }
                p.check_live()?;

                Ok(q.page_typed(rows, &app.cursor, &binding)
                    .map_err(query_error)?)
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
) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<rss_mdm_resource::directory::VersionRow>>, Error> {
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

                let rows = rows
                    .into_iter()
                    .map(super::projection::<rss_mdm_resource::directory::VersionRow>)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(q.page_typed(rows, &app.cursor, &binding)
                    .map_err(query_error)?)
            })
        },
        transaction::TransactionOwner::SoftwareCatalog,
    )
    .await
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct SourceRow {
    #[schemars(with = "rss_mdm_resource::Id")]
    pub id: String,
    #[schemars(with = "rss_mdm_resource::Id")]
    pub revision: String,
    pub protocol: ProtocolKind,
    pub state: crate::catalog::LifecycleState,
    #[serde(flatten)]
    pub view: crate::catalog::SourceView,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Private,
    WingetRest,
    WingetCommunity,
    BrewTap,
}
