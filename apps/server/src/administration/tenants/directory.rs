//! Installation management queries stay under the registry's transaction and realm authority.
use super::service::{ReadReply, Service};
use super::*;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::directory::{Query, Schema};
use serde_json::Value;
pub static TENANTS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Tenant>("tenants", &["tenantId"], 100, 1000, &[]).expect("Public directory model"));
pub static PROVISIONINGS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Receipt>("provisionings", &["operationId"], 100, 1000, &[]).expect("Public directory model"));
fn error(e: rss_mdm_query::Error) -> Reason {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Reason::Conflict,
        _ => Reason::Invalid,
    }
}
pub(super) async fn page(
    s: &Service,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    q: &Query,
    provisionings: bool,
) -> Result<ReadReply> {
    q.require_schema(if provisionings {
        &PROVISIONINGS
    } else {
        &TENANTS
    })
    .map_err(error)?;
    let current = rss_mdm_authorization_service::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await
    .map_err(|_| Reason::Storage)?;
    let binding = q
        .binding(&(
            p.tenant_id(),
            p.instance_id(),
            current.query_binding(p).map_err(|_| Reason::Forbidden)?,
        ))
        .map_err(error)?;
    let codec = rss_mdm_query::cursor::CursorCodec::from_key(s.fingerprint.clone());
    let after = q.after(&codec, &binding).map_err(error)?;
    enum Rows {
        Provisionings(Vec<Receipt>),
        Tenants(Vec<Tenant>),
    }
    let rows = if provisionings {
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision'",
        );
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*PROVISIONING_BINDINGS).map_err(error)?;
        let values = sql
            .build_query_scalar::<Value>()
            .fetch_all(c)
            .await
            .map_err(|_| Reason::Storage)?;
        Rows::Provisionings(
            values
                .into_iter()
                .map(serde_json::from_value)
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| Reason::Storage)?,
        )
    } else {
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT t.tenant_id::text FROM public.mdm_tenants t JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id) CROSS JOIN public.mdm_installation i WHERE NOT t.deleted",
        );
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*TENANT_BINDINGS).map_err(error)?;
        let ids: Vec<String> = sql
            .build_query_scalar()
            .fetch_all(&mut *c)
            .await
            .map_err(|_| Reason::Storage)?;
        let mut rows = Vec::with_capacity(ids.len());
        for id in ids {
            rows.push(tenant_on(c, &id, false).await?)
        }
        Rows::Tenants(rows)
    };
    p.check_live().map_err(|_| Reason::Forbidden)?;
    Ok(match rows {
        Rows::Provisionings(rows) => {
            ReadReply::Provisionings(q.page_typed(rows, &codec, &binding).map_err(error)?)
        }
        Rows::Tenants(rows) => {
            ReadReply::List(q.page_typed(rows, &codec, &binding).map_err(error)?)
        }
    })
}

pub static PROVISIONING_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&PROVISIONINGS, &[rss_mdm_query_postgres::Source::json("", "receipt")]).expect("Complete public model storage binding"));

pub static TENANT_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&TENANTS, &[rss_mdm_query_postgres::Source::required_column("tenantId", "t.tenant_id::text COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("name", "t.name COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("notes", "t.notes COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("revision", "t.revision"),
rss_mdm_query_postgres::Source::column("initialEpoch", "t.initial_epoch"),
rss_mdm_query_postgres::Source::column("currentEpoch", "e.epoch"),
rss_mdm_query_postgres::Source::column("management", "(t.tenant_id=i.management_tenant_id)"),
rss_mdm_query_postgres::Source::column("deletable", "NOT(t.used OR t.deleted OR t.tenant_id=i.management_tenant_id)")]).expect("Complete public model storage binding"));
