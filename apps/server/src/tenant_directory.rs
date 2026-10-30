//! Installation management queries stay under the registry's transaction and realm authority.
use super::*;
use rss_mdm_query::directory::{Field, Kind, Query, Schema};
use serde_json::Value;
pub(super) static TENANTS: Schema = Schema {
    id: "tenants",
    keys: &["tenantId"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("tenantId", Kind::Uuid),
        Field::scalar("name", Kind::Text),
        Field::scalar("notes", Kind::Text),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("initialEpoch", Kind::Integer),
        Field::scalar("management", Kind::Boolean),
        Field::scalar("deletable", Kind::Boolean),
        Field::output("currentEpoch"),
    ],
};
pub(super) static PROVISIONINGS: Schema = Schema {
    id: "provisionings",
    keys: &["operationId"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("operationId", Kind::Uuid),
        Field::output("action"),
        Field::output("result"),
    ],
};
fn error(e: rss_mdm_query::Error) -> Reason {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Reason::Conflict,
        _ => Reason::Invalid,
    }
}
fn column(n: &str) -> &'static str {
    match n {
        "tenantId" => "t.tenant_id::text COLLATE \"C\"",
        "name" => "t.name COLLATE \"C\"",
        "notes" => "t.notes COLLATE \"C\"",
        "revision" => "t.revision",
        "initialEpoch" => "t.initial_epoch",
        "management" => "(t.tenant_id=i.management_tenant_id)",
        "deletable" => "NOT(t.used OR t.deleted OR t.tenant_id=i.management_tenant_id)",
        "operationId" => "operation_id::text COLLATE \"C\"",
        _ => unreachable!("checked tenant directory field"),
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
    let current = rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
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
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(error)?;
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
            "SELECT t.tenant_id::text FROM public.mdm_tenants t CROSS JOIN public.mdm_installation i WHERE NOT t.deleted",
        );
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(error)?;
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
