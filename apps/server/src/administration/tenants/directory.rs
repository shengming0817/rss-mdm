//! Installation management queries stay under the registry's transaction and realm authority.
use super::service::{ReadReply, Service};
use super::*;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::directory::{Query, Schema};
use serde_json::Value;
pub static TENANTS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Tenant>("tenants", &["tenantId"], 100, 1000, &[])
        .expect("Public directory model")
});
pub static PROVISIONINGS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Receipt>("provisionings", &["operationId"], 100, 1000, &[])
        .expect("Public directory model")
});
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
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*PROVISIONING_BINDINGS)
            .map_err(error)?;
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
        // Epoch is an RSS tenant-scoped fact. The installation registry is bounded to
        // 1024 business tenants plus management; qualify each original row under its
        // tenant scope before applying one complete public-model filter and page.
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT tenant_id::text FROM public.mdm_tenants WHERE NOT deleted ORDER BY tenant_id LIMIT 1026",
        ).fetch_all(&mut *c).await.map_err(|_| Reason::Storage)?;
        if ids.len() > 1025 {
            return Err(Reason::Storage);
        }
        let mut candidates = Vec::with_capacity(ids.len());
        for id in ids {
            candidates.push(tenant_on(c, &id, false).await?);
        }
        scope(c, p.tenant_id()).await?;
        let mut sql = sqlx::QueryBuilder::new("SELECT row FROM jsonb_array_elements(");
        sql.push_bind(serde_json::to_value(candidates).map_err(|_| Reason::Storage)?)
            .push("::jsonb) row WHERE true");
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*TENANT_BINDINGS)
            .map_err(error)?;
        let values: Vec<Value> = sql
            .build_query_scalar()
            .fetch_all(c)
            .await
            .map_err(|_| Reason::Storage)?;
        let rows = values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<Tenant>, _>>()
            .map_err(|_| Reason::Storage)?;
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

pub static PROVISIONING_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &PROVISIONINGS,
            &[rss_mdm_query_postgres::Source::json("", "receipt")],
        )
        .expect("Complete public model storage binding")
    });

pub static TENANT_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &TENANTS,
            &[rss_mdm_query_postgres::Source::json("", "row")],
        )
        .expect("Complete public model storage binding")
    });
