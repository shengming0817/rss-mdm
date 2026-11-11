//! Device Access query owner. SQL predicates, ordering and projection share this field catalog.
//! ref: sqlx-core/src/query_builder.rs@v0.9.0.
use crate::{Error, database::db, service::Service};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Query, Schema},
};
use serde_json::Value;
use sqlx::PgConnection;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<BindingView>("device_access", &["id"], 64, 100, &[])
        .expect("Public directory model")
});
pub(crate) fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Malformed,
    }
}
pub(crate) async fn authorization_binding(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
) -> Result<String, Error> {
    Ok(rss_mdm_authorization_service::snapshot_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?
    .query_binding(p)?)
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingView {
    pub id: uuid::Uuid,
    pub operation_id: uuid::Uuid,
    pub device: String,
    pub instance: uuid::Uuid,
    pub principal: uuid::Uuid,
    pub binding_generation: i64,
    pub factor_generation: i64,
    pub revision: i64,
    pub server_state: rss_mdm_device_access::State,
    pub account_disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    pub account: Option<rss_mdm_agent_wire::runtime::AccessAccount>,
    pub account_intent: rss_mdm_device_access::AccountIntent,
    pub created_by_rss: bool,
    pub policy: uuid::Uuid,
    pub policy_version: uuid::Uuid,
    pub desired: rss_mdm_agent_wire::runtime::AccessConfiguration,
    pub received_revision: Option<i64>,
    pub applied_revision: Option<i64>,
    pub effect: Option<rss_mdm_agent_wire::runtime::AccessEffect>,
}
pub fn view(b: super::Binding) -> BindingView {
    BindingView {
        id: b.id,
        operation_id: b.operation_id,
        device: b.device,

        instance: b.person.instance,
        principal: b.person.principal,
        binding_generation: b.generation,
        factor_generation: b.factor_generation,
        revision: b.revision,
        server_state: b.state,
        account_disposition: b.account_disposition,
        account: b.account,
        account_intent: b.intent,
        created_by_rss: b.created_by_rss,
        policy: b.policy,
        policy_version: b.policy_version,
        desired: b.configuration,
        received_revision: b.received_revision,
        applied_revision: b.applied_revision,
        effect: b.effect,
    }
}

impl Service {
    pub async fn device_access_binding(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        device: &str,
        id: uuid::Uuid,
    ) -> Result<BindingView, Error> {
        let p = request.proof.as_ref();
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?
        .require(p, Permission::AccountWrite, Some(device))
        .map_err(rss_mdm_authorization_service::Error::from)?;
        let before = authorization_binding(&mut tx, p).await?;
        let b = super::storage::get_in(
            &mut tx,
            uuid::Uuid::parse_str(&self.tenant.to_string()).map_err(|_| Error::Corrupt)?,
            id,
        )
        .await?;
        if b.device != device {
            return Err(Error::NotFound);
        }
        p.check_live()?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(request, &before).await?;
        Ok(view(b))
    }
    pub async fn device_access_bindings(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        device: &str,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<Page<rss_mdm_query::directory::Projection<BindingView>>, Error> {
        let p = request.proof.as_ref();
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?
        .require(p, Permission::AccountWrite, Some(device))
        .map_err(rss_mdm_authorization_service::Error::from)?;
        let before = authorization_binding(&mut tx, p).await?;
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
        let mut sql =
            sqlx::QueryBuilder::new("SELECT b.document FROM rss_da.bindings b WHERE b.tenant_id=");
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND b.device=")
            .push_bind(device.to_owned());
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*BINDINGS).map_err(error)?;
        let rows: Vec<Value> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let rows = rows
            .into_iter()
            .map(|v| {
                let b: super::Binding = serde_json::from_value(v).map_err(|_| Error::Corrupt)?;
                b.validate().map_err(|_| Error::Corrupt)?;
                Ok(view(b))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        p.check_live()?;
        let page = q.page_typed(rows, codec, &binding).map_err(error)?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(request, &before).await?;
        Ok(page)
    }
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &SCHEMA,
            &[
                rss_mdm_query_postgres::Source::json("id", "b.document#>'{id}'"),
                rss_mdm_query_postgres::Source::json("operationId", "b.document#>'{operationId}'"),
                rss_mdm_query_postgres::Source::json("device", "b.document#>'{device}'"),
                rss_mdm_query_postgres::Source::json(
                    "factorGeneration",
                    "b.document#>'{factorGeneration}'",
                ),
                rss_mdm_query_postgres::Source::json("revision", "b.document#>'{revision}'"),
                rss_mdm_query_postgres::Source::json(
                    "accountDisposition",
                    "b.document#>'{accountDisposition}'",
                ),
                rss_mdm_query_postgres::Source::json("account", "b.document#>'{account}'"),
                rss_mdm_query_postgres::Source::json(
                    "createdByRss",
                    "b.document#>'{createdByRss}'",
                ),
                rss_mdm_query_postgres::Source::json("policy", "b.document#>'{policy}'"),
                rss_mdm_query_postgres::Source::json(
                    "policyVersion",
                    "b.document#>'{policyVersion}'",
                ),
                rss_mdm_query_postgres::Source::json(
                    "receivedRevision",
                    "b.document#>'{receivedRevision}'",
                ),
                rss_mdm_query_postgres::Source::json(
                    "appliedRevision",
                    "b.document#>'{appliedRevision}'",
                ),
                rss_mdm_query_postgres::Source::json("effect", "b.document#>'{effect}'"),
                rss_mdm_query_postgres::Source::column(
                    "instance",
                    "(b.document->'person'->>'instance') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column(
                    "principal",
                    "b.principal::text COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column("bindingGeneration", "b.generation"),
                rss_mdm_query_postgres::Source::column("serverState", "b.state COLLATE \"C\""),
                rss_mdm_query_postgres::Source::json("accountIntent", "b.document->'intent'"),
                rss_mdm_query_postgres::Source::json("desired", "b.document->'configuration'"),
            ],
        )
        .expect("Complete public model storage binding")
    });
