//! Device Access query owner. SQL predicates, ordering and projection share this field catalog.
//! ref: sqlx-core/src/query_builder.rs@v0.9.0.
use crate::{Error, agent::Service, database::db};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::Value;
use sqlx::PgConnection;
pub static SCHEMA: Schema = Schema {
    id: "device_access",
    keys: &["id"],
    default_limit: 64,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("serverState", Kind::Enum(&["pending", "active", "revoked"])),
        Field::scalar("principal", Kind::Uuid),
        Field::scalar("policy", Kind::Uuid),
        Field::scalar("bindingGeneration", Kind::Integer),
        Field::output("operationId"),
        Field::output("device"),
        Field::output("registration"),
        Field::output("registrationGeneration"),
        Field::output("instance"),
        Field::output("factorGeneration"),
        Field::output("accountDisposition"),
        Field::output("account"),
        Field::output("accountIntent"),
        Field::output("createdByRss"),
        Field::output("policyVersion"),
        Field::output("desired"),
        Field::output("receivedRevision"),
        Field::output("appliedRevision"),
        Field::output("effect"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "b.id::text COLLATE \"C\"",
        "revision" => "b.revision",
        "serverState" => "b.state COLLATE \"C\"",
        "principal" => "b.principal::text COLLATE \"C\"",
        "policy" => "(b.document->>'policy') COLLATE \"C\"",
        "bindingGeneration" => "b.generation",
        _ => unreachable!("checked binding field"),
    }
}
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
    Ok(
        rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
            .await?
            .query_binding(p)?,
    )
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingView {
    pub id: uuid::Uuid,
    pub operation_id: uuid::Uuid,
    pub device: String,
    pub registration: uuid::Uuid,
    pub registration_generation: i64,
    pub instance: uuid::Uuid,
    pub principal: uuid::Uuid,
    pub binding_generation: i64,
    pub factor_generation: i64,
    pub revision: i64,
    pub server_state: super::State,
    pub account_disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    pub account: Option<rss_mdm_agent_wire::runtime::AccessAccount>,
    pub account_intent: super::AccountIntent,
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
        registration: b.registration,
        registration_generation: b.registration_generation,
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
        p: &AuthorizedPrincipal,
        device: &str,
        id: uuid::Uuid,
    ) -> Result<BindingView, Error> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::service::authorize(&mut tx, p, device, Permission::AccountWrite).await?;
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
        Ok(view(b))
    }
    pub async fn device_access_bindings(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<Page<rss_mdm_query::directory::Projection<BindingView>>, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id())
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
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT b.document FROM mdm_access.device_access_bindings b WHERE b.tenant_id=",
        );
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND b.device=")
            .push_bind(device.to_owned());
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(error)?;
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
        self.store.confirm_query(p, &before).await?;
        Ok(page)
    }
}
