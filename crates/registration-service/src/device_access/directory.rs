//! Device Access query owner. SQL predicates, ordering and projection share this field catalog.
//! ref: sqlx-core/src/query_builder.rs@v0.9.0.
use crate::{Error, agent::Service, database::db};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::{Value, json};
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
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
pub(crate) async fn context(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
) -> Result<(String, i64), Error> {
    let authority = rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await?
        .query_binding(p)?;
    let revision:i64=sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm_access.directory_revisions WHERE tenant_id=$1::uuid),0)").bind(p.tenant_id()).fetch_one(c).await.map_err(db)?;
    Ok((authority, revision))
}
pub fn view(b: super::Binding) -> Value {
    json!({"id":b.id,"operationId":b.operation_id,"device":b.device,"registration":b.registration,"registrationGeneration":b.registration_generation,
        "instance":b.person.instance,"principal":b.person.principal,"bindingGeneration":b.generation,"factorGeneration":b.factor_generation,"revision":b.revision,
        "serverState":b.state,"accountDisposition":b.account_disposition,"account":b.account,"accountIntent":b.intent,"createdByRss":b.created_by_rss,
        "policy":b.policy,"policyVersion":b.policy_version,"desired":b.configuration,"receivedRevision":b.received_revision,
        "appliedRevision":b.applied_revision,"effect":b.effect})
}

impl Service {
    pub async fn device_access_binding(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: uuid::Uuid,
    ) -> Result<Value, Error> {
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
    ) -> Result<Page<Value>, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::service::authorize(&mut tx, p, device, Permission::AccountWrite).await?;
        let before = context(&mut tx, p).await?;
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
        if before != context(&mut tx, p).await? {
            return Err(Error::Conflict);
        }
        p.check_live()?;
        let page = q.page(rows, codec, &binding).map_err(error)?;
        tx.rollback().await.map_err(db)?;
        Ok(page)
    }
}
