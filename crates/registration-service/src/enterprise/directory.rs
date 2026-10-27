//! Tenant enterprise metadata directory, distinct from device-scoped binding queries.
use super::*;
use crate::device_access::directory::{context, error};
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::Value;
pub static SCHEMA: Schema = Schema {
    id: "enterprise_configuration",
    keys: &["id"],
    default_limit: 64,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Text),
        Field::scalar(
            "kind",
            Kind::Enum(&["relying_party", "subject", "windows_key"]),
        ),
        Field::output("value"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "q.id COLLATE \"C\"",
        "kind" => "q.kind COLLATE \"C\"",
        _ => unreachable!("checked enterprise field"),
    }
}
const SELECT: &str = "SELECT jsonb_build_object('id',q.id,'kind',q.kind,'value',q.document) FROM (SELECT tenant_id,'rp:'||id AS id,'relying_party'::text AS kind,document FROM mdm_enterprise.relying_parties UNION ALL SELECT tenant_id,'subject:'||provider::text||':'||principal::text,'subject',document FROM mdm_enterprise.subjects UNION ALL SELECT tenant_id,'windows:'||binding::text,'windows_key',document FROM mdm_enterprise.windows_sources) q WHERE q.tenant_id=";
impl Service {
    pub async fn enterprise_configuration_record(
        &self,
        p: &AuthorizedPrincipal,
        id: &str,
    ) -> Result<RecordView, Error> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        if id.len() > 256 || id.chars().any(char::is_control) {
            return Err(Error::Malformed);
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize(&mut tx, p, Permission::EnterpriseApplicationsRead).await?;
        let mut sql = sqlx::QueryBuilder::new(SELECT);
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND q.id=")
            .push_bind(id.to_owned());
        let value: Value = sql
            .build_query_scalar()
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::NotFound)?;
        p.check_live()?;
        tx.rollback().await.map_err(db)?;
        serde_json::from_value(value).map_err(|_| Error::Corrupt)
    }

    pub async fn enterprise_configuration(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<Page<rss_mdm_query::directory::Projection<RecordView>>, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize(&mut tx, p, Permission::EnterpriseApplicationsRead).await?;
        let before = context(&mut tx, p).await?;
        let binding = q
            .binding(&(p.tenant_id(), p.instance_id(), p.principal_id(), &before))
            .map_err(error)?;
        let after = q.after(codec, &binding).map_err(error)?;
        let mut sql = sqlx::QueryBuilder::new(SELECT);
        sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(error)?;
        let rows: Vec<Value> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let rows = rows
            .into_iter()
            .map(|row| serde_json::from_value::<RecordView>(row).map_err(|_| Error::Corrupt))
            .collect::<Result<Vec<_>, _>>()?;
        if before != context(&mut tx, p).await? {
            return Err(Error::Conflict);
        }
        p.check_live()?;
        let page = q.page_typed(rows, codec, &binding).map_err(error)?;
        tx.rollback().await.map_err(db)?;
        Ok(page)
    }
}

#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
pub struct RecordView {
    pub id: String,
    #[serde(flatten)]
    pub record: Record,
}
