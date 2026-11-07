//! Tenant enterprise metadata directory, distinct from device-scoped binding queries.
use super::*;
use crate::device_access::directory::{authorization_binding, error};
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::Value;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema {
    id: "enterprise_configuration",
    keys: &["id"],
    default_limit: 64,
    max_limit: 100,
    fields: vec![
        Field::scalar("id", Kind::Text),
        Field::scalar(
            "kind",
            Kind::enumeration(&["relying_party", "subject", "windows_key"]),
        ),
        Field::output("value"),
    ],
});
fn column(name: &str) -> &'static str {
    match name {
        "id" => "q.id COLLATE \"C\"",
        "kind" => "q.kind COLLATE \"C\"",
        _ => unreachable!("checked enterprise field"),
    }
}
const SELECT: &str = "SELECT jsonb_build_object('id',q.id,'kind',q.kind,'value',q.document) FROM (SELECT tenant_id,'rp:'||id AS id,'relying_party'::text AS kind,document FROM rss_da.relying_parties UNION ALL SELECT tenant_id,'subject:'||provider::text||':'||principal::text,'subject',document FROM rss_da.subjects UNION ALL SELECT tenant_id,'windows:'||binding::text,'windows_key',document FROM rss_da.windows_sources) q WHERE q.tenant_id=";
impl Service {
    pub async fn enterprise_configuration_record(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        id: &str,
    ) -> Result<RecordView, Error> {
        let p = request.proof.as_ref();
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        if id.len() > 256 || id.chars().any(char::is_control) {
            return Err(Error::Malformed);
        }
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?
        .require(p, Permission::EnterpriseApplicationsRead, None)
        .map_err(rss_mdm_authorization_service::Error::from)?;
        let before = authorization_binding(&mut tx, p).await?;
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
        self.store.confirm_query(request, &before).await?;
        serde_json::from_value(value).map_err(|_| Error::Corrupt)
    }

    pub async fn enterprise_configuration(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<Page<rss_mdm_query::directory::Projection<RecordView>>, Error> {
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
        .require(p, Permission::EnterpriseApplicationsRead, None)
        .map_err(rss_mdm_authorization_service::Error::from)?;
        let before = authorization_binding(&mut tx, p).await?;
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
        p.check_live()?;
        let page = q.page_typed(rows, codec, &binding).map_err(error)?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(request, &before).await?;
        Ok(page)
    }
}

#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
pub struct RecordView {
    pub id: String,
    #[serde(flatten)]
    pub record: Record,
}
