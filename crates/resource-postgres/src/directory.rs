//! Current Resource headers; directory reads never load immutable version artifacts.
use crate::{STORAGE, core::*, error::*, store::ResourceStore};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
/// ID pagination and lifecycle filters for Resource metadata.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    /// Exclusive canonical resource ID.
    pub after: Option<String>,
    /// Requested page size, one through one thousand.
    #[serde(default = "limit")]
    pub limit: usize,
    /// Reverse canonical ID order.
    #[serde(default)]
    pub descending: bool,
    /// Exact software, script or configuration kind.
    pub kind: Option<String>,
    /// Whether an active version must currently exist.
    pub active: Option<bool>,
}
fn limit() -> usize {
    64
}
impl ResourceStore {
    /// Project validated aggregate headers in this store's tenant and runtime.
    pub async fn directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        q: &DirectoryQuery,
    ) -> InTransaction<Vec<Value>> {
        input!(self.check(tx)?);
        if !(1..=1000).contains(&q.limit) || q.after.as_ref().is_some_and(|v| Id::new(v).is_err()) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let kind = match q.kind.as_deref() {
            None => None,
            Some("software") => Some(0_i32),
            Some("script") => Some(1),
            Some("configuration") => Some(2),
            _ => return Ok(Err(Rejection::InvalidInput)),
        };
        let tenant = tx.tenant_id();
        let query = q.clone();
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT id,revision,document,digest FROM mdm_resource.aggregates WHERE tenant_id=$1::uuid AND ($2::text IS NULL OR CASE WHEN $3 THEN id COLLATE \"C\"<$2 COLLATE \"C\" ELSE id COLLATE \"C\">$2 COLLATE \"C\" END) AND ($4::integer IS NULL OR (convert_from(document,'UTF8')::jsonb->>3)::integer=$4) AND ($5::boolean IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(convert_from(document,'UTF8')::jsonb->5) s WHERE s->>1='1')=$5) ORDER BY CASE WHEN NOT $3 THEN id END COLLATE \"C\" ASC,CASE WHEN $3 THEN id END COLLATE \"C\" DESC LIMIT $6")
                .bind(tenant.to_string()).bind(query.after).bind(query.descending).bind(kind).bind(query.active).bind((query.limit+1) as i64).fetch_all(c).await
        })).await?;
        let mut items = Vec::new();
        let mut bytes = 0_usize;
        for row in rows {
            let header = STORAGE.checked(row.try_get("document")?, row.try_get("digest")?)?;
            bytes += header.len();
            if bytes > 8_388_608 {
                return Err(STORAGE.fault("directory::bytes"));
            }
            let id: String = row.try_get("id")?;
            items.push(crate::codec::directory_header(
                &header,
                tenant,
                &id,
                row.try_get("revision")?,
            )?);
        }
        Ok(Ok(items))
    }
}
