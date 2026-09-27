//! Group/Scope semantic coordinates and covered/pending fact watermarks.
use crate::Error;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
type InTransaction<T> = std::result::Result<std::result::Result<T, Error>, PgError>;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SourceReference {
    pub id: String,
    pub revision: u64,
}
pub(crate) struct SourceHeads {
    tenant: TenantId,
}
impl SourceHeads {
    pub fn new(tenant: TenantId) -> Self {
        Self { tenant }
    }
    pub async fn reference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
    ) -> InTransaction<Option<u64>> {
        if tx.tenant_id() != self.tenant {
            return Ok(Err(Error::Forbidden));
        }
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let value=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,i64>("SELECT revision FROM mdm_planning.source_heads WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
        Ok(Ok(value
            .map(|v| {
                u64::try_from(v)
                    .map_err(|_| PgError::from(sqlx::Error::Protocol("source coordinate".into())))
            })
            .transpose()?))
    }
    pub async fn advance_reference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        revision: u64,
    ) -> InTransaction<()> {
        if tx.tenant_id() != self.tenant {
            return Ok(Err(Error::Forbidden));
        }
        if id.is_empty() || id.len() > 128 {
            return Ok(Err(Error::Malformed));
        }
        let Ok(revision) = i64::try_from(revision) else {
            return Ok(Err(Error::Malformed));
        };
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let changed=tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_planning.source_heads(tenant_id,id,revision) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision WHERE mdm_planning.source_heads.revision<=excluded.revision").bind(tenant).bind(id).bind(revision).execute(c).await.map(|r|r.rows_affected())})).await?;
        Ok(if changed == 1 {
            Ok(())
        } else {
            Err(Error::Conflict)
        })
    }
    pub async fn require_reference_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        watermark: u64,
    ) -> InTransaction<()> {
        self.advance_input_in(tx, id, watermark, true).await
    }
    pub async fn observe_reference_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        watermark: u64,
    ) -> InTransaction<()> {
        self.advance_input_in(tx, id, watermark, false).await
    }
    async fn advance_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        watermark: u64,
        required: bool,
    ) -> InTransaction<()> {
        if tx.tenant_id() != self.tenant {
            return Ok(Err(Error::Forbidden));
        }
        let Ok(watermark) = i64::try_from(watermark) else {
            return Ok(Err(Error::Malformed));
        };
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let changed=tx.with_connection(move|c|Box::pin(async move {sqlx::query(if required {"UPDATE mdm_planning.source_heads SET required_input=greatest(required_input,$3) WHERE tenant_id=$1::uuid AND id=$2"}else{"UPDATE mdm_planning.source_heads SET observed_input=greatest(observed_input,$3) WHERE tenant_id=$1::uuid AND id=$2"}).bind(tenant).bind(id).bind(watermark).execute(c).await.map(|r|r.rows_affected())})).await?;
        Ok(if changed == 1 {
            Ok(())
        } else {
            Err(Error::NotFound)
        })
    }
}
