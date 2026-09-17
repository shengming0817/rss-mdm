use crate::{Admission, BackendStorage, digest};
use rss_transactional_messaging::{
    message::{MessageEnvelope, MessageId, MessageMetadata},
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgTransaction};
use sqlx::Row;

/// Verified aggregate bytes and their storage CAS token.
pub struct AggregateRecord {
    /// Persisted storage revision.
    pub revision: u64,
    /// Digest-verified document bytes.
    pub document: Vec<u8>,
}
/// Original request and response, both verified against their stored digests.
pub struct RequestRecord {
    /// Domain owner identity.
    pub owner: String,
    /// SHA-256 of the original request bytes.
    pub fingerprint: Vec<u8>,
    /// Original request bytes for deterministic recovery.
    pub request: Vec<u8>,
    /// Original result bytes for idempotent replay.
    pub receipt: Vec<u8>,
}
impl RequestRecord {
    fn for_write(owner: &str, request: Vec<u8>, receipt: Vec<u8>) -> Self {
        Self {
            owner: owner.to_owned(),
            fingerprint: digest(&request),
            request,
            receipt,
        }
    }
}
impl BackendStorage {
    // Only the closed enum supplies an SQL identifier; all other values are bound.
    fn query(self, template: &'static str) -> sqlx::SqlStr {
        // Audited: every template is a source literal; schema is a closed enum
        // of three ASCII identifiers. Request values only enter bind parameters.
        sqlx::SqlSafeStr::into_sql_str(sqlx::AssertSqlSafe(
            template.replace("{schema}", self.kind.schema()),
        ))
    }
    /// Acquire the existing tenant/domain transaction advisory lock.
    /// `kind` and `key` are adapter-selected lock coordinates, scoped by backend and
    /// transaction tenant. May wait under the transaction budget; SQL/timeout failures
    /// propagate as `PgError`. Settlement by the caller releases the lock.
    pub async fn lock(
        self,
        tx: &mut PgTransaction<'_>,
        kind: &str,
        key: &str,
    ) -> Result<(), PgError> {
        let key = format!("{}:{}:{kind}:{key}", self.kind.schema(), tx.tenant_id());
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2388))")
                    .bind(key)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
    }
    /// Read an aggregate in the transaction tenant, returning `None` when absent.
    /// Rejects an invalid stored revision or document digest with `PgError`.
    /// Does not lock the row; the adapter must arrange concurrency protection.
    pub async fn read(
        self,
        tx: &mut PgTransaction<'_>,
        id: &str,
    ) -> Result<Option<AggregateRecord>, PgError> {
        let (tenant, id) = (tx.tenant_id().to_string(), id.to_owned());
        let query=self.query("SELECT revision,document,digest FROM {schema}.aggregates WHERE tenant_id=$1::uuid AND id=$2");
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(query)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        row.map(|r| {
            Ok(AggregateRecord {
                revision: self
                    .integer("db::read", u64::try_from(r.try_get::<i64, _>("revision")?))?,
                document: self.checked(r.try_get("document")?, r.try_get("digest")?)?,
            })
        })
        .transpose()
    }
    /// Insert when `old` is absent, otherwise compare and swap that storage revision.
    /// Computes the document digest and requires exactly one changed row. Revisions
    /// must fit PostgreSQL `bigint`; conversion, SQL or zero-row CAS failures return
    /// `PgError`. The adapter enforces domain revision progression; no commit occurs.
    pub async fn write(
        self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        old: Option<u64>,
        revision: u64,
        document: Vec<u8>,
    ) -> Result<(), PgError> {
        let (tenant, id, hash) = (tx.tenant_id().to_string(), id.to_owned(), digest(&document));
        let revision = self.integer("db::write", i64::try_from(revision))?;
        let old = self.integer("db::write-old-revision", old.map(i64::try_from).transpose())?;
        let query=self.query(if old.is_some() {
            "UPDATE {schema}.aggregates SET revision=$3,document=$4,digest=$5 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$6"
        } else {
            "INSERT INTO {schema}.aggregates(tenant_id,id,revision,document,digest) SELECT $1::uuid,$2,$3,$4,$5 WHERE $6::bigint IS NULL"
        });
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(query)
                        .bind(tenant)
                        .bind(id)
                        .bind(revision)
                        .bind(document)
                        .bind(hash)
                        .bind(old)
                        .execute(c)
                        .await
                        .map(|r| r.rows_affected())
                })
            })
            .await?;
        if rows != 1 {
            return Err(self.fault("db::write"));
        }
        Ok(())
    }
    /// Read and digest-check the original request and receipt, or return `None` if absent.
    /// Invalid stored digests and SQL failures return `PgError`; no effects are resubmitted.
    /// The adapter must also validate owner, domain encoding and exact replay inputs.
    pub async fn receipt(
        self,
        tx: &mut PgTransaction<'_>,
        id: &str,
    ) -> Result<Option<RequestRecord>, PgError> {
        let (tenant, id) = (tx.tenant_id().to_string(), id.to_owned());
        let query=self.query("SELECT owner,fingerprint,request,receipt,digest FROM {schema}.requests WHERE tenant_id=$1::uuid AND id=$2");
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(query)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        row.map(|r| {
            let fingerprint: Vec<u8> = r.try_get("fingerprint")?;
            Ok(RequestRecord {
                owner: r.try_get("owner")?,
                request: self.checked(r.try_get("request")?, fingerprint.clone())?,
                fingerprint,
                receipt: self.checked(r.try_get("receipt")?, r.try_get("digest")?)?,
            })
        })
        .transpose()
    }
    /// Insert original request/result bytes and their derived digests in the caller transaction.
    /// `id` is the tenant-scoped request key; `owner` is the adapter's aggregate identity.
    /// SQL conflicts/errors propagate; this is not an upsert or automatic replay check.
    /// Caller-owned settlement must include associated aggregate and event writes.
    pub async fn save_receipt(
        self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        owner: &str,
        request: Vec<u8>,
        receipt: Vec<u8>,
    ) -> Result<(), PgError> {
        let record = RequestRecord::for_write(owner, request, receipt);
        let (tenant, id, hash) = (
            tx.tenant_id().to_string(),
            id.to_owned(),
            digest(&record.receipt),
        );
        let query=self.query("INSERT INTO {schema}.requests(tenant_id,id,owner,fingerprint,request,receipt,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)");
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(query)
                    .bind(tenant)
                    .bind(id)
                    .bind(record.owner)
                    .bind(record.fingerprint)
                    .bind(record.request)
                    .bind(record.receipt)
                    .bind(hash)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
    }
    /// Load an immutable record by transaction tenant and adapter-owned owner/kind/key.
    /// Returns `None` when absent; digest mismatch and SQL failures return `PgError`.
    /// Does not decode or authenticate domain content.
    pub async fn immutable(
        self,
        tx: &mut PgTransaction<'_>,
        owner: &str,
        kind: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, PgError> {
        let (tenant, owner, kind, key) = (
            tx.tenant_id().to_string(),
            owner.to_owned(),
            kind.to_owned(),
            key.to_owned(),
        );
        let query=self.query("SELECT document,digest FROM {schema}.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind=$3 AND key=$4");
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(query)
                        .bind(tenant)
                        .bind(owner)
                        .bind(kind)
                        .bind(key)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        row.map(|r| self.checked(r.try_get("document")?, r.try_get("digest")?))
            .transpose()
    }
    /// Insert immutable bytes, or require exact existing bytes for the same owner/kind/key.
    /// A content conflict is a `PgError`; no overwrite occurs. The insert/read runs in
    /// the caller transaction and does not commit; domain validation belongs to the adapter.
    pub async fn freeze(
        self,
        tx: &mut PgTransaction<'_>,
        owner: &str,
        kind: &str,
        key: &str,
        document: Vec<u8>,
    ) -> Result<(), PgError> {
        let (tenant, owner, kind, key, hash) = (
            tx.tenant_id().to_string(),
            owner.to_owned(),
            kind.to_owned(),
            key.to_owned(),
            digest(&document),
        );
        let insert=self.query("INSERT INTO {schema}.immutable(tenant_id,owner,kind,key,document,digest) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING");
        let select=self.query("SELECT document FROM {schema}.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind=$3 AND key=$4");
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(insert)
                    .bind(&tenant)
                    .bind(&owner)
                    .bind(&kind)
                    .bind(&key)
                    .bind(&document)
                    .bind(hash)
                    .execute(&mut *c)
                    .await?;
                let old: Vec<u8> = sqlx::query_scalar(select)
                    .bind(tenant)
                    .bind(owner)
                    .bind(kind)
                    .bind(key)
                    .fetch_one(c)
                    .await?;
                if old != document {
                    return Err(sqlx::Error::Protocol("immutable identity conflict".into()));
                }
                Ok(())
            })
        })
        .await
    }
    /// Read current role privileges, forced RLS and the adapter-selected exact catalog.
    /// Policy/catalog mismatch, invalid catalog JSON and SQL failures return `PgError`.
    /// Does not migrate schemas or grant privileges; the caller owns transaction settlement.
    pub async fn verify(
        self,
        tx: &mut PgTransaction<'_>,
        policy: Admission,
    ) -> Result<(), PgError> {
        let schema = self.kind.schema();
        let (ok, catalog) = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let ok = sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                        .bind(schema)
                        .bind(policy.tables)
                        .bind(policy.update_columns)
                        .fetch_one(&mut *c)
                        .await?;
                    let catalog = sqlx::query_scalar::<_, String>(include_str!("catalog.sql"))
                        .bind(schema)
                        .fetch_one(c)
                        .await?;
                    Ok((ok, catalog))
                })
            })
            .await?;
        let actual: serde_json::Value = self.json("db::verify", serde_json::from_str(&catalog))?;
        let expected: serde_json::Value =
            self.json("db::verify", serde_json::from_str(policy.catalog))?;
        if ok && actual == expected {
            Ok(())
        } else {
            Err(self.fault("db::verify"))
        }
    }
    /// Wrap a domain-authored message and append atomically with business writes.
    /// An existing message is an invariant error, not a replay receipt.
    pub async fn append(
        self,
        writer: &PgOutboxWriter,
        tx: &mut PgTransaction<'_>,
        id: MessageId,
        metadata: MessageMetadata,
        payload: Vec<u8>,
    ) -> Result<(), PgError> {
        let message = PendingMessage::new(MessageEnvelope::new(id, metadata, payload));
        match writer.append(tx, message).await? {
            AppendOutcome::Inserted => Ok(()),
            AppendOutcome::AlreadyPresent => Err(self.fault("event::append")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_write_derives_its_request_fingerprint() {
        let record =
            RequestRecord::for_write("owner", b"original request".to_vec(), b"receipt".to_vec());
        assert_eq!(record.owner, "owner");
        assert_eq!(record.request, b"original request");
        assert_eq!(record.receipt, b"receipt");
        assert_eq!(record.fingerprint, digest(&record.request));
        let other =
            RequestRecord::for_write("owner", b"changed request".to_vec(), b"receipt".to_vec());
        assert_ne!(record.fingerprint, other.fingerprint);
    }
}
