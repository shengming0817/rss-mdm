//! Durable control plane. Provider requests never run while a transaction is open.
//! ref: sqlx sqlx-core/src/transaction.rs (0.8.6).
use super::*;
use backend::Coordinate;
use rss_mdm_content_s3::Content;
use rss_mdm_native_protection::ProtectionContext;
use sqlx::{Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;
pub(super) const CHUNK: u64 = 128 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Piece {
    pub id: Uuid,
    pub offset: u64,
    pub length: u64,
    pub content: Content,
    pub coordinate: Coordinate,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    pub upload: Upload,
    pub pieces: Vec<Piece>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub pieces: Vec<Piece>,
    pub inspections: std::collections::BTreeMap<
        crate::installer::Kind,
        rss_mdm_software_service::management::content::InstallerInspection,
    >,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    value: serde_json::Value,
    mac: Vec<u8>,
}
pub(super) fn pg_error(operation: &str, error: sqlx::Error) -> Error {
    let (kind, code) = match &error {
        sqlx::Error::Database(e) => ("database", e.code().map(|s| s.into_owned())),
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => ("decode", None),
        sqlx::Error::RowNotFound => ("missing", None),
        sqlx::Error::PoolTimedOut => ("pool_timeout", None),
        sqlx::Error::PoolClosed => ("pool_closed", None),
        _ => ("storage", None),
    };
    // Query text, values and driver messages may contain protected material.
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_content_pg_error","operation":operation,"kind":kind,"sqlstate":code})
    );
    storage()
}
pub(super) fn class(c: StorageClass) -> &'static str {
    match c {
        StorageClass::Artifact => "artifact",
        StorageClass::NativeConfiguration => "native_configuration",
    }
}
pub(super) fn encode<T: Serialize>(v: &T) -> Result<serde_json::Value, Error> {
    serde_json::to_value(v).map_err(|_| Error::Metadata)
}
pub(super) fn decode<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, Error> {
    serde_json::from_value(v).map_err(|_| Error::Metadata)
}
pub(super) async fn commit(tx: Transaction<'_, Postgres>) -> Result<(), Error> {
    tx.commit().await.map_err(|_| Error::CommitUnknown)
}
impl Store {
    pub(super) fn sign<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<serde_json::Value, Error> {
        sign_document(&self.protection, self.tenant, key, value)
    }
    pub(super) fn unsign<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        v: serde_json::Value,
    ) -> Result<T, Error> {
        verify_document(&self.protection, self.tenant, key, v)
    }
    pub(super) fn manifest_key(&self, c: StorageClass, a: &Artifact) -> String {
        format!("{}:{}:{}", class(c), hex(a.digest().bytes()), a.length())
    }
    pub(super) async fn tx(&self) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *tx)
            .await
            .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','6000',true),set_config('lock_timeout','6000',true)")
   .bind(self.tenant.to_string()).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        if let Storage::S3(s3) = &self.config.storage {
            crate::connections::require_live(&mut tx, self.tenant, s3.revision).await?;
        }
        Ok(tx)
    }
    pub(super) async fn quota(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        extra: u64,
    ) -> Result<(), Error> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2664))")
            .bind(self.tenant.to_string())
            .execute(&mut **tx)
            .await
            .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        // Active sessions reserve the remaining content plus one tail rewrite. Unknown/orphan writes
        // remain charged, including after expiry; only exact confirmed reclamation releases bytes.
        let used:i64=sqlx::query_scalar("WITH physical AS (SELECT owner,sum((content->>'length')::bigint) AS bytes FROM mdm_content.objects o WHERE state<>'deleted' AND NOT EXISTS(SELECT 1 FROM mdm_content.manifests m WHERE m.state<>'deleted' AND m.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id))) GROUP BY owner), live AS (SELECT u.id,greatest(u.reserved,coalesce(p.bytes,0)) AS bytes FROM mdm_content.uploads u LEFT JOIN physical p ON p.owner=u.id WHERE NOT u.complete OR u.epoch IS NOT NULL) SELECT (coalesce((SELECT sum(bytes) FROM live),0)+coalesce((SELECT sum(p.bytes) FROM physical p WHERE NOT EXISTS(SELECT 1 FROM live l WHERE l.id=p.owner)),0)+coalesce((SELECT sum(reserved) FROM mdm_content.pins),0))::bigint")
   .fetch_one(&mut **tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        if used < 0
            || (used as u64)
                .checked_add(extra)
                .is_none_or(|n| n > self.config.max_temporary_bytes)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(super) async fn journal_admit(&self) -> Result<(), Error> {
        let mut tx = self.tx().await?;
        let identity = serde_json::json!({"protection":self.protection.fingerprint_id(),"backend":self.backend.identity()?});
        sqlx::query("INSERT INTO mdm_content.settings(tenant_id,identity) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(self.tenant.to_string()).bind(&identity).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        let old: serde_json::Value = sqlx::query_scalar(
            "SELECT identity FROM mdm_content.settings WHERE tenant_id=$1::uuid",
        )
        .bind(self.tenant.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        if old != identity {
            return Err(Error::Configuration);
        }
        commit(tx).await
    }
    pub(super) async fn saved(&self, actor: &str, id: Uuid, now: i64) -> Result<Saved, Error> {
        let key = upload::storage_key(actor, id);
        let mut tx = self.tx().await?;
        let row:Option<serde_json::Value>=sqlx::query_scalar("SELECT document FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND id=$2 AND expires>$3")
   .bind(self.tenant.to_string()).bind(key).bind(now).fetch_optional(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        let saved: Saved = self.unsign(&key.to_string(), row.ok_or(Error::Conflict)?)?;
        if saved.upload.id != id || saved.upload.binding.actor != actor {
            return Err(Error::Metadata);
        }
        commit(tx).await?;
        Ok(saved)
    }
    pub(super) async fn claim(
        &self,
        actor: &str,
        id: Uuid,
        offset: Option<u64>,
        now: i64,
        epoch: Uuid,
        budget: UploadBudget,
    ) -> Result<(Saved, Uuid), Error> {
        let key = upload::storage_key(actor, id);
        let mut tx = self.tx().await?;
        let row=sqlx::query("SELECT document,held_until,epoch FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND id=$2 AND expires>$3 FOR UPDATE")
   .bind(self.tenant.to_string()).bind(key).bind(now).fetch_optional(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?.ok_or(Error::Conflict)?;
        let saved: Saved = self.unsign(
            &key.to_string(),
            row.try_get("document")
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?,
        )?;
        if saved.upload.id != id || saved.upload.binding.actor != actor {
            return Err(Error::Metadata);
        }
        if row
            .try_get::<i64, _>("held_until")
            .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?
            > now
            || saved.upload.complete
            || (saved.upload.offset == saved.upload.binding.length
                && row
                    .try_get::<Option<Uuid>, _>("epoch")
                    .map_err(|_| storage())?
                    .is_some())
            || offset.is_some_and(|o| o != saved.upload.offset)
        {
            return Err(Error::Conflict);
        }
        sqlx::query("UPDATE mdm_content.uploads SET epoch=$3,held_until=ceil(extract(epoch FROM clock_timestamp())+$4)::bigint WHERE tenant_id=$1::uuid AND id=$2").bind(self.tenant.to_string()).bind(key).bind(epoch).bind(budget.remaining().as_secs_f64()).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await?;
        Ok((saved, epoch))
    }
    pub(super) async fn claim_parse(
        &self,
        actor: &str,
        id: Uuid,
        now: i64,
        epoch: Uuid,
        budget: UploadBudget,
        length: u64,
    ) -> Result<(), Error> {
        let key = upload::storage_key(actor, id);
        let mut tx = self.tx().await?;
        self.quota(&mut tx, length).await?;
        let changed = sqlx::query("UPDATE mdm_content.uploads SET epoch=$3,reserved=$6,held_until=ceil(extract(epoch FROM clock_timestamp())+$4)::bigint WHERE tenant_id=$1::uuid AND id=$2 AND complete AND expires>$5 AND epoch IS NULL")
            .bind(self.tenant.to_string()).bind(key).bind(epoch).bind(budget.remaining().as_secs_f64()).bind(now).bind(length as i64).execute(&mut *tx).await.map_err(|_| storage())?.rows_affected();
        if changed != 1 {
            return Err(Error::Conflict);
        }
        commit(tx).await
    }
    pub(super) async fn release(
        &self,
        key: Uuid,
        epoch: Uuid,
        temporary: u64,
    ) -> Result<(), Error> {
        let mut tx = self.tx().await?;
        let document: Option<serde_json::Value> = sqlx::query_scalar("SELECT document FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND id=$2 AND epoch=$3 FOR UPDATE")
            .bind(self.tenant.to_string()).bind(key).bind(epoch).fetch_optional(&mut *tx).await.map_err(|_| storage())?;
        let Some(document) = document else {
            return commit(tx).await;
        };
        let saved: Saved = self.unsign(&key.to_string(), document)?;
        let baseline = protected::reservation(&saved.upload.binding)?;
        sqlx::query("UPDATE mdm_content.uploads SET held_until=0,epoch=NULL,reserved=greatest($5,reserved-$4) WHERE tenant_id=$1::uuid AND id=$2 AND epoch=$3").bind(self.tenant.to_string()).bind(key).bind(epoch).bind(temporary as i64).bind(baseline as i64).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await
    }
    pub(super) async fn put_piece(
        &self,
        lease: (Uuid, Uuid, Arc<crate::budget::UploadLease>),
        offset: u64,
        length: u64,
        bytes: Vec<u8>,
        expires: i64,
        deadline: Deadline,
    ) -> Result<Piece, Error> {
        let (owner, epoch, capacity) = lease;
        self.check_deadline(deadline)?;
        let id = Uuid::new_v4();
        let ((bytes, content), _work) = crate::reader::blocking(capacity.clone(), move || {
            let content = Content {
                length: bytes.len() as u64,
                sha256: Sha256::digest(&bytes).into(),
            };
            (bytes, content)
        })
        .await
        .map_err(|_| storage())?;
        self.check_deadline(deadline)?;
        let intent = self.backend.intent(id, content)?;
        let mut tx = self.tx().await?;
        self.quota(&mut tx, 0).await?;
        let extra: i64 = sqlx::query_scalar(
            r#"SELECT (greatest(u.reserved, p.bytes + $2::bigint)
                      - greatest(u.reserved, p.bytes))::bigint
               FROM mdm_content.uploads u
               CROSS JOIN LATERAL (
                   SELECT coalesce(sum((o.content->>'length')::bigint), 0) AS bytes
                   FROM mdm_content.objects o
                   WHERE o.owner=u.id AND o.state<>'deleted'
                     AND NOT EXISTS (
                         SELECT 1 FROM mdm_content.manifests m
                         WHERE m.state<>'deleted'
                           AND m.document->'value'->'pieces' @>
                               jsonb_build_array(jsonb_build_object('id',o.id))
                     )
               ) p
               WHERE u.id=$1"#,
        )
        .bind(owner)
        .bind(content.length as i64)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        self.quota(&mut tx, extra as u64).await?;
        let owns:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND id=$2 AND epoch=$3 AND NOT complete)").bind(self.tenant.to_string()).bind(owner).bind(epoch).fetch_one(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        if !owns {
            return Err(Error::Conflict);
        }
        sqlx::query("INSERT INTO mdm_content.objects(tenant_id,id,owner,content,intent,expires,state) VALUES($1::uuid,$2,$3,$4,$5,$6,'pending')")
   .bind(self.tenant.to_string()).bind(id).bind(owner).bind(encode(&content)?).bind(encode(&intent)?).bind(expires).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await?;
        let coordinate = match self
            .backend
            .write(&intent, content, bytes, deadline, capacity.clone())
            .await
        {
            Ok(coordinate) => coordinate,
            Err(backend::WriteFailure::Unresolved(error)) => return Err(error),
            Err(backend::WriteFailure::NotWritten(error)) => {
                // Only the completed provider call can prove non-publication. Missing
                // recovery or a dropped future never reaches this settlement path.
                let mut tx = self.tx().await?;
                sqlx::query("UPDATE mdm_content.objects SET state='deleted' WHERE tenant_id=$1::uuid AND id=$2 AND coordinate IS NULL AND state IN ('pending','deleting')")
                    .bind(self.tenant.to_string()).bind(id).execute(&mut *tx).await
                    .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
                commit(tx).await?;
                return Err(error);
            }
        };
        // Preserve the exact version even if subsequent verification fails.
        let mut tx = self.tx().await?;
        sqlx::query(
            "UPDATE mdm_content.objects SET coordinate=$3 WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(self.tenant.to_string())
        .bind(id)
        .bind(encode(&coordinate)?)
        .execute(&mut *tx)
        .await
        .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        commit(tx).await?;
        self.backend
            .read(&coordinate, content, 0, content.length, deadline, capacity)
            .await?;
        let mut tx = self.tx().await?;
        sqlx::query("UPDATE mdm_content.objects SET state='ready' WHERE tenant_id=$1::uuid AND id=$2 AND state='pending'").bind(self.tenant.to_string()).bind(id).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await?;
        Ok(Piece {
            id,
            offset,
            length,
            content,
            coordinate,
        })
    }
    pub(super) async fn save_frontier(
        &self,
        saved: &Saved,
        epoch: Uuid,
        deadline: Deadline,
        commit_started: &std::sync::atomic::AtomicBool,
    ) -> Result<(), Error> {
        self.check_deadline(deadline)?;
        let mut tx = self.tx().await?;
        let count=sqlx::query("UPDATE mdm_content.uploads SET document=$4,held_until=0,epoch=NULL WHERE tenant_id=$1::uuid AND id=$2 AND epoch=$3 AND NOT complete")
   .bind(self.tenant.to_string()).bind(saved.upload.storage_key()).bind(epoch).bind(self.sign(&saved.upload.storage_key().to_string(),saved)?).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?.rows_affected();
        if count != 1 {
            return Err(Error::Conflict);
        }
        let pieces = saved.pieces.iter().map(|p| p.id).collect::<Vec<_>>();
        sqlx::query("UPDATE mdm_content.objects SET expires=0 WHERE tenant_id=$1::uuid AND owner=$2 AND state='ready' AND NOT(id=ANY($3))")
         .bind(self.tenant.to_string()).bind(saved.upload.storage_key()).bind(pieces).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        self.check_deadline(deadline)?;
        commit_started.store(true, std::sync::atomic::Ordering::Release);
        commit(tx).await
    }
    pub(super) fn check_deadline(&self, d: Deadline) -> Result<(), Error> {
        if self.timer.now() >= d.instant() {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    pub(super) async fn pin(
        &self,
        a: &Artifact,
        c: StorageClass,
        deadline: Deadline,
        reserved: u64,
    ) -> Result<(Manifest, Uuid), Error> {
        self.check_deadline(deadline)?;
        let mut tx = self.tx().await?;
        self.quota(&mut tx, reserved).await?;
        let row:Option<serde_json::Value>=sqlx::query_scalar("SELECT document FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND state='ready' FOR UPDATE")
   .bind(self.tenant.to_string()).bind(class(c)).bind(a.digest().bytes().as_slice()).bind(a.length() as i64).fetch_optional(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        let manifest = self.unsign(&self.manifest_key(c, a), row.ok_or(Error::Invariant)?)?;
        let id = Uuid::new_v4();
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        let expires = now
            .checked_add(
                deadline
                    .instant()
                    .saturating_duration_since(self.timer.now())
                    .as_secs() as i64
                    + 1,
            )
            .ok_or(Error::Deadline)?;
        sqlx::query("INSERT INTO mdm_content.pins(tenant_id,id,class,sha256,length,expires,reserved) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)").bind(self.tenant.to_string()).bind(id).bind(class(c)).bind(a.digest().bytes().as_slice()).bind(a.length() as i64).bind(expires).bind(reserved as i64).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await?;
        Ok((manifest, id))
    }
    pub(super) async fn unpin(&self, id: Uuid) -> Result<(), Error> {
        let mut tx = self.tx().await?;
        sqlx::query("DELETE FROM mdm_content.pins WHERE tenant_id=$1::uuid AND id=$2")
            .bind(self.tenant.to_string())
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        commit(tx).await
    }
}

pub(super) fn verify_document<T: serde::de::DeserializeOwned>(
    protection: &rss_mdm_native_protection::Protector,
    tenant: rss_request_context::TenantId,
    key: &str,
    v: serde_json::Value,
) -> Result<T, Error> {
    let signed: Signed = decode(v)?;
    let aad = ProtectionContext::new(tenant, key, "content.journal/v1", 1)
        .map_err(|_| Error::Metadata)?
        .derive();
    let mac = protection
        .mac(
            &serde_json::to_vec(&signed.value).map_err(|_| Error::Metadata)?,
            &aad,
        )
        .map_err(|_| Error::Metadata)?;
    if !bool::from(mac.as_slice().ct_eq(&signed.mac)) {
        return Err(Error::Metadata);
    }
    decode(signed.value)
}

pub(super) fn sign_document<T: Serialize>(
    protection: &rss_mdm_native_protection::Protector,
    tenant: rss_request_context::TenantId,
    key: &str,
    value: &T,
) -> Result<serde_json::Value, Error> {
    let value = encode(value)?;
    let aad = ProtectionContext::new(tenant, key, "content.journal/v1", 1)
        .map_err(|_| Error::Metadata)?
        .derive();
    let mac = protection
        .mac(
            &serde_json::to_vec(&value).map_err(|_| Error::Metadata)?,
            &aad,
        )
        .map_err(|_| Error::Metadata)?;
    encode(&Signed {
        value,
        mac: mac.to_vec(),
    })
}
