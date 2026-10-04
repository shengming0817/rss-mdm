//! Protected diagnostic storage and immutable associations on the caller's transaction.
//! ref: sqlx sqlx-core/src/transaction.rs@003b698e99e024f3621b8043a2426fde5b741171.
use crate::{Artifact, Binding, Error, Purpose, StorageClass, Store, Verified};
use rss_mdm_resource::{Digest, Id};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
/// Immutable native provenance; no device paths, payloads or Resource identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub operation: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub input_version: String,
    pub input_digest: [u8; 32],
    pub sources_digest: [u8; 32],
    pub accepted_at: i64,
    pub expires_at: i64,
}
/// Restricted immutable read projection, never a storage path or credential.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub reference: String,
    pub length: u64,
    pub sha256: String,
    pub expires_at: i64,
}
impl Metadata {
    pub fn artifact(&self) -> Result<Artifact, Error> {
        Artifact::new(
            Id::new(&self.reference).map_err(|_| Error::Malformed)?,
            self.length,
            Digest::parse(&self.sha256).map_err(|_| Error::Malformed)?,
        )
        .map_err(|_| Error::Malformed)
    }
}
/// Read-only storage capability for the independently assembled execution Queries owner.
#[derive(Clone)]
pub struct Reader(Arc<Store>);
impl Reader {
    pub async fn verify(&self, artifact: &Artifact) -> Result<Verified, Error> {
        self.0
            .verify_class(artifact, StorageClass::NativeDiagnostic)
            .await
    }
}
impl Store {
    pub fn diagnostic_reader(self: &Arc<Self>) -> Reader {
        Reader(self.clone())
    }
    /// Resume the same physical upload. All file work must be called outside PG transactions.
    /// The returned shared file pin remains owned by the caller until association settlement.
    pub async fn promote_diagnostic(
        self: &Arc<Self>,
        identity: &Identity,
        bytes: &[u8],
        now: i64,
    ) -> Result<Verified, Error> {
        if identity.operation.is_nil()
            || identity.registration.is_nil()
            || identity.generation <= 0
            || identity.accepted_at < 0
            || identity.expires_at <= now
            || identity.input_version.is_empty()
            || bytes.is_empty()
            || bytes.len() > 16 * 1024 * 1024
        {
            return Err(Error::Malformed);
        }
        let encoded =
            serde_json::to_vec(&("rss-mdm.diagnostic/v1", self.tenant.to_string(), identity))
                .map_err(|_| Error::Malformed)?;
        let key = Sha256::digest(encoded);
        let id = Uuid::from_bytes(key[..16].try_into().map_err(|_| Error::Malformed)?);
        let reference = format!("diagnostic-{id}");
        let digest = Digest::of(bytes);
        let binding = Binding {
            purpose: Purpose::Diagnostic(identity.clone()),
            reference,
            length: bytes.len() as u64,
            sha256: digest.bytes(),
            actor: format!("diagnostic:{}", self.tenant),
        };
        let artifact = binding.artifact()?;
        let actor = binding.actor.clone();
        // A resumed session never gets a new retention window.
        let upload = self.begin(id, binding, now).await?;
        if !upload.complete {
            let offset = usize::try_from(upload.offset).map_err(|_| Error::Metadata)?;
            let rest = bytes.get(offset..).ok_or(Error::Metadata)?;
            if !rest.is_empty() {
                self.append(&actor, id, upload.offset, now, rest).await?;
            }
            self.finish(&actor, id, now).await?;
        }
        self.verify_class(&artifact, StorageClass::NativeDiagnostic)
            .await
    }
}
// Command's manifest capability remains read-only. This lock serializes association
// with the Flow-owned GC barrier without requiring SELECT FOR SHARE's UPDATE grant.
pub(super) async fn association_lock(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    digest: [u8; 32],
    length: u64,
) -> Result<(), sqlx::Error> {
    let key = format!(
        "content.diagnostic:{}:{}:{length}",
        tenant,
        crate::hex(digest)
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2664))")
        .bind(key)
        .execute(c)
        .await?;
    Ok(())
}
/// Append on the original execution transaction. This function never commits it.
pub async fn record_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    identity: &Identity,
    artifact: &Artifact,
) -> Result<(Metadata, bool), Error> {
    association_lock(c, tenant, artifact.digest().bytes(), artifact.length())
        .await
        .map_err(|e| crate::journal::pg_error(concat!(file!(), ":", line!()), e))?;
    let ready:Option<String>=sqlx::query_scalar("SELECT state FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND class='native_diagnostic' AND sha256=$2 AND length=$3")
      .bind(tenant.to_string()).bind(artifact.digest().bytes().as_slice()).bind(artifact.length() as i64).fetch_optional(&mut *c).await.map_err(|e|crate::journal::pg_error(concat!(file!(), ":", line!()),e))?;
    if ready.as_deref() != Some("ready") {
        return Err(Error::Conflict);
    }
    let binding = serde_json::to_value(identity).map_err(|_| Error::Malformed)?;
    let fresh = sqlx::query("INSERT INTO mdm_content.diagnostic_artifacts(tenant_id,operation,registration,generation,identity,reference,length,sha256,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,operation) DO NOTHING")
        .bind(tenant.to_string()).bind(identity.operation).bind(identity.registration).bind(identity.generation)
        .bind(&binding).bind(artifact.reference().as_str()).bind(artifact.length() as i64).bind(artifact.digest().bytes().as_slice()).bind(identity.expires_at)
        .execute(&mut *c).await.map_err(|e|crate::journal::pg_error(concat!(file!(), ":", line!()),e))?.rows_affected() == 1;
    let row = sqlx::query("SELECT identity,reference,length,sha256,expires_at FROM mdm_content.diagnostic_artifacts WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(tenant.to_string()).bind(identity.operation).fetch_one(c).await.map_err(|e|crate::journal::pg_error(concat!(file!(), ":", line!()),e))?;
    if row
        .try_get::<serde_json::Value, _>("identity")
        .map_err(|e| crate::journal::pg_error(concat!(file!(), ":", line!()), e))?
        != binding
    {
        return Err(Error::Conflict);
    }
    let metadata = metadata(row)?;
    if metadata.artifact()? != *artifact {
        return Err(Error::Conflict);
    }
    Ok((metadata, fresh))
}
pub async fn read_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: Uuid,
    generation: i64,
) -> Result<Option<Metadata>, Error> {
    let row = sqlx::query("SELECT reference,length,sha256,expires_at FROM mdm_content.diagnostic_artifacts WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND generation=$4 AND expires_at>extract(epoch FROM clock_timestamp())")
        .bind(tenant.to_string()).bind(operation).bind(registration).bind(generation).fetch_optional(c).await.map_err(|e|crate::journal::pg_error(concat!(file!(), ":", line!()),e))?;
    row.map(metadata).transpose()
}
fn metadata(row: sqlx::postgres::PgRow) -> Result<Metadata, Error> {
    Ok(Metadata {
        reference: row
            .try_get("reference")
            .map_err(|e| crate::journal::pg_error(concat!(file!(), ":", line!()), e))?,
        length: u64::try_from(
            row.try_get::<i64, _>("length")
                .map_err(|e| crate::journal::pg_error(concat!(file!(), ":", line!()), e))?,
        )
        .map_err(|_| Error::Metadata)?,
        sha256: crate::hex(
            row.try_get::<Vec<u8>, _>("sha256")
                .map_err(|e| crate::journal::pg_error(concat!(file!(), ":", line!()), e))?
                .try_into()
                .map_err(|_| Error::Metadata)?,
        ),
        expires_at: row
            .try_get("expires_at")
            .map_err(|e| crate::journal::pg_error(concat!(file!(), ":", line!()), e))?,
    })
}
