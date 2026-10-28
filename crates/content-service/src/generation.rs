//! Storage generation identity is independent of connection credentials and logical content.
use crate::{Error, Storage, journal};
use rss_mdm_native_protection::Protector;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Generation {
    pub id: Uuid,
    pub storage: Storage,
    pub backend_identity: serde_json::Value,
}
impl Generation {
    pub(crate) fn seal(
        &self,
        protector: &Protector,
        tenant: TenantId,
    ) -> Result<serde_json::Value, Error> {
        journal::sign_document(protector, tenant, &format!("generation:{}", self.id), self)
    }
    pub(crate) fn open(
        protector: &Protector,
        tenant: TenantId,
        id: Uuid,
        document: serde_json::Value,
    ) -> Result<Self, Error> {
        let generation: Self =
            journal::verify_document(protector, tenant, &format!("generation:{id}"), document)?;
        if generation.id != id || id.is_nil() {
            return Err(Error::Invariant);
        }
        Ok(generation)
    }
}

impl crate::Store {
    /// Resolve current committed storage at operation entry; the returned snapshot never changes.
    pub(crate) async fn current(&self) -> Result<Self, Error> {
        let mut tx = self.pool.begin().await.map_err(|_| crate::storage())?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','6000',true)")
            .bind(self.tenant.to_string()).execute(&mut *tx).await.map_err(|_|crate::storage())?;
        let (active, revision): (Uuid, i64) = sqlx::query_as(
            "SELECT active_generation,revision FROM mdm_content.settings WHERE tenant_id=$1::uuid",
        )
        .bind(self.tenant.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| crate::storage())?;
        tx.rollback().await.map_err(|_| crate::storage())?;
        if active == self.generation
            && revision == self.storage_revision
            && self.backend.available()
        {
            return Ok(self.clone());
        }
        let mut cached = self.current_cache.lock().await;
        if let Some(cached) = &*cached
            && cached.id == active
            && cached.revision == revision
            && cached.backend.available()
        {
            return Ok(Self {
                generation: active,
                storage_revision: revision,
                config: cached.config.clone(),
                backend: cached.backend.clone(),
                ..self.clone()
            });
        }
        let opened = Self::open(
            self.protection.clone(),
            &self.config,
            &self.tenant.to_string(),
            self.timer.clone(),
            self.pool.clone(),
        )
        .await?;
        if !opened.backend.available() {
            return Err(Error::Storage);
        }
        let mut tx = opened.tx().await?;
        sqlx::query("SELECT mdm_content.observe_generation($1)")
            .bind(opened.generation)
            .execute(&mut *tx)
            .await
            .map_err(|_| crate::storage())?;
        crate::journal::commit(tx).await?;
        *cached = Some(CachedGeneration {
            id: opened.generation,
            revision: opened.storage_revision,
            config: opened.config.clone(),
            backend: opened.backend.clone(),
        });
        Ok(Self {
            generation: opened.generation,
            storage_revision: opened.storage_revision,
            config: opened.config.clone(),
            backend: opened.backend.clone(),
            ..self.clone()
        })
    }
}

impl crate::Store {
    pub async fn active_s3_revision(&self) -> Result<Option<i64>, Error> {
        let current = self.current().await?;
        let _admission = current.admit(crate::gate::Kind::Read).await?;
        match current.config.storage {
            crate::Storage::S3(value) => Ok(Some(
                i64::try_from(value.revision).map_err(|_| Error::Invariant)?,
            )),
            crate::Storage::Volume { .. } => Ok(None),
        }
    }
}

impl crate::Store {
    /// A persisted exact marker distinguishes a changed provider behind an unchanged URL.
    /// Only an uninitialized generation may create it; a missing established marker is fatal.
    pub(crate) async fn verify_marker(&self) -> Result<(), Error> {
        use sha2::{Digest, Sha256};
        let mut tx = self.tx().await?;
        let marker: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT marker FROM mdm_content.generations WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(self.tenant.to_string())
        .bind(self.generation)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| crate::storage())?;
        crate::journal::commit(tx).await?;
        let bytes = Sha256::digest(format!(
            "rss-mdm-storage-marker:{}:{}",
            self.tenant, self.generation
        ))
        .to_vec();
        let content = rss_mdm_content_s3::Content {
            length: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        };
        let id = self.generation;
        let mut location = match marker {
            Some(document) => crate::location::Location::open(
                &self.protection,
                self.tenant,
                self.generation,
                id,
                content,
                document,
            )?,
            None => crate::location::Location {
                generation: self.generation,
                piece: id,
                content,
                intent: self.backend.intent_in(self.generation, id, content)?,
                coordinate: None,
            },
        };
        let deadline = self.deadline()?;
        if location.coordinate.is_none() {
            location.coordinate = self
                .backend
                .recover(&location.intent, content, deadline)
                .await?;
            // Volume intent recovery alone cannot prove publication: read first, then complete
            // the original create-only write while the marker has never been established.
            let exists = if let Some(c) = &location.coordinate {
                self.backend
                    .read(c, content, 0, content.length, deadline, ())
                    .await
                    .is_ok()
            } else {
                false
            };
            if !exists {
                location.coordinate = Some(
                    self.backend
                        .write(&location.intent, content, bytes, deadline, ())
                        .await
                        .map_err(|e| match e {
                            crate::backend::WriteFailure::NotWritten(e)
                            | crate::backend::WriteFailure::Unresolved(e) => e,
                        })?,
                );
            }
            let exact = location.coordinate.as_ref().ok_or(Error::CommitUnknown)?;
            self.backend
                .read(exact, content, 0, content.length, deadline, ())
                .await?;
            let mut tx = self.tx().await?;
            sqlx::query("SELECT mdm_content.record_marker($1,$2)")
                .bind(self.generation)
                .bind(location.seal(&self.protection, self.tenant)?)
                .execute(&mut *tx)
                .await
                .map_err(|_| crate::storage())?;
            crate::journal::commit(tx).await?;
        } else {
            self.backend
                .read(
                    location.coordinate.as_ref().ok_or(Error::Invariant)?,
                    content,
                    0,
                    content.length,
                    deadline,
                    (),
                )
                .await?;
        }
        Ok(())
    }
}

pub(crate) struct CachedGeneration {
    id: Uuid,
    revision: i64,
    config: crate::Config,
    backend: crate::backend::Backend,
}
