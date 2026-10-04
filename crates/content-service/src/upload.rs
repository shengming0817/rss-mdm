//! Sequential durable upload frontier; unacknowledged file tails are discarded on resume.
use super::*;
use rss_mdm_resource::{Digest as ResourceDigest, Id};
use uuid::Uuid;
/// Immutable physical upload binding; diagnostics never claim a Resource identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub purpose: Purpose,
    pub reference: String,
    pub length: u64,
    pub sha256: [u8; 32],
    pub actor: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "binding",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Purpose {
    Resource(ResourceBinding),
    Diagnostic(crate::diagnostic::Identity),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBinding {
    pub storage_class: StorageClass,
    pub resource: String,
    pub version: String,
    pub variant: String,
    pub platform: rss_mdm_resource::Platform,
    pub architecture: rss_mdm_resource::Architecture,
    pub resource_digest: [u8; 32],
    pub source: Option<rss_mdm_resource::SoftwareSource>,
    pub origin: Option<String>,
}
impl Binding {
    pub fn resource(&self) -> Result<&ResourceBinding, Error> {
        match &self.purpose {
            Purpose::Resource(v) => Ok(v),
            Purpose::Diagnostic(_) => Err(Error::Malformed),
        }
    }
    pub fn class(&self) -> StorageClass {
        match &self.purpose {
            Purpose::Resource(v) => v.storage_class,
            Purpose::Diagnostic(_) => StorageClass::NativeDiagnostic,
        }
    }
    pub fn artifact(&self) -> Result<Artifact, Error> {
        Artifact::new(
            Id::new(&self.reference).map_err(|_| Error::Malformed)?,
            self.length,
            ResourceDigest::from_bytes(self.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    pub id: Uuid,
    pub binding: Binding,
    pub offset: u64,
    pub expires: i64,
    pub complete: bool,
}
pub(super) fn storage_key(actor: &str, id: Uuid) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"rss-mdm.upload/v1\0");
    digest.update(actor.as_bytes());
    digest.update(id.as_bytes());
    let digest = digest.finalize();
    Uuid::from_bytes(digest[..16].try_into().expect("digest prefix"))
}
impl Upload {
    pub(super) fn storage_key(&self) -> Uuid {
        storage_key(&self.binding.actor, self.id)
    }
}
impl Store {
    pub async fn begin(&self, id: Uuid, binding: Binding, now: i64) -> Result<Upload, Error> {
        if id.is_nil()
            || now < 0
            || binding.actor.is_empty()
            || binding.actor.len() > 1024
            || binding.length == 0
            || binding.length > self.config.max_artifact_bytes
            || serde_json::to_vec(&binding)
                .map_err(|_| Error::Metadata)?
                .len()
                > 16384
        {
            return Err(Error::Malformed);
        }
        if matches!(&binding.purpose,Purpose::Resource(r) if r.storage_class==StorageClass::NativeDiagnostic)
        {
            return Err(Error::Malformed);
        }
        self.clean_orphans(now).await?;
        binding.artifact()?;
        let expires = match &binding.purpose {
            Purpose::Diagnostic(i) => i.expires_at,
            Purpose::Resource(_) => now
                .checked_add(self.config.retention_seconds as i64)
                .ok_or(Error::Malformed)?,
        };
        if expires <= now {
            return Err(Error::Malformed);
        }
        let reserved = protected::reservation(&binding)?;
        let key = storage_key(&binding.actor, id);
        let mut tx = self.tx().await?;
        self.quota(&mut tx, 0).await?;
        let old:Option<serde_json::Value>=sqlx::query_scalar("SELECT document FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(self.tenant.to_string()).bind(key).fetch_optional(&mut *tx).await.map_err(|_|storage())?;
        if let Some(old) = old {
            let saved: journal::Saved = self.unsign(&key.to_string(), old)?;
            if saved.upload.binding != binding
                || saved.upload.id != id
                || saved.upload.expires <= now
            {
                return Err(Error::Conflict);
            }
            journal::commit(tx).await?;
            return Ok(saved.upload);
        }
        self.quota(&mut tx, reserved).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_content.uploads WHERE NOT complete AND expires>$1",
        )
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage())?;
        if count >= self.config.max_uploads as i64 {
            return Err(Error::Conflict);
        }
        let upload = Upload {
            id,
            binding,
            offset: 0,
            expires,
            complete: false,
        };
        let saved = journal::Saved {
            upload: upload.clone(),
            pieces: vec![],
        };
        sqlx::query("INSERT INTO mdm_content.uploads(tenant_id,id,document,expires,reserved,complete) VALUES($1::uuid,$2,$3,$4,$5,false)").bind(self.tenant.to_string()).bind(key).bind(self.sign(&key.to_string(),&saved)?).bind(upload.expires).bind(reserved as i64).execute(&mut *tx).await.map_err(|_|storage())?;
        journal::commit(tx).await?;
        Ok(upload)
    }
    pub async fn status(&self, actor: &str, id: Uuid, now: i64) -> Result<Upload, Error> {
        Ok(self.saved(actor, id, now).await?.upload)
    }
    pub async fn append<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        actor: &str,
        id: Uuid,
        offset: u64,
        now: i64,
        body: R,
    ) -> Result<Upload, Error> {
        self.clean_orphans(now).await?;
        let _permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        let deadline = self.deadline()?;
        let (saved, epoch) = self.claim(actor, id, Some(offset), now).await?;
        let key = saved.upload.storage_key();
        let result = tokio::time::timeout_at(
            deadline.instant().into(),
            self.append_claimed(saved, epoch, body, deadline),
        )
        .await
        .map_err(|_| Error::Deadline)
        .and_then(|v| v);
        if result.is_err() {
            let _ = self.release(key, epoch).await;
        }
        result
    }
    async fn append_claimed<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        mut saved: journal::Saved,
        epoch: Uuid,
        mut body: R,
        deadline: Deadline,
    ) -> Result<Upload, Error> {
        use tokio::io::AsyncReadExt;
        use zeroize::Zeroizing;
        let start = saved.upload.offset;
        if start >= saved.upload.binding.length {
            return Err(Error::Conflict);
        }
        let native = saved.upload.binding.class().protected();
        let artifact = saved.upload.binding.artifact()?;
        let key = saved.upload.storage_key();
        let mut buffer = Zeroizing::new(Vec::new());
        if native {
            if let Some(piece) = saved.pieces.first() {
                let bytes = self
                    .backend
                    .read(
                        &piece.coordinate,
                        piece.content,
                        0,
                        piece.content.length,
                        deadline,
                    )
                    .await?;
                buffer = self.plaintext(&bytes, &artifact, saved.upload.binding.class(), start)?;
            }
            saved.pieces.clear();
        } else if saved
            .pieces
            .last()
            .is_some_and(|p| p.length < journal::CHUNK)
        {
            let tail = saved.pieces.pop().ok_or(Error::Invariant)?;
            buffer.extend_from_slice(
                &self
                    .backend
                    .read(
                        &tail.coordinate,
                        tail.content,
                        0,
                        tail.content.length,
                        deadline,
                    )
                    .await?,
            );
        }
        let mut chunk = Zeroizing::new([0; 65536]);
        loop {
            self.check_deadline(deadline)?;
            let n = body.read(&mut chunk[..]).await.map_err(|_| storage())?;
            if n == 0 {
                break;
            }
            saved.upload.offset = saved
                .upload
                .offset
                .checked_add(n as u64)
                .ok_or(Error::Malformed)?;
            if saved.upload.offset > saved.upload.binding.length {
                return Err(Error::Malformed);
            }
            buffer.extend_from_slice(&chunk[..n]);
            if !native && buffer.len() as u64 >= journal::CHUNK {
                let remainder = buffer.split_off(journal::CHUNK as usize);
                let bytes = std::mem::replace(&mut *buffer, remainder);
                let offset = saved.pieces.last().map_or(0, |p| p.offset + p.length);
                saved.pieces.push(
                    self.put_piece(
                        (key, epoch),
                        offset,
                        journal::CHUNK,
                        bytes,
                        saved.upload.expires,
                        deadline,
                    )
                    .await?,
                );
            }
        }
        if saved.upload.offset == start {
            return Err(Error::Malformed);
        }
        if !buffer.is_empty() {
            let offset = if native {
                0
            } else {
                saved.pieces.last().map_or(0, |p| p.offset + p.length)
            };
            let length = buffer.len() as u64;
            let bytes = if native {
                self.seal(&buffer, &artifact, saved.upload.binding.class())?
            } else {
                std::mem::take(&mut *buffer)
            };
            saved.pieces.push(
                self.put_piece(
                    (key, epoch),
                    offset,
                    length,
                    bytes,
                    saved.upload.expires,
                    deadline,
                )
                .await?,
            );
        }
        self.save_frontier(&saved, epoch, deadline).await?;
        Ok(saved.upload)
    }
    pub async fn finish(&self, actor: &str, id: Uuid, now: i64) -> Result<Upload, Error> {
        let old = self.saved(actor, id, now).await?;
        if old.upload.complete {
            return Ok(old.upload);
        }
        let _permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        let deadline = self.deadline()?;
        let (mut saved, epoch) = self.claim(actor, id, None, now).await?;
        let key = saved.upload.storage_key();
        let result=async {
   if saved.upload.offset!=saved.upload.binding.length{return Err(Error::Conflict)}
   let a=saved.upload.binding.artifact()?;let c=saved.upload.binding.class();
   self.check_pieces(&saved.pieces,&a,c,deadline).await?;
   self.check_deadline(deadline)?;let mut tx=self.tx().await?;
   let owns:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND id=$2 AND epoch=$3 AND NOT complete)").bind(self.tenant.to_string()).bind(key).bind(epoch).fetch_one(&mut *tx).await.map_err(|_|storage())?;if !owns{return Err(Error::Conflict)}
   let manifest=journal::Manifest{pieces:saved.pieces.clone()};
   sqlx::query("INSERT INTO mdm_content.manifests(tenant_id,class,sha256,length,document,expires,state) VALUES($1::uuid,$2,$3,$4,$5,$6,'ready') ON CONFLICT(tenant_id,class,sha256,length) DO UPDATE SET expires=EXCLUDED.expires, document=CASE WHEN mdm_content.manifests.state='deleted' THEN EXCLUDED.document ELSE mdm_content.manifests.document END,state='ready' WHERE mdm_content.manifests.state<>'deleting'")
    .bind(self.tenant.to_string()).bind(journal::class(c)).bind(a.digest().bytes().as_slice()).bind(a.length() as i64).bind(self.sign(&self.manifest_key(c,&a),&manifest)?).bind(saved.upload.expires).execute(&mut *tx).await.map_err(|_|storage())?;
   let state:String=sqlx::query_scalar("SELECT state FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 FOR UPDATE").bind(self.tenant.to_string()).bind(journal::class(c)).bind(a.digest().bytes().as_slice()).bind(a.length() as i64).fetch_one(&mut *tx).await.map_err(|_|storage())?;
   if state!="ready"{return Err(Error::Conflict)}saved.upload.complete=true;
   let changed=sqlx::query("UPDATE mdm_content.uploads SET complete=true,document=$4,epoch=NULL,held_until=0 WHERE tenant_id=$1::uuid AND id=$2 AND epoch=$3").bind(self.tenant.to_string()).bind(key).bind(epoch).bind(self.sign(&key.to_string(),&saved)?).execute(&mut *tx).await.map_err(|_|storage())?.rows_affected();if changed!=1{return Err(Error::Conflict)}
   self.check_deadline(deadline)?;journal::commit(tx).await?;Ok(saved.upload)
  }.await;
        if result.is_err() {
            let _ = self.release(key, epoch).await;
        }
        result
    }
}
