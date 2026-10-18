use crate::setup::{
    Error, Result,
    providers::storage::{Profile, Workload},
};
use rss_mdm_content_service::connections as domain;
use rss_mdm_native_protection::Protector;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use std::path::{Path, PathBuf};
use uuid::Uuid;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    kind: String,
    endpoint: String,
    region: String,
    bucket: String,
    namespace: String,
    credentials_reference: String,
    access_key_file: PathBuf,
    secret_key_file: PathBuf,
    session_token_file: Option<PathBuf>,
    private_ca_file: Option<PathBuf>,
    max_concurrent: usize,
    connect_seconds: u64,
}
pub(super) struct Request<'a> {
    pub directory: &'a Path,
    pub profile: Option<&'a Profile>,
    pub operation: Uuid,
    pub expires: Option<i64>,
    pub generate: bool,
}
pub(super) async fn import(
    c: &mut PgConnection,
    runtime: &mut Value,
    protection: &Protector,
    input: Request<'_>,
) -> Result<()> {
    if runtime["content"].is_null() || runtime["content"]["storage"]["kind"] == "volume" {
        return Ok(());
    }
    let legacy: Legacy =
        serde_json::from_value(runtime["content"]["storage"].clone()).map_err(|_| Error::Input)?;
    let profile = input.profile.ok_or(Error::Input)?;
    if legacy.kind != "s3"
        || legacy.endpoint != profile.endpoint
        || legacy.region != profile.region
        || legacy.bucket != profile.bucket
        || legacy.namespace != profile.namespace
        || legacy.credentials_reference.is_empty()
    {
        return Err(Error::Conflict);
    }
    let ca = crate::config::read(&profile.ca_file, 1024 * 1024, false).map_err(|_| Error::Input)?;
    if let Some(path) = legacy.private_ca_file {
        if *crate::config::read(&path, 1024 * 1024, false).map_err(|_| Error::Input)? != *ca {
            return Err(Error::Conflict);
        }
    }
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
    let source = if input.generate {
        domain::Source::Generate
    } else {
        domain::Source::Import {
            access_key: crate::config::secret(&legacy.access_key_file)
                .map_err(|_| Error::Corrupt)?,
            secret_key: crate::config::secret(&legacy.secret_key_file)
                .map_err(|_| Error::Corrupt)?,
            session_token: legacy
                .session_token_file
                .as_ref()
                .map(|p| crate::config::secret(p).map_err(|_| Error::Corrupt))
                .transpose()?,
            expires_at: input.expires,
        }
    };
    let metadata = domain::Metadata {
        endpoint: profile.endpoint.clone(),
        region: profile.region.clone(),
        bucket: profile.bucket.clone(),
        namespace: profile.namespace.clone(),
        private_ca: ca.to_vec(),
    };
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let receipt = domain::prepare(
        &mut tx,
        id,
        input.operation,
        &domain::Request {
            expected_revision: 0,
            profile: profile.id.clone(),
            source,
        },
        "offline-v4-transfer",
        protection,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    domain::bind_metadata(&mut tx, id, input.operation, &metadata)
        .await
        .map_err(|_| Error::Conflict)?;
    let pending = domain::pending(&mut tx, id, input.operation, protection)
        .await
        .map_err(|_| Error::Corrupt)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let workload = Workload {
        create_identity: pending.generated,
        access: pending.credentials.access_key,
        secret: pending.credentials.secret_key,
        token: pending.credentials.session_token,
    };
    let evidence = crate::setup::providers::storage::prepare(
        input.directory,
        profile,
        Uuid::parse_str(tenant).map_err(|_| Error::Input)?,
        input.operation,
        &workload,
    )
    .await?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    domain::qualify(
        &mut tx,
        id,
        input.operation,
        &metadata,
        evidence.qualified_at,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    runtime["content"]["storage"] = json!({"kind":"s3","revision":receipt.revision,"max_concurrent":legacy.max_concurrent,"connect_seconds":legacy.connect_seconds});
    Ok(())
}

struct BackupSecrets {
    access: zeroize::Zeroizing<String>,
    secret: zeroize::Zeroizing<String>,
    token: Option<zeroize::Zeroizing<String>>,
}
impl rss_mdm_content_s3::Secrets for BackupSecrets {
    fn resolve(
        &self,
        reference: &str,
    ) -> rss_mdm_content_s3::Result<rss_mdm_content_s3::Credentials> {
        if reference != "transfer-backup" {
            return Err(rss_mdm_content_s3::Error::Configuration);
        }
        rss_mdm_content_s3::Credentials::new(
            self.access.to_string(),
            self.secret.to_string(),
            self.token.as_ref().map(|v| v.to_string()),
            None,
        )
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedObject {
    record: rss_mdm_content_service::backup::ObjectRecord,
    copied_object: Option<rss_mdm_content_s3::Object>,
    body_file: Option<String>,
}
fn budget(bytes: u64) -> Result<rss_mdm_content_s3::Budget> {
    rss_mdm_content_s3::Budget::new(
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        std::time::Duration::from_secs(300),
        std::time::Duration::from_secs(10),
        bytes,
        1024,
    )
    .map_err(|_| Error::Input)
}
/// 保存确切版本的物理字节；未确认的原写入仍明确记录为 unresolved。
pub(super) async fn backup(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    runtime: &Value,
) -> Result<()> {
    use futures::StreamExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;
    if runtime["content"]["storage"]["kind"] != "s3" {
        return Ok(());
    }
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
    let store = connect(runtime).await?;
    let mut copy = runtime.clone();
    let protection = super::materials::protection(&mut copy)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    rss_mdm_content_service::backup::validate_catalog(&mut tx, id, &protection)
        .await
        .map_err(|_| Error::Corrupt)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    let root = journal.path(&format!("s3-{}", host.simple()))?;
    let objects = crate::setup::local::Journal::open(&root)?;
    let mut after = None;
    let mut copied = 0u64;
    let mut unresolved = 0u64;
    loop {
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        let page = rss_mdm_content_service::backup::s3_page(&mut tx, id, after)
            .await
            .map_err(|_| Error::Corrupt)?;
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if page.is_empty() {
            break;
        }
        for record in page {
            after = Some(record.id);
            let name = format!("{}.json", record.id.simple());
            if let Some(previous) = objects.load::<SavedObject>(&name)? {
                if serde_json::to_value(&previous.record).map_err(|_| Error::Corrupt)?
                    != serde_json::to_value(&record).map_err(|_| Error::Corrupt)?
                {
                    return Err(Error::Conflict);
                }
                if let Some(file) = previous.body_file {
                    let actual = super::backup::file_digest(&objects.path(&file)?)?;
                    if actual.bytes != record.content.length
                        || actual.sha256
                            != record
                                .content
                                .sha256
                                .iter()
                                .map(|v| format!("{v:02x}"))
                                .collect::<String>()
                    {
                        return Err(Error::Corrupt);
                    }
                    copied += 1;
                } else {
                    unresolved += 1;
                }
                continue;
            }
            let verified = match &record.object {
                Some(object) => match store
                    .verify(object, record.content, budget(record.content.length)?)
                    .await
                {
                    Ok(value) => Some(value),
                    Err(rss_mdm_content_s3::Error::Missing) if !record.required => None,
                    Err(_) => return Err(Error::Corrupt),
                },
                None => match store
                    .recover(&record.write, budget(record.content.length)?)
                    .await
                    .map_err(|_| Error::Storage)?
                {
                    rss_mdm_content_s3::Recovery::Matched(
                        rss_mdm_content_s3::Written::Verified(object),
                    ) => Some(object),
                    rss_mdm_content_s3::Recovery::Matched(
                        rss_mdm_content_s3::Written::Unverified { .. },
                    ) => return Err(Error::Corrupt),
                    rss_mdm_content_s3::Recovery::Unresolved if !record.required => None,
                    rss_mdm_content_s3::Recovery::Unresolved => return Err(Error::Corrupt),
                },
            };
            let (copied_object, body_file) = if let Some(verified) = verified {
                let name = format!("{}.body", record.id.simple());
                let stage = objects.path(&format!("copy-{}.pending", Uuid::new_v4()))?;
                let mut options = tokio::fs::OpenOptions::new();
                options.create_new(true).write(true).mode(0o600);
                let mut output = options.open(&stage).await.map_err(|_| Error::Storage)?;
                let mut stream = store
                    .read(
                        &verified,
                        0,
                        record.content.length,
                        budget(record.content.length)?,
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
                let mut hash = Sha256::new();
                let mut count = 0u64;
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|_| Error::Storage)?;
                    count = count
                        .checked_add(chunk.len() as u64)
                        .ok_or(Error::Corrupt)?;
                    if count > record.content.length {
                        return Err(Error::Corrupt);
                    }
                    hash.update(&chunk);
                    output.write_all(&chunk).await.map_err(|_| Error::Storage)?;
                }
                if count != record.content.length
                    || <[u8; 32]>::from(hash.finalize()) != record.content.sha256
                {
                    return Err(Error::Corrupt);
                }
                output.sync_all().await.map_err(|_| Error::Storage)?;
                drop(output);
                std::fs::rename(&stage, objects.path(&name)?).map_err(|_| Error::Storage)?;
                std::fs::File::open(&root)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| Error::Storage)?;
                copied += 1;
                (Some(verified.object().clone()), Some(name))
            } else {
                unresolved += 1;
                (None, None)
            };
            objects.save(
                &format!("{}.json", record.id.simple()),
                &SavedObject {
                    record,
                    copied_object,
                    body_file,
                },
            )?;
        }
    }
    objects.save("snapshot.json",&json!({"tenant":tenant,"copiedObjects":copied,"unavailableUnreferencedObjects":unresolved}))
}

async fn connect(runtime: &Value) -> Result<rss_mdm_content_s3::Store> {
    let legacy: Legacy =
        serde_json::from_value(runtime["content"]["storage"].clone()).map_err(|_| Error::Input)?;
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let namespace = format!("{}/{}", legacy.namespace, tenant);
    let store = rss_mdm_content_s3::Store::connect(
        rss_mdm_content_s3::Config {
            endpoint: legacy.endpoint,
            region: legacy.region,
            bucket: legacy.bucket,
            namespace,
            credentials_reference: "transfer-backup".into(),
            private_ca_pem: legacy
                .private_ca_file
                .as_ref()
                .map(|p| {
                    crate::config::read(p, 1024 * 1024, false)
                        .map(|v| v.to_vec())
                        .map_err(|_| Error::Input)
                })
                .transpose()?,
            max_concurrent: 1,
            connect_timeout: std::time::Duration::from_secs(5),
        },
        std::sync::Arc::new(BackupSecrets {
            access: crate::config::secret(&legacy.access_key_file).map_err(|_| Error::Corrupt)?,
            secret: crate::config::secret(&legacy.secret_key_file).map_err(|_| Error::Corrupt)?,
            token: legacy
                .session_token_file
                .as_ref()
                .map(|p| crate::config::secret(p).map_err(|_| Error::Corrupt))
                .transpose()?,
        }),
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        budget(4096)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    Ok(store)
}

/// 恢复只修复已知物理版本；原本未知且无引用的写入保持原 intent。
pub(super) async fn restore(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    runtime: &Value,
) -> Result<()> {
    if runtime["content"]["storage"]["kind"] != "s3" {
        return Ok(());
    }
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
    let store = connect(runtime).await?;
    let mut copy = runtime.clone();
    let protection = super::materials::protection(&mut copy)?;
    let root = journal.path(&format!("s3-{}", host.simple()))?;
    let objects = crate::setup::local::Journal::open(&root)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&root).map_err(|_| Error::Storage)? {
        let name = entry
            .map_err(|_| Error::Storage)?
            .file_name()
            .into_string()
            .map_err(|_| Error::Corrupt)?;
        if name
            .strip_suffix(".json")
            .is_some_and(|stem| Uuid::parse_str(stem).is_ok())
        {
            names.push(name);
        }
    }
    names.sort();
    for name in names {
        let saved: SavedObject = objects.load(&name)?.ok_or(Error::Corrupt)?;
        let Some(original) = &saved.record.object else {
            continue;
        };
        let record = &saved.record;
        let verified = match store
            .verify(original, record.content, budget(record.content.length)?)
            .await
        {
            Ok(value) => value,
            Err(rss_mdm_content_s3::Error::Missing) => {
                let Some(body_file) = saved.body_file else {
                    if record.required {
                        return Err(Error::Corrupt);
                    }
                    continue;
                };
                // 同一原写入恢复未知提交；禁止换 operation 来掩盖未知结果。
                match store
                    .recover(&record.write, budget(record.content.length)?)
                    .await
                    .map_err(|_| Error::Storage)?
                {
                    rss_mdm_content_s3::Recovery::Matched(
                        rss_mdm_content_s3::Written::Verified(value),
                    ) => value,
                    rss_mdm_content_s3::Recovery::Matched(_) => return Err(Error::Corrupt),
                    rss_mdm_content_s3::Recovery::Unresolved => {
                        let file = tokio::fs::File::open(objects.path(&body_file)?)
                            .await
                            .map_err(|_| Error::Storage)?;
                        let stream = futures::stream::try_unfold(file, |mut file| async move {
                            use tokio::io::AsyncReadExt;
                            let mut bytes = vec![0u8; 65536];
                            let n = file
                                .read(&mut bytes)
                                .await
                                .map_err(|_| rss_mdm_content_s3::Error::Configuration)?;
                            if n == 0 {
                                return Ok(None);
                            }
                            bytes.truncate(n);
                            Ok(Some((axum::body::Bytes::from(bytes), file)))
                        });
                        match store
                            .put(
                                &record.write,
                                Box::pin(stream),
                                budget(record.content.length)?,
                            )
                            .await
                            .map_err(|_| Error::Storage)?
                        {
                            rss_mdm_content_s3::Mutation::Confirmed(
                                rss_mdm_content_s3::Written::Verified(value),
                            ) => value,
                            _ => return Err(Error::Storage),
                        }
                    }
                }
            }
            Err(_) => return Err(Error::Storage),
        };
        if verified.object() != original {
            let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant)
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
            rss_mdm_content_service::backup::rebind(
                &mut tx,
                id,
                record,
                original,
                &verified,
                &protection,
            )
            .await
            .map_err(|_| Error::Corrupt)?;
            tx.commit().await.map_err(|_| Error::Storage)?;
        }
    }
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    rss_mdm_content_service::backup::validate_catalog(&mut tx, id, &protection)
        .await
        .map_err(|_| Error::Corrupt)?;
    tx.rollback().await.map_err(|_| Error::Storage)
}
