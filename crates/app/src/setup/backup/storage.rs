use crate::setup::{Error, Result};
use rss_mdm_content_service::connections as domain;
use rss_mdm_native_protection::Protector;
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;
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
async fn capture_generation(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    generation: Uuid,
    runtime: &Value,
) -> Result<()> {
    if runtime["content"]["storage"]["kind"] != "s3" {
        return Ok(());
    }
    let (store, protection) = load_connection(c, runtime).await?;
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
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
    let root = journal.path(&format!("s3-{}-{}", host.simple(), generation.simple()))?;
    let objects = crate::setup::local::Journal::open(&root)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let marker = rss_mdm_content_service::backup::marker(&mut tx, id, generation, &protection)
        .await
        .map_err(|_| Error::Corrupt)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    if let Some(marker) = marker {
        backup_object(&objects, &root, &store, marker).await?;
    }
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
        let page =
            rss_mdm_content_service::backup::s3_page(&mut tx, id, generation, &protection, after)
                .await
                .map_err(|_| Error::Corrupt)?;
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if page.is_empty() {
            break;
        }
        for record in page {
            after = Some(record.id);
            if backup_object(&objects, &root, &store, record).await? {
                copied += 1;
            } else {
                unresolved += 1;
            }
        }
    }
    objects.save("snapshot.json",&json!({"tenant":tenant,"copiedObjects":copied,"unavailableUnreferencedObjects":unresolved}))
}

async fn restore_generation(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    generation: Uuid,
    runtime: &Value,
) -> Result<()> {
    if runtime["content"]["storage"]["kind"] != "s3" {
        return Ok(());
    }
    let (store, protection) = load_connection(c, runtime).await?;
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
    let root = journal.path(&format!("s3-{}-{}", host.simple(), generation.simple()))?;
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
        restore_object(c, tenant, &objects, &store, &protection, &name).await?;
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

async fn load_connection(
    c: &mut PgConnection,
    runtime: &Value,
) -> Result<(rss_mdm_content_s3::Store, std::sync::Arc<Protector>)> {
    let config: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
    let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)
        .map_err(|_| Error::Input)?;
    let revision = runtime["content"]["storage"]["revision"]
        .as_u64()
        .ok_or(Error::Input)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let loaded = domain::load(&mut tx, tenant, revision, &protection)
        .await
        .map_err(|_| Error::Corrupt)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    let metadata = &loaded.metadata;
    let config = rss_mdm_content_s3::Config {
        endpoint: metadata.endpoint.clone(),
        region: metadata.region.clone(),
        bucket: metadata.bucket.clone(),
        namespace: format!("{}/{}", metadata.namespace, tenant),
        credentials_reference: "content-connection".into(),
        private_ca_pem: Some(metadata.private_ca.clone()),
        max_concurrent: 1,
        connect_timeout: std::time::Duration::from_secs(5),
    };
    let store = rss_mdm_content_s3::Store::connect(
        config,
        std::sync::Arc::new(loaded),
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        budget(4096)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    Ok((store, protection))
}

async fn backup_object(
    objects: &crate::setup::local::Journal,
    root: &std::path::Path,
    store: &rss_mdm_content_s3::Store,
    record: rss_mdm_content_service::backup::ObjectRecord,
) -> Result<bool> {
    use futures::StreamExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    let name = format!("{}.json", record.id.simple());
    if let Some(previous) = objects.load::<SavedObject>(&name)? {
        if serde_json::to_value(&previous.record).map_err(|_| Error::Corrupt)?
            != serde_json::to_value(&record).map_err(|_| Error::Corrupt)?
        {
            return Err(Error::Conflict);
        }
        if let Some(file) = &previous.body_file {
            let actual = super::archive::file_digest(&objects.path(file)?)?;
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
        }
        return Ok(previous.body_file.is_some());
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
            rss_mdm_content_s3::Recovery::Matched(rss_mdm_content_s3::Written::Verified(
                object,
            )) => Some(object),
            rss_mdm_content_s3::Recovery::Matched(rss_mdm_content_s3::Written::Unverified {
                ..
            }) => return Err(Error::Corrupt),
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
        std::fs::File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;

        (Some(verified.object().clone()), Some(name))
    } else {
        (None, None)
    };
    let did_copy = body_file.is_some();
    objects.save(
        &format!("{}.json", record.id.simple()),
        &SavedObject {
            record,
            copied_object,
            body_file,
        },
    )?;

    Ok(did_copy)
}

async fn restore_object(
    c: &mut PgConnection,
    tenant: &str,
    objects: &crate::setup::local::Journal,
    store: &rss_mdm_content_s3::Store,
    protection: &Protector,
    name: &str,
) -> Result<()> {
    let id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;

    let saved: SavedObject = objects.load(name)?.ok_or(Error::Corrupt)?;
    let Some(original) = saved
        .record
        .object
        .as_ref()
        .or(saved.copied_object.as_ref())
    else {
        if saved.record.required || saved.body_file.is_some() {
            return Err(Error::Corrupt);
        }
        return Ok(());
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
                return Ok(());
            };
            // 同一原写入恢复未知提交；禁止换 operation 来掩盖未知结果。
            match store
                .recover(&record.write, budget(record.content.length)?)
                .await
                .map_err(|_| Error::Storage)?
            {
                rss_mdm_content_s3::Recovery::Matched(rss_mdm_content_s3::Written::Verified(
                    value,
                )) => value,
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
    if verified.object() != original || record.object.is_none() {
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        rss_mdm_content_service::backup::rebind(
            &mut tx, id, record, original, &verified, protection,
        )
        .await
        .map_err(|_| Error::Corrupt)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
    }

    Ok(())
}

pub(in crate::setup) async fn capture(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    runtime: &Value,
) -> Result<()> {
    generation_snapshots(c, journal, host, runtime, false).await
}
pub(in crate::setup) async fn restore(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    runtime: &Value,
) -> Result<()> {
    generation_snapshots(c, journal, host, runtime, true).await
}
async fn generation_snapshots(
    c: &mut PgConnection,
    journal: &crate::setup::local::Journal,
    host: Uuid,
    runtime: &Value,
    restore: bool,
) -> Result<()> {
    let config: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
    let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)
        .map_err(|_| Error::Corrupt)?;
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
    let mut after = None;
    loop {
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        let generations =
            rss_mdm_content_service::backup::generations(&mut tx, tenant, &protection, after)
                .await
                .map_err(|_| Error::Corrupt)?;
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if generations.is_empty() {
            break;
        }
        for (id, storage) in generations {
            after = Some(id);
            if !matches!(storage, rss_mdm_content_service::Storage::S3(_)) {
                continue;
            }
            let mut material = runtime.clone();
            material["content"]["storage"] =
                serde_json::to_value(storage).map_err(|_| Error::Corrupt)?;
            if restore {
                restore_generation(c, journal, host, id, &material).await?;
            } else {
                capture_generation(c, journal, host, id, &material).await?;
            }
        }
    }
    Ok(())
}
