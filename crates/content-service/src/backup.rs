//! 内容 owner 的只读物理目录；未知写入仍保留原 intent，不推断成成功或缺失。
use crate::{
    Error,
    backend::{Coordinate, Intent},
    storage,
};
use rss_mdm_content_s3::{Content, Object, Write};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRecord {
    pub id: Uuid,
    pub generation: Uuid,
    pub content: Content,
    pub write: Write,
    pub object: Option<Object>,
    pub required: bool,
    pub marker: bool,
}
pub async fn s3_page(
    c: &mut PgConnection,
    tenant: TenantId,
    generation: Uuid,
    protection: &rss_mdm_native_protection::Protector,
    after: Option<Uuid>,
) -> Result<Vec<ObjectRecord>, Error> {
    let rows=sqlx::query("SELECT o.id,o.content,o.location,(EXISTS(SELECT 1 FROM mdm_content.manifests m WHERE m.tenant_id=o.tenant_id AND m.state='ready' AND m.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id))) OR EXISTS(SELECT 1 FROM mdm_content.uploads u WHERE u.tenant_id=o.tenant_id AND u.expires>extract(epoch FROM clock_timestamp()) AND u.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id)))) AS required FROM mdm_content.objects o WHERE tenant_id=$1::uuid AND generation=$3 AND state<>'deleted' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 128").bind(tenant.to_string()).bind(after).bind(generation).fetch_all(c).await.map_err(|_|storage())?;
    rows.into_iter()
        .map(|r| {
            let content: Content =
                serde_json::from_value(r.try_get("content").map_err(|_| storage())?)
                    .map_err(|_| Error::Metadata)?;
            let id = r.try_get("id").map_err(|_| storage())?;
            let location = crate::location::Location::open(
                protection,
                tenant,
                generation,
                id,
                content,
                r.try_get("location").map_err(|_| storage())?,
            )?;
            let Intent::S3 { write } = location.intent else {
                return Err(Error::Configuration);
            };
            let coordinate = location.coordinate;
            let object = match coordinate {
                Some(Coordinate::S3 { object }) => Some(object),
                None => None,
                _ => return Err(Error::Configuration),
            };
            if content != write.content()
                || object
                    .as_ref()
                    .is_some_and(|o| o.target() != write.target())
            {
                return Err(Error::Invariant);
            }
            Ok(ObjectRecord {
                id,
                generation,
                content,
                write,
                object,
                required: r.try_get("required").map_err(|_| storage())?,
                marker: false,
            })
        })
        .collect()
}

/// 校验仍可消费的签名目录及其物理记录；损坏目录不能通过备份被“修复”。
pub async fn validate_catalog(
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<(), Error> {
    let mut after: Option<(String, Vec<u8>, i64)> = None;
    loop {
        let (class, digest, length) = after
            .clone()
            .map(|v| (Some(v.0), Some(v.1), Some(v.2)))
            .unwrap_or_default();
        let rows=sqlx::query("SELECT class,sha256,length,document FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND state='ready' AND ($2::text IS NULL OR (class,sha256,length)>($2,$3::bytea,$4::bigint)) ORDER BY class,sha256,length LIMIT 128").bind(tenant.to_string()).bind(class).bind(digest).bind(length).fetch_all(&mut *c).await.map_err(|_|storage())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let class: String = row.try_get("class").map_err(|_| storage())?;
            let digest: Vec<u8> = row.try_get("sha256").map_err(|_| storage())?;
            let length: i64 = row.try_get("length").map_err(|_| storage())?;
            let key = format!(
                "{}:{}:{}",
                class,
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                length
            );
            let manifest: crate::journal::Manifest = crate::journal::verify_document(
                protection,
                tenant,
                &key,
                row.try_get("document").map_err(|_| storage())?,
            )?;
            validate_pieces(c, tenant, protection, &manifest.pieces).await?;
            after = Some((class, digest, length));
        }
    }
    let mut after = None;
    loop {
        let rows=sqlx::query("SELECT id,document FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND expires>extract(epoch FROM clock_timestamp()) AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 128").bind(tenant.to_string()).bind(after).fetch_all(&mut *c).await.map_err(|_|storage())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let id: Uuid = row.try_get("id").map_err(|_| storage())?;
            let saved: crate::journal::Saved = crate::journal::verify_document(
                protection,
                tenant,
                &id.to_string(),
                row.try_get("document").map_err(|_| storage())?,
            )?;
            validate_pieces(c, tenant, protection, &saved.pieces).await?;
            after = Some(id);
        }
    }
    Ok(())
}
async fn validate_pieces(
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    pieces: &[crate::journal::Piece],
) -> Result<(), Error> {
    for piece in pieces {
        let row: Option<(Uuid, serde_json::Value)> = sqlx::query_as("SELECT o.generation,o.location FROM mdm_content.objects o JOIN mdm_content.settings s ON s.tenant_id=o.tenant_id AND s.active_generation=o.generation WHERE o.tenant_id=$1::uuid AND o.id=$2 AND o.state<>'deleted' AND o.content=$3")
            .bind(tenant.to_string()).bind(piece.id).bind(crate::journal::encode(&piece.content)?).fetch_optional(&mut *c).await.map_err(|_| storage())?;
        let (generation, document) = row.ok_or(Error::Invariant)?;
        let location = crate::location::Location::open(
            protection,
            tenant,
            generation,
            piece.id,
            piece.content,
            document,
        )?;
        if location.coordinate.is_none() {
            return Err(Error::Invariant);
        }
    }
    Ok(())
}

/// 恢复时仅替换已核验物理版本；逻辑内容 SHA、上传前沿、原 intent 和操作身份不变。
/// 必须在调用者的停写维护事务中提交，未知提交以同一映射重放。
pub async fn rebind(
    c: &mut PgConnection,
    tenant: TenantId,
    record: &ObjectRecord,
    previous: &Object,
    restored: &rss_mdm_content_s3::Verified,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<bool, Error> {
    if restored.content() != record.content
        || restored.object().target() != record.write.target()
        || previous.target() != record.write.target()
        || record.object.as_ref().is_some_and(|o| o != previous)
    {
        return Err(Error::Invariant);
    }
    if record.marker {
        let document:serde_json::Value=sqlx::query_scalar("SELECT marker FROM mdm_content.generations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
            .bind(tenant.to_string()).bind(record.generation).fetch_one(&mut *c).await.map_err(|_|storage())?;
        let mut location = crate::location::Location::open(
            protection,
            tenant,
            record.generation,
            record.id,
            record.content,
            document.clone(),
        )?;
        let Some(Coordinate::S3 { object }) = &location.coordinate else {
            return Err(Error::Invariant);
        };
        if object == restored.object() {
            return Ok(false);
        };
        if object != previous {
            return Err(Error::Conflict);
        };
        location.coordinate = Some(Coordinate::S3 {
            object: restored.object().clone(),
        });
        sqlx::query("UPDATE mdm_content.generations SET marker=$3 WHERE tenant_id=$1::uuid AND id=$2 AND marker=$4")
            .bind(tenant.to_string()).bind(record.generation).bind(location.seal(protection,tenant)?).bind(document).execute(c).await.map_err(|_|storage())?;
        return Ok(true);
    }
    let row=sqlx::query("SELECT location,content,state FROM mdm_content.objects WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 FOR UPDATE").bind(tenant.to_string()).bind(record.id).bind(record.generation).fetch_one(&mut *c).await.map_err(|_|storage())?;
    let content: Content = serde_json::from_value(row.try_get("content").map_err(|_| storage())?)
        .map_err(|_| Error::Metadata)?;
    let mut location = crate::location::Location::open(
        protection,
        tenant,
        record.generation,
        record.id,
        content,
        row.try_get("location").map_err(|_| storage())?,
    )?;
    let Intent::S3 { write } = &location.intent else {
        return Err(Error::Invariant);
    };
    if content != record.content
        || write != &record.write
        || row.try_get::<String, _>("state").map_err(|_| storage())? == "deleted"
    {
        return Err(Error::Conflict);
    }
    let current = location.coordinate.clone();
    if let Some(Coordinate::S3 { object }) = &current {
        if object == restored.object() {
            return Ok(false);
        }
        if object != previous {
            return Err(Error::Conflict);
        }
    } else if current.is_some() || record.object.is_some() {
        return Err(Error::Conflict);
    }
    location.coordinate = Some(Coordinate::S3 {
        object: restored.object().clone(),
    });
    sqlx::query("UPDATE mdm_content.objects SET location=$3 WHERE tenant_id=$1::uuid AND id=$2 AND generation=$4")
        .bind(tenant.to_string()).bind(record.id).bind(location.seal(protection, tenant)?).bind(record.generation)
        .execute(c).await.map_err(|_| storage())?;
    Ok(true)
}

/// Retained and in-progress generations remain part of the recovery set.
pub async fn generations(
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    after: Option<Uuid>,
) -> Result<Vec<(Uuid, crate::Storage)>, Error> {
    let rows=sqlx::query("SELECT id,descriptor FROM mdm_content.generations WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 128")
        .bind(tenant.to_string()).bind(after).fetch_all(c).await.map_err(|_|storage())?;
    rows.into_iter()
        .map(|row| {
            let id = row.try_get("id").map_err(|_| storage())?;
            let generation = crate::generation::Generation::open(
                protection,
                tenant,
                id,
                row.try_get("descriptor").map_err(|_| storage())?,
            )?;
            Ok((id, generation.storage))
        })
        .collect()
}
pub async fn marker(
    c: &mut PgConnection,
    tenant: TenantId,
    generation: Uuid,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<Option<ObjectRecord>, Error> {
    let document: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT marker FROM mdm_content.generations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant.to_string())
    .bind(generation)
    .fetch_one(c)
    .await
    .map_err(|_| storage())?;
    let Some(document) = document else {
        return Ok(None);
    };
    let content = crate::journal::decode(document["value"]["content"].clone())?;
    let location = crate::location::Location::open(
        protection, tenant, generation, generation, content, document,
    )?;
    let Intent::S3 { write } = location.intent else {
        return Err(Error::Configuration);
    };
    let object = match location.coordinate {
        Some(Coordinate::S3 { object }) => Some(object),
        None => None,
        _ => return Err(Error::Invariant),
    };
    Ok(Some(ObjectRecord {
        id: generation,
        generation,
        content,
        write,
        object,
        required: true,
        marker: true,
    }))
}
