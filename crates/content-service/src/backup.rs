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
    pub content: Content,
    pub write: Write,
    pub object: Option<Object>,
    pub required: bool,
}
pub async fn s3_page(
    c: &mut PgConnection,
    tenant: TenantId,
    after: Option<Uuid>,
) -> Result<Vec<ObjectRecord>, Error> {
    let rows=sqlx::query("SELECT o.id,o.content,o.intent,o.coordinate,(EXISTS(SELECT 1 FROM mdm_content.manifests m WHERE m.tenant_id=o.tenant_id AND m.state='ready' AND m.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id))) OR EXISTS(SELECT 1 FROM mdm_content.uploads u WHERE u.tenant_id=o.tenant_id AND u.expires>extract(epoch FROM clock_timestamp()) AND u.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id)))) AS required FROM mdm_content.objects o WHERE tenant_id=$1::uuid AND state<>'deleted' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 128").bind(tenant.to_string()).bind(after).fetch_all(c).await.map_err(|_|storage())?;
    rows.into_iter()
        .map(|r| {
            let content: Content =
                serde_json::from_value(r.try_get("content").map_err(|_| storage())?)
                    .map_err(|_| Error::Metadata)?;
            let Intent::S3 { write } =
                serde_json::from_value(r.try_get("intent").map_err(|_| storage())?)
                    .map_err(|_| Error::Metadata)?
            else {
                return Err(Error::Configuration);
            };
            let coordinate: Option<Coordinate> = r
                .try_get::<Option<serde_json::Value>, _>("coordinate")
                .map_err(|_| storage())?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Metadata)?;
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
                id: r.try_get("id").map_err(|_| storage())?,
                content,
                write,
                object,
                required: r.try_get("required").map_err(|_| storage())?,
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
            validate_pieces(c, tenant, &manifest.pieces).await?;
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
            validate_pieces(c, tenant, &saved.pieces).await?;
            after = Some(id);
        }
    }
    Ok(())
}
async fn validate_pieces(
    c: &mut PgConnection,
    tenant: TenantId,
    pieces: &[crate::journal::Piece],
) -> Result<(), Error> {
    for piece in pieces {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.objects WHERE tenant_id=$1::uuid AND id=$2 AND state<>'deleted' AND content=$3 AND coordinate=$4)").bind(tenant.to_string()).bind(piece.id).bind(serde_json::to_value(piece.content).map_err(|_|Error::Metadata)?).bind(serde_json::to_value(&piece.coordinate).map_err(|_|Error::Metadata)?).fetch_one(&mut *c).await.map_err(|_|storage())?;
        if !valid {
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
    let row=sqlx::query("SELECT intent,content,coordinate,state FROM mdm_content.objects WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant.to_string()).bind(record.id).fetch_one(&mut *c).await.map_err(|_|storage())?;
    let content: Content = serde_json::from_value(row.try_get("content").map_err(|_| storage())?)
        .map_err(|_| Error::Metadata)?;
    let Intent::S3 { write } =
        serde_json::from_value(row.try_get("intent").map_err(|_| storage())?)
            .map_err(|_| Error::Metadata)?
    else {
        return Err(Error::Invariant);
    };
    if content != record.content
        || write != record.write
        || row.try_get::<String, _>("state").map_err(|_| storage())? == "deleted"
    {
        return Err(Error::Conflict);
    }
    let current: Option<Coordinate> = row
        .try_get::<Option<serde_json::Value>, _>("coordinate")
        .map_err(|_| storage())?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Metadata)?;
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
    let filter = serde_json::json!([{"id":record.id}]);
    let uploads=sqlx::query("SELECT id,document FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND document->'value'->'pieces' @> $2 FOR UPDATE").bind(tenant.to_string()).bind(&filter).fetch_all(&mut *c).await.map_err(|_|storage())?;
    for row in uploads {
        let id: Uuid = row.try_get("id").map_err(|_| storage())?;
        let mut saved: crate::journal::Saved = crate::journal::verify_document(
            protection,
            tenant,
            &id.to_string(),
            row.try_get("document").map_err(|_| storage())?,
        )?;
        replace_piece(&mut saved.pieces, record, previous, restored.object())?;
        let document = crate::journal::sign_document(protection, tenant, &id.to_string(), &saved)?;
        sqlx::query(
            "UPDATE mdm_content.uploads SET document=$3 WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(tenant.to_string())
        .bind(id)
        .bind(document)
        .execute(&mut *c)
        .await
        .map_err(|_| storage())?;
    }
    let manifests=sqlx::query("SELECT class,sha256,length,document FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND document->'value'->'pieces' @> $2 FOR UPDATE").bind(tenant.to_string()).bind(&filter).fetch_all(&mut *c).await.map_err(|_|storage())?;
    for row in manifests {
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
        let mut manifest: crate::journal::Manifest = crate::journal::verify_document(
            protection,
            tenant,
            &key,
            row.try_get("document").map_err(|_| storage())?,
        )?;
        replace_piece(&mut manifest.pieces, record, previous, restored.object())?;
        let document = crate::journal::sign_document(protection, tenant, &key, &manifest)?;
        sqlx::query("UPDATE mdm_content.manifests SET document=$5 WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4").bind(tenant.to_string()).bind(class).bind(digest).bind(length).bind(document).execute(&mut *c).await.map_err(|_|storage())?;
    }
    sqlx::query("UPDATE mdm_content.objects SET coordinate=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant.to_string())
        .bind(record.id)
        .bind(
            serde_json::to_value(Coordinate::S3 {
                object: restored.object().clone(),
            })
            .map_err(|_| Error::Metadata)?,
        )
        .execute(c)
        .await
        .map_err(|_| storage())?;
    Ok(true)
}
fn replace_piece(
    pieces: &mut [crate::journal::Piece],
    record: &ObjectRecord,
    previous: &Object,
    next: &Object,
) -> Result<(), Error> {
    let mut found = false;
    for piece in pieces.iter_mut().filter(|piece| piece.id == record.id) {
        let Coordinate::S3 { object } = &piece.coordinate else {
            return Err(Error::Invariant);
        };
        if object != previous || piece.content != record.content {
            return Err(Error::Invariant);
        }
        piece.coordinate = Coordinate::S3 {
            object: next.clone(),
        };
        found = true;
    }
    if found { Ok(()) } else { Err(Error::Invariant) }
}
