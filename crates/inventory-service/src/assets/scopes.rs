//! Device-authorized discovery from existing immutable asset and collection history.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (borrowed transaction, no commit owner).
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    kind: String,
    tenant: String,
    device: String,
    authority: String,
    watermark: i64,
    after: String,
}

impl AssetService {
    pub(super) async fn inventory_scopes(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        access: &ReadScope,
        limit: usize,
        token: Option<&str>,
    ) -> Result<Response> {
        checked_input(rss_observation::Id::new(device))?;
        if !(1..=100).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        if access
            .devices
            .as_ref()
            .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let tenant = self.tenant.to_string();
        let target = device.to_owned();
        if !tx
            .with_connection(move |c| Box::pin(crate::device::read::exists(c, tenant, target)))
            .await?
        {
            return Err(Error::NotFound.into());
        }
        let current = self.list_watermark(tx).await?;
        let tenant = self.tenant.to_string();
        let targets = vec![device.to_owned()];
        let sources = tx
            .with_connection(move |c| {
                Box::pin(crate::device::read::sources_at(c, tenant, targets, current))
            })
            .await?;
        if sources.len() > 2000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let sources = sources
            .into_iter()
            .map(|row| {
                Ok(serde_json::json!({
                    "registration":row.try_get::<String,_>("registration")?,
                    "generation":row.try_get::<String,_>("generation")?,
                    "source":row.try_get::<String,_>("source")?,
                    "epoch":row.try_get::<String,_>("epoch")?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let catalog = catalog_in(tx, self.tenant, current).await?;
        let visible = catalog
            .fields()
            .filter(|f| {
                access.sensitive || f.sensitivity == rss_mdm_inventory::Sensitivity::Standard
            })
            .map(|f| f.key.as_str().to_owned())
            .collect::<Vec<_>>();
        let authority = digest(&(access, &sources, &visible))?;
        let (watermark, after) = if let Some(token) = token {
            let cursor = self.scope_cursor(token, device, &authority)?;
            if cursor.watermark > current {
                return Err(Error::Conflict.into());
            }
            (cursor.watermark, cursor.after)
        } else {
            (current, String::new())
        };
        let catalog = catalog_in(tx, self.tenant, watermark).await?;
        let fields = catalog
            .fields()
            .filter(|f| visible.iter().any(|key| key == f.key.as_str()))
            .map(|f| f.key.as_str().to_owned())
            .collect::<Vec<_>>();
        let tenant = self.tenant.to_string();
        let projection = rss_mdm_inventory_postgres::projection_scope(self.tenant);
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, String>(SCOPES)
                        .bind(tenant)
                        .bind(serde_json::json!(sources))
                        .bind(watermark)
                        .bind(fields)
                        .bind(after)
                        .bind((limit + 1) as i64)
                        .bind(projection.source().source())
                        .bind(projection.generation())
                        .fetch_all(c)
                        .await
                })
            })
            .await?;
        let more = rows.len() > limit;
        let selected = rows.into_iter().take(limit).collect::<Vec<_>>();
        let next_cursor = if more {
            let cursor = Cursor {
                kind: "inventory-scopes-v1".into(),
                tenant: self.tenant.to_string(),
                device: device.into(),
                authority,
                watermark,
                after: selected.last().ok_or(Error::Malformed)?.clone(),
            };
            let mut bytes = checked_input(serde_json::to_vec(&cursor))?;
            bytes.extend(ring::hmac::sign(&self.asset_cursor_key, &bytes).as_ref());
            Some(URL_SAFE_NO_PAD.encode(bytes))
        } else {
            None
        };
        let items = selected
            .into_iter()
            .map(|value| {
                let scope: rss_mdm_inventory::CollectionScope =
                    stored(serde_json::from_str(&value))?;
                stored(scope.validate_executable())?;
                Ok(InventoryScope { scope })
            })
            .collect::<Result<_>>()?;
        Ok(Response::InventoryScopes {
            device: device.into(),
            watermark,
            items,
            next_cursor,
        })
    }

    fn scope_cursor(&self, token: &str, device: &str, authority: &str) -> Result<Cursor> {
        if token.len() > 65536 {
            return Err(Error::Malformed.into());
        }
        let bytes = checked_input(URL_SAFE_NO_PAD.decode(token))?;
        if bytes.len() <= 32 {
            return Err(Error::Malformed.into());
        }
        let (payload, signature) = bytes.split_at(bytes.len() - 32);
        ring::hmac::verify(&self.asset_cursor_key, payload, signature)
            .map_err(|_| Error::Conflict)?;
        let cursor: Cursor = checked_input(serde_json::from_slice(payload))?;
        if cursor.kind != "inventory-scopes-v1"
            || cursor.tenant != self.tenant.to_string()
            || cursor.device != device
            || cursor.authority != authority
            || cursor.watermark < 0
        {
            return Err(Error::Conflict.into());
        }
        Ok(cursor)
    }
}

const SCOPES: &str = r#"
WITH authority AS (
 SELECT registration,source,epoch FROM jsonb_to_recordset($2::jsonb)
 AS a(registration text,source text,epoch text)
), inventory AS (
 SELECT DISTINCT ON(h.scope_digest,h.field,h.field_scope)
   h.field_scope,h.document
 FROM mdm.inventory_history h
 WHERE h.tenant_id=$1::uuid AND h.revision<=$3 AND h.field=ANY($4::text[])
 ORDER BY h.scope_digest,h.field,h.field_scope,h.revision DESC
), facts AS (
 SELECT (h.field_scope::jsonb)::text AS scope FROM inventory h
 JOIN authority a ON a.registration=h.document->>'registration'
   AND a.source=h.document->>'source' AND a.epoch=h.document->>'epoch'
 WHERE h.document IS NOT NULL AND h.document->>'state'<>'deleted'
   AND h.document->>'journal'=$7 AND h.document->>'generation'=$8
), runs AS (
 SELECT DISTINCT ON(h.scope,h.run) h.scope,h.run,h.sequence,h.document
 FROM mdm_access.collection_history h
 WHERE h.tenant_id=$1::uuid AND h.revision<=$3
 ORDER BY h.scope,h.run,h.revision DESC
), attempts AS (
 SELECT DISTINCT ON(h.scope,f->'definition'->>'key',f->'scope')
   f->'scope' AS scope,
   ((h.document->>'attempts')::jsonb->'fields'->(f->'definition'->>'key')->>'quality') AS quality
 FROM runs h
 JOIN authority a ON a.registration=h.scope::jsonb->>'registration'
   AND a.source=h.scope::jsonb->>'source' AND a.epoch=h.scope::jsonb->>'epoch'
 CROSS JOIN LATERAL jsonb_array_elements((h.document->>'attempts')::jsonb->'definition'->'fields') f
 WHERE h.document IS NOT NULL AND f->'definition'->>'key'=ANY($4::text[])
 ORDER BY h.scope,f->'definition'->>'key',f->'scope',h.sequence DESC,h.run DESC
), candidates AS (
 SELECT scope FROM facts
 UNION SELECT scope::text FROM attempts WHERE quality<>'deleted'
)
SELECT scope FROM candidates WHERE scope::jsonb->>'kind'<>'device'
 AND scope COLLATE "C">$5::text COLLATE "C"
ORDER BY scope COLLATE "C" LIMIT $6
"#;
