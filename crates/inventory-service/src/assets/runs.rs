//! Device-authorized progress across every collection source; no new execution owner.
use super::*;
use sqlx::Row;
#[derive(schemars::JsonSchema, Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunView {
    pub id: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub source: rss_mdm_inventory::Source,
    pub epoch: Uuid,
    pub delivery: crate::inventory_runtime::DeliveryStatus,
    pub fingerprint: String,
    #[schemars(schema_with = "rss_mdm_inventory::coverage_schema")]
    pub coverage: rss_observation::Coverage,
    pub complete: bool,
    pub dataset: String,
    pub template_version: String,
    pub sequence: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub result: crate::collection::RunResult,
    pub reason: Option<crate::collection::FinishReason>,
    pub delivery_pending: bool,
    pub fields: Vec<QualityField>,
    #[serde(skip)]
    array_fields: BTreeSet<FieldKey>,
}
impl AssetService {
    pub(super) async fn collection_run(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        id: Uuid,
        scope: &ReadScope,
    ) -> Result<RunView> {
        if scope
            .devices
            .as_ref()
            .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let tenant = self.tenant;
        let device = device.to_owned();
        let row=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT c.registration,r.generation,c.source,c.sequence,c.started_at,c.sealed_at,c.result,c.reason,c.delivery_pending,c.scope,c.batch,c.digest,c.progress_version,CASE WHEN v.metadata_bytes<=67108864 THEN v.metadata::text END AS metadata FROM mdm_access.collection_runs c JOIN mdm_access.collection_versions v ON (v.tenant_id,v.version)=(c.tenant_id,c.progress_version) JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(c.tenant_id,c.registration) WHERE c.tenant_id=$1::uuid AND c.id=$2 AND r.device=$3")
                .bind(tenant.to_string()).bind(id).bind(device).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        let progress: crate::collection::summary::Summary = stored(
            crate::collection::summary::Summary::decode(row.try_get("metadata")?),
        )?;
        let definition = &progress.definition;
        if !definition
            .bindings()
            .iter()
            .any(|f| f.scope == scope.collection_scope)
        {
            return Err(Error::NotFound.into());
        }
        let fields = progress
            .fields
            .iter()
            .filter(|(key, _)| {
                definition
                    .field_scope(**key)
                    .is_ok_and(|s| s == &scope.collection_scope)
                    && definition.field(**key).is_ok_and(fields::visible)
            })
            .map(|(key, attempt)| QualityField {
                reason: attempt.reason.clone(),
                scope: definition.field_scope(*key).expect("frozen field").clone(),
                item_count: attempt.item_count,
                invalid_items: attempt.invalid_items,
                field: *key,
                quality: attempt.quality,
                status: attempt.status,
                received_at: attempt.received_at,
            })
            .collect();
        let coordinate: rss_observation::Scope =
            stored(serde_json::from_str(row.try_get("scope")?))?;
        stored(definition.validate_scope(&coordinate))?;
        let delivery = if let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>("batch")? {
            let batch = stored(rss_observation::Batch::decode(&bytes))?;
            let reference = stored(rss_mdm_inventory::CollectionReference::from_batch(
                definition, &batch,
            ))?;
            if batch.id().as_str() != id.to_string()
                || batch.sequence() != row.try_get::<i64, _>("sequence")? as u64
                || reference.digest() != row.try_get::<String, _>("progress_version")?
                || batch.encode() != bytes
            {
                return Err(Error::Unavailable(Failure::CollectionQuery).into());
            }
            self.inventory.inspect_report(&coordinate, &batch).await?
        } else {
            crate::inventory_runtime::DeliveryStatus {
                receipt: None,
                projection: crate::inventory_runtime::ProjectionStatus::NotApplicable,
            }
        };
        Ok(RunView {
            epoch: stored(Uuid::parse_str(coordinate.epoch().as_str()))?,
            delivery,
            fingerprint: stored(definition.fingerprint())?,
            coverage: stored(definition.coverage())?,
            complete: progress.coverage_complete(),
            id,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
            source: stored(rss_mdm_inventory::Source::parse(row.try_get("source")?))?,
            dataset: definition.dataset().into(),
            template_version: definition.version().into(),
            sequence: row.try_get("sequence")?,
            started_at: row.try_get("started_at")?,
            finished_at: row.try_get("sealed_at")?,
            result: crate::collection::RunResult::parse(row.try_get("result")?)?,
            reason: row
                .try_get::<Option<String>, _>("reason")?
                .as_deref()
                .map(crate::collection::FinishReason::parse)
                .transpose()?,
            delivery_pending: row.try_get("delivery_pending")?,
            array_fields: definition
                .bindings()
                .iter()
                .filter(|f| {
                    matches!(
                        f.definition.value_type,
                        rss_mdm_inventory::ValueType::Array { .. }
                    )
                })
                .map(|f| f.definition.key)
                .collect(),
            fields,
        })
    }
}

impl AssetService {
    pub(super) async fn collection_items(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        id: Uuid,
        field: FieldKey,
        scope: &ReadScope,
        page: (Option<&str>, usize),
    ) -> Result<Response> {
        let (cursor, limit) = page;
        if !(1..=1000).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        let run = self.collection_run(tx, device, id, scope).await?;
        if run.finished_at.is_none() {
            return Err(Error::Conflict.into());
        }
        if !run.fields.iter().any(|f| f.field == field) {
            return Err(Error::Forbidden.into());
        }
        if !run.array_fields.contains(&field) {
            return Err(Error::Malformed.into());
        }
        let metadata = run
            .fields
            .iter()
            .find(|f| f.field == field)
            .ok_or(Error::Forbidden)?;
        let codec = rss_mdm_query::cursor::CursorCodec::from_key(self.asset_cursor_key.clone());
        let binding = digest(&(
            "collection-items",
            self.tenant.to_string(),
            device,
            id,
            field,
            scope,
            &run.fingerprint,
            run.finished_at,
        ))?;
        let offset: usize = cursor
            .map(|token| -> Result<usize> {
                codec
                    .decode(
                        &checked_input(rss_contract::PageCursor::parse(token))?,
                        &binding,
                    )
                    .map_err(|_| Error::Conflict.into())
            })
            .transpose()?
            .unwrap_or(0);
        if offset > metadata.item_count {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let field_name = field.as_str().to_owned();
        let rows: Vec<(i64, String, Option<String>)> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("WITH selected AS (
                SELECT progress_version AS version,attempts::jsonb AS progress FROM mdm_access.collection_runs
                WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NOT NULL
            ), indexed AS (
                SELECT i.ordinal,i.quality,count(*) FILTER(WHERE i.quality='success') OVER(ORDER BY i.ordinal)-1 AS position
                FROM mdm_access.collection_items i,selected s
                WHERE i.tenant_id=$1::uuid AND i.version=s.version AND i.field=$3
            ), page AS (
                SELECT i.ordinal,i.quality,CASE WHEN i.quality='success'
                  THEN (s.progress #> ARRAY['fields',$3,'value','value','value'])->i.position::integer END AS value
                FROM indexed i,selected s WHERE i.ordinal>=$4 ORDER BY i.ordinal LIMIT $5
            ), bounded AS (
                SELECT *,sum(octet_length(quality)+coalesce(octet_length(value::text),4)) OVER(ORDER BY ordinal) AS bytes FROM page
            ) SELECT ordinal,quality,value::text FROM bounded WHERE bytes<=16777216 ORDER BY ordinal")
                .bind(tenant).bind(id).bind(field_name).bind(offset as i64).bind(limit as i64).fetch_all(c).await
        })).await?;
        let mut items = Vec::with_capacity(rows.len());
        for (ordinal, quality, value) in rows {
            if ordinal != (offset + items.len()) as i64 {
                return Err(Error::Unavailable(Failure::CollectionQuery).into());
            }
            items.push(ItemQualityView {
                index: ordinal as usize,
                value: value
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(|_| Error::Unavailable(Failure::CollectionQuery))?,
                quality: stored(serde_json::from_value(serde_json::Value::String(quality)))?,
            });
        }
        if offset < metadata.item_count && items.is_empty() {
            return Err(Error::Unavailable(Failure::CollectionQuery).into());
        }
        let next = offset + items.len();
        Ok(Response::CollectionItems {
            run: id,
            field,
            items,
            next_cursor: if next < metadata.item_count {
                Some(
                    checked_input(codec.encode(&binding, &next))?
                        .as_str()
                        .to_owned(),
                )
            } else {
                None
            },
        })
    }
}
