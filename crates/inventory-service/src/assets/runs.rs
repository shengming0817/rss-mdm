//! Device-authorized progress across every collection source; no new execution owner.
use super::*;
use sqlx::Row;
#[derive(schemars::JsonSchema, Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunView {
    pub id: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
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
    pub fields: Vec<QualityField>,
    #[serde(skip)]
    array_fields: BTreeSet<FieldKey>,
}
struct RunEvidence {
    id: Uuid,
    row: sqlx::postgres::PgRow,
    scope: rss_observation::Scope,
    progress: crate::collection::summary::Summary,
}

impl RunEvidence {
    async fn read(
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> Result<Option<Self>> {
        let tenant = tx.tenant_id();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT c.device, c.source, c.sequence, c.started_at, c.sealed_at, c.result, c.reason, c.scope, c.batch, c.digest, c.progress_version, CASE WHEN v.metadata_bytes <= 67108864 THEN CAST(v.metadata AS text) END AS metadata FROM mdm_access.collection_runs AS c INNER JOIN mdm_access.collection_versions AS v ON (v.tenant_id, v.version) = (c.tenant_id, c.progress_version) INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (c.tenant_id, c.device) WHERE c.tenant_id = CAST($1 AS uuid) AND c.id = $2 AND r.id = $3")
                .bind(tenant.to_string()).bind(id).bind(device.into_uuid()).fetch_optional(c).await
        })).await?;
        let Some(row) = row else { return Ok(None) };
        let scope: rss_observation::Scope = stored(serde_json::from_str(row.try_get("scope")?))?;
        if scope.tenant() != tenant || scope.registration().as_str() != device.to_string() {
            return Err(Error::Unavailable(Failure::CollectionQuery).into());
        }
        let progress = stored(crate::collection::summary::Summary::decode(
            row.try_get("metadata")?,
        ))?;
        stored(progress.definition.validate_scope(&scope))?;
        Ok(Some(Self {
            id,
            row,
            scope,
            progress,
        }))
    }

    async fn delivery(
        &self,
        inventory: &crate::inventory_runtime::InventoryRuntime,
        control: (
            rss_request_context::Deadline,
            rss_request_context::Cancellation<'_>,
        ),
    ) -> Result<crate::inventory_runtime::DeliveryStatus> {
        let Some(bytes) = self.row.try_get::<Option<&[u8]>, _>("batch")? else {
            return Ok(crate::inventory_runtime::DeliveryStatus::NO_BATCH);
        };
        let batch = stored(rss_observation::Batch::decode(bytes))?;
        let reference = stored(rss_mdm_inventory::CollectionReference::from_batch(
            &self.progress.definition,
            &batch,
        ))?;
        if batch.id().as_str() != self.id.to_string()
            || u64::try_from(self.row.try_get::<i64, _>("sequence")?).ok() != Some(batch.sequence())
            || reference.digest() != self.row.try_get::<&str, _>("progress_version")?
            || batch.encode() != bytes
        {
            return Err(Error::Unavailable(Failure::CollectionQuery).into());
        }
        Ok(inventory
            .inspect_report(
                self.scope.tenant(),
                &self.scope,
                &batch,
                control.0,
                control.1,
            )
            .await?)
    }
}

impl AssetService {
    /// Only non-field collection evidence is exposed; inventory values retain their own scopes.
    pub async fn collection_receipt(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        use rss_mdm_audit_integration::operation::{ReceiptStage, ReceiptSummary};
        let principal = &request.proof;
        crate::transaction::inspect_budget(
            &self.runtime,
            principal.binding(),
            request.remaining()?,
            (self, request, *device),
            |context, tx| {
                Box::pin(async move {
                    let (assets, request, device) = *context;
                    let principal = &request.proof;
                    query_authority(tx, principal).await?.require(
                        principal,
                        rss_mdm_authorization_service::Permission::InventoryRead,
                        Some(&device),
                    )?;
                    let Some(evidence) = RunEvidence::read(tx, device, id).await? else {
                        return Ok(None);
                    };
                    let delivery = evidence
                        .delivery(
                            &assets.inventory,
                            (
                                rss_request_context::Deadline::at(request.deadline),
                                rss_request_context::Cancellation::observe(
                                    request.cancellation.as_ref(),
                                ),
                            ),
                        )
                        .await?;
                    principal.check_live()?;
                    let mut value = ReceiptSummary::new(id);
                    value.object = Some(device.to_string());
                    value.recorded_at = Some(evidence.row.try_get("started_at")?);
                    value.completed_at = evidence.row.try_get("sealed_at")?;
                    value.state = Some(evidence.row.try_get("result")?);
                    value.executions.push(id);
                    for (phase, state) in [
                        ("observation", delivery.receipt.status()),
                        ("projection", delivery.projection.status()),
                    ] {
                        value.stages.push(ReceiptStage {
                            phase: phase.into(),
                            revision: None,
                            state: Some(state.into()),
                        });
                    }
                    Ok(Some(value))
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
    pub(super) async fn collection_run(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        scope: &ReadScope,
        read_control: (
            rss_request_context::Deadline,
            rss_request_context::Cancellation<'_>,
        ),
    ) -> Result<RunView> {
        if scope
            .devices
            .as_ref()
            .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let evidence = RunEvidence::read(tx, *device, id)
            .await?
            .ok_or(Error::NotFound)?;
        let row = &evidence.row;
        let progress = &evidence.progress;
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
        let delivery = evidence.delivery(&self.inventory, read_control).await?;
        Ok(RunView {
            epoch: stored(Uuid::parse_str(evidence.scope.epoch().as_str()))?,
            delivery,
            fingerprint: stored(definition.fingerprint())?,
            coverage: stored(definition.coverage())?,
            complete: progress.coverage_complete(),
            id,
            device: row.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })?,

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
    #[expect(
        clippy::too_many_arguments,
        reason = "collection identity, authorized read scope, pagination and caller budget remain independent"
    )]
    pub(super) async fn collection_items(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        field: FieldKey,
        scope: &ReadScope,
        page: (Option<&str>, usize),
        read_control: (
            rss_request_context::Deadline,
            rss_request_context::Cancellation<'_>,
        ),
    ) -> Result<Response> {
        let (cursor, limit) = page;
        if !(1..=1024).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        let run = self
            .collection_run(tx, device, id, scope, read_control)
            .await?;
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
            tx.tenant_id().to_string(),
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
        let tenant = tx.tenant_id().to_string();
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
