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
    tenant: TenantId,
    device: rss_mdm_agent_wire::DeviceId,
}

impl RunEvidence {
    async fn read(
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        fields: bool,
    ) -> Result<Option<Self>> {
        let tenant = tx.tenant_id();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT c.device, c.source, c.sequence, c.started_at, c.sealed_at, c.result, c.reason, c.scope, c.batch, c.digest, c.progress_version, CASE WHEN v.metadata_bytes <= 67108864 THEN CAST(v.metadata AS text) END AS metadata FROM mdm_access.collection_runs AS c LEFT JOIN mdm_access.collection_versions AS v ON $4 AND (v.tenant_id, v.version) = (c.tenant_id, c.progress_version) INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (c.tenant_id, c.device) WHERE c.tenant_id = CAST($1 AS uuid) AND c.id = $2 AND r.id = $3")
                .bind(tenant.to_string()).bind(id).bind(device.into_uuid()).bind(fields).fetch_optional(c).await
        })).await?;
        Ok(row.map(|row| Self {
            id,
            row,
            tenant,
            device,
        }))
    }

    fn scope(&self) -> Result<rss_observation::Scope> {
        let scope: rss_observation::Scope =
            stored(serde_json::from_str(self.row.try_get("scope")?))?;
        if scope.tenant() != self.tenant || scope.registration().as_str() != self.device.to_string()
        {
            return Err(Error::Unavailable(Failure::CollectionQuery).into());
        }
        Ok(scope)
    }

    async fn delivery(
        &self,
        inventory: &crate::inventory_runtime::InventoryRuntime,
        definition: Option<&rss_mdm_inventory::CollectionDefinition>,
        control: (
            rss_request_context::Deadline,
            rss_request_context::Cancellation<'_>,
        ),
    ) -> Result<crate::inventory_runtime::DeliveryStatus> {
        let Some(bytes) = self.row.try_get::<Option<&[u8]>, _>("batch")? else {
            return Ok(crate::inventory_runtime::DeliveryStatus::NO_BATCH);
        };
        let batch = stored(rss_observation::Batch::decode(bytes))?;
        let scope = self.scope()?;
        if let Some(definition) = definition {
            let reference = stored(rss_mdm_inventory::CollectionReference::from_batch(
                definition, &batch,
            ))?;
            if reference.digest() != self.row.try_get::<&str, _>("progress_version")? {
                return Err(Error::Unavailable(Failure::CollectionQuery).into());
            }
        }
        if batch.id().as_str() != self.id.to_string()
            || u64::try_from(self.row.try_get::<i64, _>("sequence")?).ok() != Some(batch.sequence())
            || crate::collection::store::fingerprint(&batch, &scope)?
                != self.row.try_get::<&str, _>("digest")?
            || batch.encode() != bytes
        {
            return Err(Error::Unavailable(Failure::CollectionQuery).into());
        }
        Ok(inventory
            .inspect_report(self.tenant, &scope, &batch, control.0, control.1)
            .await?)
    }
}

pub struct ReportDiagnostics {
    pub original: rss_mdm_audit_integration::operation::ReceiptSummary,
    pub delivery: std::result::Result<crate::inventory_runtime::DeliveryStatus, Error>,
}

impl AssetService {
    /// Read the original authorized collection before observing current delivery evidence.
    pub async fn collection_receipt(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> std::result::Result<Option<ReportDiagnostics>, Error> {
        let principal = &request.proof;
        let original = crate::transaction::inspect_budget(
            &self.runtime,
            principal.binding(),
            request.remaining()?,
            (principal, *device),
            |ctx, tx| {
                Box::pin(async move {
                    let (principal, device) = *ctx;
                    let access =
                        query_authority_with_lock(tx, principal, AuthorityLock::Shared).await?;
                    access.require(
                        principal,
                        rss_mdm_authorization_service::Permission::InventoryRead,
                        Some(&device),
                    )?;
                    let Some(evidence) = RunEvidence::read(tx, device, id, false).await? else {
                        return Ok(None);
                    };
                    let mut summary = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                    summary.object = Some(device.to_string());
                    summary.recorded_at = Some(evidence.row.try_get("started_at")?);
                    summary.completed_at = evidence.row.try_get("sealed_at")?;
                    summary.state = Some(evidence.row.try_get("result")?);
                    summary.executions.push(id);
                    Ok(Some((summary, evidence, access.query_binding(principal)?)))
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await?;
        let Some((original, evidence, binding)) = original else {
            return Ok(None);
        };
        let remaining = request.remaining()?.timeout();
        let reserve = remaining - (remaining / 2).min(std::time::Duration::from_secs(1));
        let probe_cutoff = request.deadline - reserve;
        let probe = evidence.delivery(
            &self.inventory,
            None,
            (
                rss_request_context::Deadline::at(probe_cutoff),
                rss_request_context::Cancellation::observe(request.cancellation.as_ref()),
            ),
        );
        let delivery = tokio::time::timeout_at(probe_cutoff.into(), probe)
            .await
            .map_err(|_| Error::Unavailable(Failure::RequestDeadline))
            .and_then(|result| {
                result.map_err(|e| match e {
                    Fault::Request(error) => error,
                    _ => Error::Unavailable(Failure::CollectionQuery),
                })
            });
        let fresh = request.revalidate().await?;
        crate::transaction::inspect_budget(
            &self.runtime,
            principal.binding(),
            request.remaining()?,
            (request, *device, fresh, binding),
            |ctx, tx| {
                Box::pin(async move {
                    let (request, device, fresh, binding) = ctx;
                    let current =
                        query_authority_with_lock(tx, &request.proof, AuthorityLock::Shared)
                            .await?;
                    current.require(
                        &request.proof,
                        rss_mdm_authorization_service::Permission::InventoryRead,
                        Some(device),
                    )?;
                    if request.current_binding(&current, fresh.as_ref())? != *binding {
                        return Err(Error::Forbidden.into());
                    }
                    Ok(())
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await?;
        Ok(Some(ReportDiagnostics { original, delivery }))
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
        let evidence = RunEvidence::read(tx, *device, id, true)
            .await?
            .ok_or(Error::NotFound)?;
        let row = &evidence.row;
        let coordinate = evidence.scope()?;
        let progress = stored(crate::collection::summary::Summary::decode(
            row.try_get("metadata")?,
        ))?;
        stored(progress.definition.validate_scope(&coordinate))?;
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
        let delivery = evidence
            .delivery(&self.inventory, Some(definition), read_control)
            .await?;
        Ok(RunView {
            epoch: stored(Uuid::parse_str(coordinate.epoch().as_str()))?,
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
