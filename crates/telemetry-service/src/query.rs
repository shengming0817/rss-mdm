//! Management queries retain tenant, device and sensitive-field authorization through the read.
use crate::{Error, Service};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_request_context::Deadline;
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use std::{
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
/// A bounded product query. No SQL, tenant override or client-authored definition is accepted.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryRequest {
    pub device: String,
    pub field: String,
    pub resource: String,
    pub start_micros: i64,
    pub end_micros: i64,
    pub max_points: NonZeroU32,
    pub mode: QueryMode,
    pub after: Option<String>,
}
enum ReadKind {
    History,
    Aggregate(Box<AggregateRequest>),
    Health,
    Resources,
}
/// Receipt-window health, with per-field quality counts and no sampled values.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthRequest {
    pub device: String,
    pub field: String,
    pub received_from: i64,
    pub received_until: i64,
    pub max_batches: NonZeroU32,
}
/// Resource identities are public ordering keys, not authorization tokens.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRequest {
    pub device: String,
    pub field: String,
    pub after: Option<String>,
    pub limit: NonZeroU32,
}
struct ReadAuthority<'a>(&'a Query);
impl Authority for ReadAuthority<'_> {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_timeseries::Error> {
        match access {
            Access::Query(q) if q.binding()? == self.0.binding()? => Ok(()),
            _ => Err(rss_timeseries::Error::Unauthorized),
        }
    }
}
impl Service {
    /// Enumerate only this authorized device/field; every continuation repeats authorization.
    pub async fn resources(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &ResourceRequest,
        audit: &RequestAudit,
    ) -> Result<Json, Error> {
        if let Some(after) = &input.after {
            Id::new(after)?;
        }
        let query = HistoryRequest {
            device: input.device.clone(),
            field: input.field.clone(),
            resource: "device".into(),
            start_micros: 0,
            end_micros: 1,
            max_points: input.limit,
            mode: QueryMode::History,
            after: input.after.clone(),
        };
        self.execute(proof, &query, ReadKind::Resources, audit)
            .await
    }
    /// Every page checks current account/device grants; backend cursors grant no authority.
    pub async fn history(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &HistoryRequest,
        audit: &RequestAudit,
    ) -> Result<Json, Error> {
        self.execute(proof, input, ReadKind::History, audit).await
    }
    /// Aggregate one exact immutable definition and source incarnation with explicit gap semantics.
    pub async fn aggregate(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &AggregateRequest,
        audit: &RequestAudit,
    ) -> Result<Json, Error> {
        if input.query.mode != QueryMode::History {
            return Err(Error::Invalid);
        }
        self.execute(
            proof,
            &input.query,
            ReadKind::Aggregate(Box::new(input.clone())),
            audit,
        )
        .await
    }
    /// Health applies the same device and sensitive-field checks as sample reads.
    pub async fn health(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &HealthRequest,
        audit: &RequestAudit,
    ) -> Result<Json, Error> {
        Interval::new(
            Timestamp::new(input.received_from)?,
            Timestamp::new(input.received_until)?,
        )?;
        let query = HistoryRequest {
            device: input.device.clone(),
            field: input.field.clone(),
            resource: "device".into(),
            start_micros: input.received_from,
            end_micros: input.received_until,
            max_points: input.max_batches,
            mode: QueryMode::History,
            after: None,
        };
        self.execute(proof, &query, ReadKind::Health, audit).await
    }
    async fn execute(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &HistoryRequest,
        kind: ReadKind,
        audit: &RequestAudit,
    ) -> Result<Json, Error> {
        proof.check_live().map_err(|_| Error::Denied)?;
        if proof.tenant_id() != self.tenant.to_string()
            || input.max_points.get() > self.storage_budget.points.get()
        {
            return Err(Error::Denied);
        }
        let service = self.clone();
        let proof = proof.clone();
        let input = input.clone();
        let audit = audit.clone();
        let failure = Arc::new(Mutex::new(None));
        let rejected = failure.clone();
        let settled = self
            .runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    service
                        .planning
                        .audit_store
                        .bind_in(tx)
                        .await
                        .map_err(crate::storage_error)?;
                    let read_service = service.clone();
                    let read_audit = audit.clone();
                    let result = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                read_on(&read_service, c, &proof, &input, &kind, &read_audit)
                                    .await
                                    .map_err(|e| {
                                        *rejected.lock().expect("query rejection") = Some(e);
                                        sqlx::Error::Protocol("telemetry query rejected".into())
                                    })
                            })
                        })
                        .await?;
                    audit.require_request_settlement();
                    Ok(result)
                })
            })
            .await;
        settled.fold(
            Ok,
            |_| Err(Error::Storage),
            |_| {
                Err(failure
                    .lock()
                    .expect("query rejection")
                    .unwrap_or(Error::Storage))
            },
            |_| Err(Error::Unknown),
            |_| Err(Error::Unknown),
            |_| Err(Error::Storage),
        )
    }
}
async fn read_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    input: &HistoryRequest,
    kind: &ReadKind,
    _audit: &RequestAudit,
) -> Result<Json, Error> {
    rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
        .await
        .map_err(|_| Error::Denied)?;
    let authorization =
        rss_mdm_authorization_service::snapshot_on(c, proof.tenant_id(), proof.instance_id())
            .await
            .map_err(|_| Error::Denied)?;
    authorization
        .require(proof, Permission::InventoryRead, Some(&input.device))
        .map_err(|_| Error::Denied)?;
    let key = rss_mdm_inventory::FieldKey::parse(&input.field).map_err(|_| Error::Invalid)?;
    let (field, retired) = rss_mdm_inventory_postgres::historical_field_in(c, service.tenant, key)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Invalid)?;
    if field.sensitivity == rss_mdm_inventory::Sensitivity::Sensitive {
        authorization
            .require(proof, Permission::InventorySensitiveRead, None)
            .map_err(|_| Error::Denied)?;
    }
    if field.time_series.is_none() && !matches!(kind, ReadKind::Health) {
        return Err(Error::Invalid);
    }
    if let ReadKind::Aggregate(aggregate) = kind {
        let result = aggregate_on(service, c, input, aggregate).await?;
        proof.check_live().map_err(|_| Error::Denied)?;
        return Ok(result);
    }
    if let ReadKind::Resources = kind {
        let mut resources:Vec<String>=sqlx::query_scalar("SELECT resource FROM mdm_telemetry.resources WHERE tenant_id=$1::uuid AND device=$2 AND field=$3 AND ($4::text IS NULL OR resource>$4) ORDER BY resource LIMIT $5")
            .bind(service.tenant.to_string()).bind(&input.device).bind(&input.field).bind(&input.after).bind(i64::from(input.max_points.get())+1).fetch_all(c).await?;
        let more = resources.len() > input.max_points.get() as usize;
        resources.truncate(input.max_points.get() as usize);
        let next = if more {
            resources.last().cloned()
        } else {
            None
        };
        proof.check_live().map_err(|_| Error::Denied)?;
        return Ok(json!({"resources":resources,"nextAfter":next,"retired":retired}));
    }
    if let ReadKind::Health = kind {
        let mut rows=sqlx::query("SELECT id,received_at,first_observed,last_observed,delivery,quality->$3 AS quality FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2 AND $3=ANY(fields) AND received_at>=$4 AND received_at<$5 ORDER BY received_at DESC,id DESC LIMIT $6")
            .bind(service.tenant.to_string()).bind(&input.device).bind(&input.field).bind(input.start_micros).bind(input.end_micros).bind(i64::from(input.max_points.get())+1).fetch_all(&mut *c).await?;
        let batches_truncated = rows.len() > input.max_points.get() as usize;
        rows.truncate(input.max_points.get() as usize);
        use sqlx::Row;
        let rows=rows.into_iter().map(|row|Ok(json!({"batchId":row.try_get::<uuid::Uuid,_>("id")?,"receivedAt":row.try_get::<i64,_>("received_at")?,"firstObserved":row.try_get::<i64,_>("first_observed")?,"lastObserved":row.try_get::<i64,_>("last_observed")?,"delivery":row.try_get::<String,_>("delivery")?,"qualityCounts":row.try_get::<Json,_>("quality")?}))).collect::<Result<Vec<_>,sqlx::Error>>()?;
        let mut retention=sqlx::query("SELECT resource,version,due_at,phase,result FROM mdm_telemetry.retention_targets WHERE tenant_id=$1::uuid AND device=$2 AND field=$3 ORDER BY due_at,id LIMIT $4")
            .bind(service.tenant.to_string()).bind(&input.device).bind(&input.field).bind(i64::from(input.max_points.get())+1).fetch_all(c).await?;
        let retention_truncated = retention.len() > input.max_points.get() as usize;
        retention.truncate(input.max_points.get() as usize);
        let retention=retention.into_iter().map(|row|Ok(json!({"resource":row.try_get::<String,_>("resource")?,"definitionVersion":row.try_get::<i64,_>("version")?,"dueAt":row.try_get::<i64,_>("due_at")?,"phase":row.try_get::<i16,_>("phase")?,"progress":row.try_get::<Option<Json>,_>("result")?}))).collect::<Result<Vec<_>,sqlx::Error>>()?;
        proof.check_live().map_err(|_| Error::Denied)?;
        return Ok(
            json!({"batches":rows,"batchesTruncated":batches_truncated,"retention":retention,"retentionTruncated":retention_truncated,"qualityOrder":["valid","missing","failed"],"retired":retired}),
        );
    }
    if input.mode == QueryMode::Latest && input.after.is_some() {
        return Err(Error::Invalid);
    }
    let query = Query::new(
        Selection::Resource {
            scope: Scope::new(service.tenant, Id::new("mdm.telemetry")?),
            subject: Id::new(&input.device)?,
            resource: Id::new(&input.resource)?,
            keys: [Id::new(&input.field)?].into(),
        },
        Interval::new(
            Timestamp::new(input.start_micros)?,
            Timestamp::new(input.end_micros)?,
        )?,
        QueryBudget {
            max_series: service.storage_budget.series,
            max_points: if input.mode == QueryMode::Latest {
                service.storage_budget.points
            } else {
                input.max_points
            },
        },
        input.mode,
    )?;
    let binding = query.binding()?;
    let cursor = input
        .after
        .as_ref()
        .map(|v| rss_contract::PageCursor::parse(v).map(|v| Continuation::new(binding, v)))
        .transpose()
        .map_err(|_| Error::Invalid)?;
    let live = rss_mdm_registration_service::device::store::live_collection_streams_on(
        c,
        service.tenant,
        &input.device,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let authorized = Authorized::<Query>::verify(&ReadAuthority(&query), query.clone())?;
    let cutoff = Deadline::from_timeout(
        &crate::backend::SystemClock,
        std::time::Duration::from_secs(6),
    )
    .map_err(|_| Error::Invalid)?;
    let mut page = service
        .backend
        .query(&authorized, cursor.as_ref(), cutoff)
        .await?;
    let mut candidates = std::mem::take(&mut page.rows);
    if input.mode == QueryMode::Latest {
        // Never resolve source priority from an incomplete page. A bounded exact resource read
        // either sees all candidates or fails explicitly; history retains provider pagination.
        while let Some(next) = page.next.take() {
            let part = service
                .backend
                .query(&authorized, Some(&next), cutoff)
                .await?;
            if candidates.len().saturating_add(part.rows.len())
                > service.storage_budget.series.get() as usize
            {
                return Err(Error::Capacity);
            }
            candidates.extend(part.rows);
            page.next = part.next;
            page.availability
                .excluded
                .extend(part.availability.excluded);
            if page.availability.excluded.len() > service.storage_budget.series.get() as usize {
                return Err(Error::Capacity);
            }
        }
    }
    let rows = if input.mode == QueryMode::Latest {
        latest(
            candidates,
            &live,
            &field,
            retired,
            input.max_points.get() as usize,
        )?
    } else {
        candidates.into_iter().map(|row| {
            let live_source=!retired && source(&row,&live).is_some();
            json!({"sample":row.sample,"receivedAt":row.received_at.micros(),"liveSource":live_source})
        }).collect()
    };
    let unavailable=page.availability.excluded.into_iter().map(|r|json!({"selection":r.selection,"window":r.window,"reason":match r.reason {UnavailableReason::Deleted=>"deleted",UnavailableReason::Pruned=>"pruned"}})).collect::<Vec<_>>();
    let next = page
        .next
        .as_ref()
        .map(|v| v.verify(binding).map(|v| v.as_str().to_owned()))
        .transpose()?;
    proof.check_live().map_err(|_| Error::Denied)?;
    Ok(
        json!({"rows":rows,"unavailable":unavailable,"next":next,"retired":retired,"mode":input.mode}),
    )
}

/// Explicit statistical semantics and exact source/definition identity, returned by history.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateRequest {
    pub query: HistoryRequest,
    pub definition_version: std::num::NonZeroU64,
    pub registration: uuid::Uuid,
    pub source: rss_mdm_inventory::Source,
    pub epoch: uuid::Uuid,
    pub dimensions: std::collections::BTreeMap<String, String>,
    pub resolution_micros: std::num::NonZeroU64,
    pub operation: AggregateOp,
    pub coverage: CoveragePolicy,
    pub max_gap_micros: Option<std::num::NonZeroU64>,
}
struct AggregateAuthority<'a>(&'a AggregateQuery);
impl Authority for AggregateAuthority<'_> {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_timeseries::Error> {
        match access {
            Access::Aggregate(q) if q.binding()? == self.0.binding()? => Ok(()),
            _ => Err(rss_timeseries::Error::Unauthorized),
        }
    }
}
async fn aggregate_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    input: &HistoryRequest,
    request: &AggregateRequest,
) -> Result<Json, Error> {
    if request.definition_version.get() > i64::MAX as u64 || request.dimensions.len() > 64 {
        return Err(Error::Invalid);
    }
    let raw:Option<String>=sqlx::query_scalar("SELECT definition::text FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field=$2 AND version=$3 AND definition IS NOT NULL")
        .bind(service.tenant.to_string()).bind(&input.field).bind(request.definition_version.get() as i64).fetch_optional(c).await?;
    let field: rss_mdm_inventory::FieldDefinition =
        serde_json::from_str(&raw.ok_or(Error::Invalid)?)?;
    field.validate().map_err(|_| Error::Invalid)?;
    let operation = match request.operation {
        AggregateOp::Min => rss_mdm_inventory::TelemetryAggregation::Min,
        AggregateOp::Max => rss_mdm_inventory::TelemetryAggregation::Max,
        AggregateOp::Sum => rss_mdm_inventory::TelemetryAggregation::Sum,
        AggregateOp::Count => rss_mdm_inventory::TelemetryAggregation::Count,
        AggregateOp::Mean => rss_mdm_inventory::TelemetryAggregation::Mean,
        AggregateOp::Increase => rss_mdm_inventory::TelemetryAggregation::Increase,
        AggregateOp::Rate => rss_mdm_inventory::TelemetryAggregation::Rate,
        AggregateOp::Timeline => rss_mdm_inventory::TelemetryAggregation::Timeline,
        AggregateOp::Transitions => rss_mdm_inventory::TelemetryAggregation::Transitions,
        AggregateOp::Coverage => rss_mdm_inventory::TelemetryAggregation::Coverage,
    };
    if !field
        .time_series
        .as_ref()
        .ok_or(Error::Invalid)?
        .aggregations
        .contains(&operation)
        || !field.sources.contains_key(&request.source)
    {
        return Err(Error::Denied);
    }
    let scope = Scope::new(service.tenant, Id::new("mdm.telemetry")?);
    let stream = Stream::new(
        scope.clone(),
        Id::new(format!(
            "{}:{}",
            request.registration,
            request.source.as_str()
        ))?,
        Id::new(request.epoch.to_string())?,
    );
    let series = Series::new(
        field
            .time_series_definition(scope)
            .map_err(|_| Error::Invalid)?,
        Id::new(&input.device)?,
        Id::new(&input.resource)?,
        request
            .dimensions
            .iter()
            .map(|(k, v)| Ok((Id::new(k)?, Id::new(v)?)))
            .collect::<Result<_, rss_timeseries::Error>>()?,
    )?;
    let spec = SummarySpec::new(
        stream,
        series,
        request.resolution_micros,
        request.coverage,
        request.max_gap_micros,
    )?;
    let query = AggregateQuery::new(
        spec,
        Interval::new(
            Timestamp::new(input.start_micros)?,
            Timestamp::new(input.end_micros)?,
        )?,
        QueryBudget {
            max_series: NonZeroU32::new(1).expect("one series"),
            max_points: input.max_points,
        },
        request.operation,
    )?;
    let binding = query.binding()?;
    let cursor = input
        .after
        .as_ref()
        .map(|v| rss_contract::PageCursor::parse(v).map(|v| Continuation::new(binding, v)))
        .transpose()
        .map_err(|_| Error::Invalid)?;
    let authorized =
        Authorized::<AggregateQuery>::verify(&AggregateAuthority(&query), query.clone())?;
    let deadline = Deadline::from_timeout(
        &crate::backend::SystemClock,
        std::time::Duration::from_secs(6),
    )
    .map_err(|_| Error::Invalid)?;
    let page = service
        .backend
        .aggregate(&authorized, cursor.as_ref(), deadline)
        .await?;
    let unavailable=page.availability.excluded.into_iter().map(|r|json!({"selection":r.selection,"window":r.window,"reason":match r.reason {UnavailableReason::Deleted=>"deleted",UnavailableReason::Pruned=>"pruned"}})).collect::<Vec<_>>();
    let next = page
        .next
        .as_ref()
        .map(|v| v.verify(binding).map(|v| v.as_str().to_owned()))
        .transpose()?;
    Ok(
        json!({"buckets":page.buckets,"unavailable":unavailable,"resolutionMicros":page.resolution_micros,"refreshedThrough":page.refreshed_through.map(|v|v.micros()),"next":next}),
    )
}

fn source(
    row: &ObservedSample,
    live: &[(uuid::Uuid, String, uuid::Uuid)],
) -> Option<rss_mdm_inventory::Source> {
    live.iter()
        .find(|(registration, source, epoch)| {
            row.sample.input().stream.source().as_str() == format!("{registration}:{source}")
                && row.sample.input().stream.generation().as_str() == epoch.to_string()
        })
        .and_then(|(_, source, _)| rss_mdm_inventory::Source::parse(source).ok())
}
fn latest(
    rows: Vec<ObservedSample>,
    live: &[(uuid::Uuid, String, uuid::Uuid)],
    field: &rss_mdm_inventory::FieldDefinition,
    retired: bool,
    limit: usize,
) -> Result<Vec<Json>, Error> {
    use std::collections::BTreeMap;
    if retired {
        return Ok(Vec::new());
    }
    let mut per_source = BTreeMap::<(Vec<u8>, rss_mdm_inventory::Source), ObservedSample>::new();
    for row in rows {
        let Some(source) = source(&row, live).filter(|v| field.sources.contains_key(v)) else {
            continue;
        };
        let key = (
            serde_json::to_vec(row.sample.input().series.dimensions())?,
            source,
        );
        let tuple = |r: &ObservedSample| {
            (
                r.sample.input().observed_at,
                r.sample.input().sequence,
                r.sample.input().id.as_str().to_owned(),
            )
        };
        if per_source
            .get(&key)
            .is_none_or(|old| tuple(&row) > tuple(old))
        {
            per_source.insert(key, row);
        }
    }
    let mut selected = BTreeMap::<Vec<u8>, (u16, Vec<ObservedSample>)>::new();
    for ((dimensions, source), row) in per_source {
        let priority = field.sources[&source];
        let (best, rows) = selected.entry(dimensions).or_insert((priority, Vec::new()));
        if priority < *best {
            *best = priority;
            rows.clear();
        }
        if priority == *best {
            rows.push(row);
        }
    }
    if selected.values().map(|(_, v)| v.len()).sum::<usize>() > limit {
        return Err(Error::Capacity);
    }
    let mut result = Vec::new();
    for (_, (_, rows)) in selected {
        let conflict = rows
            .windows(2)
            .any(|v| v[0].sample.input().reading != v[1].sample.input().reading);
        for row in rows {
            result.push(json!({"sample":row.sample,"receivedAt":row.received_at.micros(),"effectiveSource":!conflict,"sourceConflict":conflict}));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(
        registration: uuid::Uuid,
        epoch: uuid::Uuid,
        source: rss_mdm_inventory::Source,
        at: i64,
        value: i64,
    ) -> ObservedSample {
        let profile = crate::tests::profile(rss_mdm_resource::TelemetryProjection::History);
        let mut input = crate::tests::input();
        input.observations[0].observed_at = at;
        input.observations[0].sequence = at as u64;
        input.observations[0].values.values_mut().for_each(|v| {
            *v = rss_mdm_agent_wire::runtime::TelemetryReading::Valid {
                value: rss_mdm_agent_wire::runtime::Scalar::Integer(value),
                interval_start: None,
            }
        });
        let scope = Scope::new(
            rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            Id::new("mdm.telemetry").unwrap(),
        );
        let stream = Stream::new(
            scope,
            Id::new(format!("{registration}:{}", source.as_str())).unwrap(),
            Id::new(epoch.to_string()).unwrap(),
        );
        let batch = crate::samples::prepare(
            &profile,
            &crate::tests::fields(),
            &input,
            stream,
            "device",
            3_000_000,
        )
        .unwrap()
        .unwrap();
        ObservedSample {
            sample: batch.samples()[0].clone(),
            received_at: Timestamp::new(3_000_000).unwrap(),
        }
    }
    #[test]
    fn latest_uses_live_incarnation_and_source_priority_instead_of_receipt_order() {
        use rss_mdm_inventory::Source::{AgentNative, AgentScript};
        let registration = uuid::Uuid::new_v4();
        let epoch = uuid::Uuid::new_v4();
        let mut field = crate::tests::fields().remove(0);
        field.sources.insert(AgentNative, 0);
        field.sources.insert(AgentScript, 1);
        let live = vec![
            (registration, AgentNative.as_str().into(), epoch),
            (registration, AgentScript.as_str().into(), epoch),
        ];
        let values = vec![
            row(registration, epoch, AgentNative, 100, 1),
            row(registration, epoch, AgentNative, 200, 2),
            row(registration, epoch, AgentScript, 300, 3),
            row(uuid::Uuid::new_v4(), epoch, AgentNative, 400, 4),
        ];
        let result = latest(values.clone(), &live, &field, false, 16).unwrap();
        assert_eq!(result.len(), 1);
        let selected: Sample = serde_json::from_value(result[0]["sample"].clone()).unwrap();
        assert_eq!(selected.input().observed_at.micros(), 200);
        assert_eq!(result[0]["effectiveSource"], true);
        assert!(
            latest(values.clone(), &live, &field, true, 16)
                .unwrap()
                .is_empty()
        );
        field.sources.insert(AgentScript, 0);
        let conflict = latest(values, &live, &field, false, 16).unwrap();
        assert_eq!(conflict.len(), 2);
        assert!(
            conflict
                .iter()
                .all(|v| v["sourceConflict"] == true && v["effectiveSource"] == false)
        );
    }
}
