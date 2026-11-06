//! All views address the same completed task and revalidate its input coordinates.
use super::*;
use rss_mdm_query::cursor::CursorCodec;
use serde::de::DeserializeOwned;
use sqlx::Row;
impl AssetService {
    fn software_page(
        &self,
        scope: &ReadScope,
        binding: &impl serde::Serialize,
        page: &Page,
    ) -> Result<(usize, String, String)> {
        if !(1..=1000).contains(&page.limit) {
            return Err(Error::Malformed.into());
        }
        let binding = digest(&("software-assets", self.tenant.to_string(), scope, binding))?;
        let position = if let Some(token) = &page.cursor {
            CursorCodec::from_key(self.asset_cursor_key.clone())
                .decode::<String>(
                    &checked_input(rss_contract::PageCursor::parse(token))?,
                    &binding,
                )
                .map_err(|_| Error::Conflict)?
        } else {
            String::new()
        };
        Ok((page.limit, position, binding))
    }
    fn software_next(&self, binding: &str, position: Option<&str>) -> Result<Option<String>> {
        position
            .map(|value| {
                Ok(checked_input(
                    CursorCodec::from_key(self.asset_cursor_key.clone())
                        .encode(binding, &value.to_owned()),
                )?
                .as_str()
                .to_owned())
            })
            .transpose()
    }
    pub(super) async fn software_directory<T: DeserializeOwned>(
        &self,
        tx: &mut PgTransaction<'_>,
        kind: &'static str,
        scope: &ReadScope,
        page: &Page,
    ) -> Result<(Vec<Record<T>>, Option<String>)> {
        let revision = self.software_revision(tx, false).await?;
        let (limit, after, binding) = self.software_page(scope, &(kind, revision), page)?;
        let tenant = self.tenant.to_string();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT id,octet_length(document::text) bytes FROM mdm_assets.software_records WHERE tenant_id=$1::uuid AND kind=$2 AND document IS NOT NULL AND id::text COLLATE \"C\">$3 COLLATE \"C\" ORDER BY id LIMIT $4")
                .bind(tenant).bind(kind).bind(after).bind((limit+1) as i64).fetch_all(c).await
        })).await?;
        let mut more = rows.len() > limit;
        let mut ids = Vec::new();
        let mut bytes = 0usize;
        for row in rows.into_iter().take(limit) {
            let size = row.try_get::<i32, _>("bytes")? as usize + 512;
            if bytes + size > 8 * 1024 * 1024 {
                more = true;
                break;
            }
            bytes += size;
            ids.push(row.try_get::<Uuid, _>("id")?);
        }
        let next = if more {
            ids.last().map(ToString::to_string)
        } else {
            None
        };
        let tenant = self.tenant.to_string();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT id,revision,document FROM mdm_assets.software_records WHERE tenant_id=$1::uuid AND kind=$2 AND id=ANY($3) ORDER BY id")
                .bind(tenant).bind(kind).bind(ids).fetch_all(c).await
        })).await?;
        let items = rows
            .into_iter()
            .map(|row| {
                Ok(Record {
                    id: row.try_get("id")?,
                    revision: row.try_get::<i64, _>("revision")? as u64,
                    definition: Some(stored(serde_json::from_value(row.try_get("document")?))?),
                })
            })
            .collect::<Result<_>>()?;
        Ok((items, self.software_next(&binding, next.as_deref())?))
    }
    pub(super) async fn software_read(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ReadScope,
        command: &Command,
    ) -> Result<Response> {
        let id = match command {
            Command::Status { id }
            | Command::Coverage { id, .. }
            | Command::Buckets { id, .. }
            | Command::Breakdowns { id, .. }
            | Command::Devices { id, .. }
            | Command::Evidence { id, .. } => *id,
            _ => return Err(Error::Malformed.into()),
        };
        let state = self.query_task_in(tx, id).await?;
        if &state.input.scope != scope {
            return Err(Error::Forbidden.into());
        }
        let job = state.input.software.as_ref().ok_or(Error::NotFound)?;
        self.software_current(tx, job).await?;
        let coordinates = job.coordinates.clone();
        let tenant = self.tenant.to_string();
        let uncertain:i64=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT uncertain FROM mdm_assets.software_progress WHERE tenant_id=$1::uuid AND run=$2").bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        if matches!(command, Command::Status { .. }) {
            return Ok(Response::Status {
                task: id,
                status: if state.failure.is_some() {
                    "failed"
                } else if state.completed {
                    "completed"
                } else if state.started {
                    "running"
                } else {
                    "pending"
                }
                .into(),
                failure: state.failure,
                coordinates,
                processed: state.summary.total as u64,
                unknown: state.summary.unknown as u64,
            });
        }
        if !state.completed || state.failure.is_some() {
            return Err(Error::Conflict.into());
        }
        match command {
            Command::Coverage { page, .. } => {
                let (limit, after, binding) =
                    self.software_page(scope, &(id, "coverage", &coordinates), page)?;
                let tenant = self.tenant.to_string();
                let metadata=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("SELECT object,octet_length(document::text) bytes FROM mdm_assets.software_objects WHERE tenant_id=$1::uuid AND run=$2 AND object COLLATE \"C\">$3 COLLATE \"C\" ORDER BY object COLLATE \"C\" LIMIT $4").bind(tenant).bind(id).bind(after).bind((limit+1) as i64).fetch_all(c).await
                })).await?;
                let mut more = metadata.len() > limit;
                let mut ids = Vec::new();
                let mut bytes = 0usize;
                for row in metadata.into_iter().take(limit) {
                    let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
                    if bytes + size > 16 * 1024 * 1024 {
                        if ids.is_empty() {
                            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
                        }
                        more = true;
                        break;
                    }
                    bytes += size;
                    ids.push(row.try_get::<String, _>("object")?);
                }
                let next_cursor = self.software_next(
                    &binding,
                    if more {
                        ids.last().map(String::as_str)
                    } else {
                        None
                    },
                )?;
                let tenant = self.tenant.to_string();
                let rows:Vec<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar("SELECT document FROM mdm_assets.software_objects WHERE tenant_id=$1::uuid AND run=$2 AND object=ANY($3) ORDER BY object COLLATE \"C\"").bind(tenant).bind(id).bind(ids).fetch_all(c).await
                })).await?;
                let items = rows
                    .into_iter()
                    .map(|v| {
                        let o: ObjectResult = stored(serde_json::from_value(v))?;
                        Ok(CoverageItem {
                            object: o.object,
                            matched: o.matched,
                            unknown: o.unknown,
                            quality: o.quality,
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok(Response::Coverage {
                    task: id,
                    coordinates,
                    items,
                    next_cursor,
                })
            }
            Command::Buckets { page, .. } => {
                let (limit, after, binding) =
                    self.software_page(scope, &(id, "buckets", &coordinates), page)?;
                let tenant = self.tenant.to_string();
                let rows = tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("SELECT b.id,b.standard,b.identity,octet_length(b.identity::text) AS bytes,count(*) AS assessment,count(*) FILTER(WHERE m.selected) AS selected,count(*) FILTER(WHERE m.selected AND m.compliance='disabled') AS disabled,count(*) FILTER(WHERE m.selected AND m.compliance='compliant') AS compliant,count(*) FILTER(WHERE m.selected AND m.compliance='non_compliant') AS non_compliant,count(*) FILTER(WHERE m.selected AND m.compliance='unknown') AS unknown FROM mdm_assets.software_buckets b JOIN mdm_assets.software_members m ON(m.tenant_id,m.run,m.bucket)=(b.tenant_id,b.run,b.id) WHERE b.tenant_id=$1::uuid AND b.run=$2 AND b.id COLLATE \"C\">$3 COLLATE \"C\" GROUP BY b.id,b.standard,b.identity HAVING bool_or(m.selected) ORDER BY b.id COLLATE \"C\" LIMIT $4")
                        .bind(tenant).bind(id).bind(after).bind((limit+1) as i64).fetch_all(c).await
                })).await?;
                let mut more = rows.len() > limit;
                let mut items = Vec::new();
                let mut bytes = 0usize;
                for row in rows.into_iter().take(limit) {
                    let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
                    if bytes + size > 8 * 1024 * 1024 {
                        more = true;
                        break;
                    }
                    bytes += size;
                    let standard: Option<Uuid> = row.try_get("standard")?;
                    let threshold = standard
                        .and_then(|id| job.configuration.standards.iter().find(|s| s.id == id))
                        .and_then(|s| s.definition.as_ref())
                        .and_then(|s| s.assessments.get(job.query.context).threshold);
                    let assessment = row.try_get::<i64, _>("assessment")? as u64;
                    let threshold_state = match threshold {
                        None => ThresholdState::Disabled,
                        Some(n) if assessment >= n => ThresholdState::Reached,
                        Some(_) if uncertain > 0 => ThresholdState::Unknown,
                        Some(_) => ThresholdState::Below,
                    };
                    items.push(Bucket {
                        id: row.try_get("id")?,
                        identity: stored(serde_json::from_value(row.try_get("identity")?))?,
                        devices: row.try_get::<i64, _>("selected")? as u64,
                        assessment_devices: assessment,
                        threshold,
                        threshold_state,
                        compliance: ComplianceCounts {
                            disabled: row.try_get::<i64, _>("disabled")? as u64,
                            compliant: row.try_get::<i64, _>("compliant")? as u64,
                            non_compliant: row.try_get::<i64, _>("non_compliant")? as u64,
                            unknown: row.try_get::<i64, _>("unknown")? as u64,
                        },
                    });
                }
                let next_cursor = self.software_next(
                    &binding,
                    more.then(|| items.last().map(|b| b.id.as_str())).flatten(),
                )?;
                Ok(Response::Buckets {
                    task: id,
                    coordinates,
                    items,
                    next_cursor,
                })
            }
            Command::Breakdowns {
                bucket,
                dimension,
                page,
                ..
            } => {
                if !job.query.dimensions.contains(dimension) {
                    return Err(Error::Malformed.into());
                }
                let (limit, after, binding) =
                    self.software_page(scope, &(id, bucket, dimension, &coordinates), page)?;
                let dimension = stored(serde_json::to_value(dimension))?
                    .as_str()
                    .ok_or(Error::Malformed)?
                    .to_owned();
                let tenant = self.tenant.to_string();
                let bucket = bucket.clone();
                let rows=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("SELECT v.value,count(DISTINCT e.object) AS devices FROM mdm_assets.software_evidence e CROSS JOIN LATERAL jsonb_array_elements_text(e.dimensions->$3) v(value) WHERE e.tenant_id=$1::uuid AND e.run=$2 AND e.bucket=$4 AND e.selected AND e.confirmed AND v.value COLLATE \"C\">$5 COLLATE \"C\" GROUP BY v.value ORDER BY v.value COLLATE \"C\" LIMIT $6")
                        .bind(tenant).bind(id).bind(dimension).bind(bucket).bind(after).bind((limit+1) as i64).fetch_all(c).await
                })).await?;
                let more = rows.len() > limit;
                let items = rows
                    .into_iter()
                    .take(limit)
                    .map(|r| {
                        Ok(Breakdown {
                            value: r.try_get("value")?,
                            devices: r.try_get::<i64, _>("devices")? as u64,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let next_cursor = self.software_next(
                    &binding,
                    more.then(|| items.last().map(|v| v.value.as_str()))
                        .flatten(),
                )?;
                Ok(Response::Breakdowns {
                    task: id,
                    coordinates,
                    items,
                    next_cursor,
                })
            }
            Command::Devices { bucket, page, .. } => {
                let (limit, after, binding) =
                    self.software_page(scope, &(id, bucket, "devices", &coordinates), page)?;
                let tenant = self.tenant.to_string();
                let bucket = bucket.clone();
                let rows=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("SELECT m.object,m.compliance,o.document->'object' AS identity,o.document->'groups' AS groups FROM mdm_assets.software_members m JOIN mdm_assets.software_objects o ON(o.tenant_id,o.run,o.object)=(m.tenant_id,m.run,m.object) WHERE m.tenant_id=$1::uuid AND m.run=$2 AND m.bucket=$3 AND m.selected AND m.object COLLATE \"C\">$4 COLLATE \"C\" ORDER BY m.object COLLATE \"C\" LIMIT $5")
                        .bind(tenant).bind(id).bind(bucket).bind(after).bind((limit+1) as i64).fetch_all(c).await
                })).await?;
                let more = rows.len() > limit;
                let mut last = None;
                let mut items = Vec::new();
                for r in rows.into_iter().take(limit) {
                    last = Some(r.try_get::<String, _>("object")?);
                    items.push(Device {
                        object: stored(serde_json::from_value(r.try_get("identity")?))?,
                        compliance: stored(serde_json::from_value(serde_json::json!(
                            r.try_get::<String, _>("compliance")?
                        )))?,
                        group_decisions: stored(serde_json::from_value(r.try_get("groups")?))?,
                    });
                }
                Ok(Response::Devices {
                    task: id,
                    coordinates,
                    items,
                    next_cursor: self
                        .software_next(&binding, if more { last.as_deref() } else { None })?,
                })
            }
            Command::Evidence {
                bucket,
                object,
                page,
                ..
            } => {
                let (limit, after, binding) = self.software_page(
                    scope,
                    &(id, bucket, object, "evidence", &coordinates),
                    page,
                )?;
                let tenant = self.tenant.to_string();
                let key = object.clone();
                let selected_bucket = bucket.clone();
                let object_document:Option<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar("SELECT o.document FROM mdm_assets.software_objects o JOIN mdm_assets.software_members m ON(m.tenant_id,m.run,m.object)=(o.tenant_id,o.run,o.object) WHERE o.tenant_id=$1::uuid AND o.run=$2 AND o.object=$3 AND m.bucket=$4 AND m.selected")
                        .bind(tenant).bind(id).bind(key).bind(selected_bucket).fetch_optional(c).await
                })).await?;
                let object_result: ObjectResult = stored(serde_json::from_value(
                    object_document.ok_or(Error::NotFound)?,
                ))?;
                let mut bytes = stored(serde_json::to_vec(&object_result.quality))?.len();
                let tenant = self.tenant.to_string();
                let wanted_bucket = bucket.clone();
                let wanted_object = object.clone();
                let metadata=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("SELECT id,octet_length(document::text) bytes FROM mdm_assets.software_evidence WHERE tenant_id=$1::uuid AND run=$2 AND bucket=$3 AND object=$4 AND selected AND id COLLATE \"C\">$5 COLLATE \"C\" ORDER BY id COLLATE \"C\" LIMIT $6")
                        .bind(tenant).bind(id).bind(wanted_bucket).bind(wanted_object).bind(after).bind((limit+1) as i64).fetch_all(c).await
                })).await?;
                let mut more = metadata.len() > limit;
                let mut ids = Vec::new();
                for row in metadata.into_iter().take(limit) {
                    let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
                    if bytes + size > 16 * 1024 * 1024 {
                        if ids.is_empty() {
                            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
                        }
                        more = true;
                        break;
                    }
                    bytes += size;
                    ids.push(row.try_get::<String, _>("id")?);
                }
                let next_cursor = self.software_next(
                    &binding,
                    if more {
                        ids.last().map(String::as_str)
                    } else {
                        None
                    },
                )?;
                let tenant = self.tenant.to_string();
                let bucket = bucket.clone();
                let object = object.clone();
                let rows:Vec<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar("SELECT document FROM mdm_assets.software_evidence WHERE tenant_id=$1::uuid AND run=$2 AND id=ANY($3) AND bucket=$4 AND object=$5 ORDER BY id COLLATE \"C\"").bind(tenant).bind(id).bind(ids).bind(bucket).bind(object).fetch_all(c).await
                })).await?;
                let items = rows
                    .into_iter()
                    .map(|v| stored(serde_json::from_value(v)))
                    .collect::<Result<_>>()?;
                Ok(Response::Evidence {
                    task: id,
                    coordinates,
                    items,
                    quality: object_result.quality,
                    next_cursor,
                })
            }
            _ => Err(Error::Malformed.into()),
        }
    }
}
