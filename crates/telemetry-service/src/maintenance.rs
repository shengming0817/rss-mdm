//! Explicit bounded lifecycle steps reuse RSS fences and continuation recovery.
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
/// Exact device/resource lifecycle request; an id permanently binds its complete action.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub id: uuid::Uuid,
    pub device: String,
    pub field: String,
    pub resource: String,
    pub start_micros: i64,
    pub end_micros: i64,
    pub action: Action,
}
/// Deleted data can be restored only using the original fence and restore window.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    CloseStream {
        target: StreamTarget,
    },
    Reclaim {
        target: StreamTarget,
    },
    ExpireReceipts {
        target: StreamTarget,
        before_micros: i64,
    },
    Delete {
        restore_until_micros: i64,
    },
    Restore {
        deletion_fence: String,
    },
    /// Explicit exact-series statistics; the server checks the catalog definition and device scope.
    Recompute {
        #[schemars(schema_with = "crate::contract_schema::summary")]
        spec: SummarySpec,
    },
    /// Advance only as far as the exact field version's raw retention allows.
    AdvanceCutoff {
        target: Target,
        before_micros: i64,
    },
    /// Preserve RSS summary, replay and restoration dependencies during bounded pruning.
    Prune {
        target: Target,
        raw_before_micros: i64,
        summaries_before_micros: i64,
    },
}
/// An exact historical series; product admission compares its definition with Inventory.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    #[schemars(schema_with = "crate::contract_schema::stream")]
    pub stream: Stream,
    #[schemars(schema_with = "crate::contract_schema::series")]
    pub series: Series,
}
impl Target {
    fn selection(
        &self,
        tenant: rss_request_context::TenantId,
        input: &Request,
    ) -> Result<Selection, Error> {
        if self.stream.scope().tenant() != tenant
            || self.stream.scope().namespace().as_str() != "mdm.telemetry"
            || self.series.subject().as_str() != input.device
            || self.series.resource().as_str() != input.resource
            || self.series.definition().spec().key.as_str() != input.field
        {
            return Err(Error::Denied);
        }
        Ok(Selection::Exact {
            stream: self.stream.clone(),
            series: self.series.clone(),
        })
    }
}
/// Stored source incarnation. Device membership is checked against durable intake records.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamTarget {
    pub registration: uuid::Uuid,
    pub source: rss_mdm_inventory::Source,
    pub epoch: uuid::Uuid,
}
impl StreamTarget {
    fn stream(&self, tenant: rss_request_context::TenantId) -> Result<Stream, Error> {
        if !matches!(
            self.source,
            rss_mdm_inventory::Source::AgentNative
                | rss_mdm_inventory::Source::AgentScript
                | rss_mdm_inventory::Source::AgentOsquery
        ) || self.registration.is_nil()
            || self.epoch.is_nil()
        {
            return Err(Error::Invalid);
        }
        Ok(Stream::new(
            Scope::new(tenant, Id::new("mdm.telemetry")?),
            Id::new(format!("{}:{}", self.registration, self.source.as_str()))?,
            Id::new(self.epoch.to_string())?,
        ))
    }
}
struct MaintainAuthority<'a>(&'a MaintenanceRequest);
impl Authority for MaintainAuthority<'_> {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_timeseries::Error> {
        match access {
            Access::Maintain(request) if request.binding()? == self.0.binding()? => Ok(()),
            _ => Err(rss_timeseries::Error::Unauthorized),
        }
    }
}
fn operation(
    tenant: rss_request_context::TenantId,
    input: &Request,
) -> Result<MaintenanceRequest, Error> {
    if input.id.is_nil() {
        return Err(Error::Invalid);
    }
    let selection = Selection::Resource {
        scope: Scope::new(tenant, Id::new("mdm.telemetry")?),
        subject: Id::new(&input.device)?,
        resource: Id::new(&input.resource)?,
        keys: [Id::new(&input.field)?].into(),
    };
    let window = Interval::new(
        Timestamp::new(input.start_micros)?,
        Timestamp::new(input.end_micros)?,
    )?;
    let action = match &input.action {
        Action::CloseStream { target } => MaintenanceAction::CloseStream {
            stream: target.stream(tenant)?,
        },
        Action::Reclaim { target } => MaintenanceAction::Reclaim {
            stream: target.stream(tenant)?,
        },
        Action::ExpireReceipts {
            target,
            before_micros,
        } => MaintenanceAction::ExpireReceipts {
            stream: target.stream(tenant)?,
            before: Timestamp::new(*before_micros)?,
        },
        Action::Delete {
            restore_until_micros,
        } => MaintenanceAction::Delete {
            selection,
            window,
            restore_until: Timestamp::new(*restore_until_micros)?,
        },
        Action::Restore { deletion_fence } => MaintenanceAction::Restore {
            selection,
            window,
            deletion_fence: Id::new(deletion_fence)?,
        },
        Action::AdvanceCutoff {
            target,
            before_micros,
        } => MaintenanceAction::AdvanceCutoff {
            selection: target.selection(tenant, input)?,
            before: Timestamp::new(*before_micros)?,
        },
        Action::Prune {
            target,
            raw_before_micros,
            summaries_before_micros,
        } => MaintenanceAction::Prune {
            selection: target.selection(tenant, input)?,
            raw_before: Timestamp::new(*raw_before_micros)?,
            summaries_before: Timestamp::new(*summaries_before_micros)?,
        },
        Action::Recompute { spec } => {
            if spec.stream().scope() != selection.scope()
                || spec.series().subject().as_str() != input.device
                || spec.series().resource().as_str() != input.resource
                || spec.series().definition().spec().key.as_str() != input.field
            {
                return Err(Error::Denied);
            }
            MaintenanceAction::Recompute {
                spec: spec.clone(),
                window,
            }
        }
    };
    Ok(MaintenanceRequest::new(
        Id::new(input.id.to_string())?,
        action,
        MaintenanceBudget {
            rows: NonZeroU32::new(4096).expect("bounded rows"),
            buckets: NonZeroU32::new(64).expect("bounded buckets"),
        },
    )?)
}
async fn authorize(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    proof: &AuthorizedPrincipal,
    input: &Request,
) -> Result<(), Error> {
    proof.check_live().map_err(|_| Error::Denied)?;
    if proof.tenant_id() != tenant.to_string() {
        return Err(Error::Denied);
    }
    rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
        .await
        .map_err(|_| Error::Denied)?;
    let snapshot =
        rss_mdm_authorization_service::snapshot_on(c, proof.tenant_id(), proof.instance_id())
            .await
            .map_err(|_| Error::Denied)?;
    snapshot
        .require(proof, Permission::InventoryRead, Some(&input.device))
        .map_err(|_| Error::Denied)?;
    snapshot
        .require(
            proof,
            if matches!(input.action, Action::Delete { .. } | Action::Restore { .. }) {
                Permission::TelemetryDelete
            } else {
                Permission::TelemetryMaintain
            },
            Some(&input.device),
        )
        .map_err(|_| Error::Denied)?;
    let key = rss_mdm_inventory::FieldKey::parse(&input.field).map_err(|_| Error::Invalid)?;
    let (field, _) = rss_mdm_inventory_postgres::historical_field_in(c, tenant, key)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Invalid)?;
    if field.sensitivity == rss_mdm_inventory::Sensitivity::Secret {
        return Err(Error::Denied);
    }
    field.time_series.as_ref().ok_or(Error::Invalid)?;
    match &input.action {
        Action::CloseStream { target }
        | Action::Reclaim { target }
        | Action::ExpireReceipts { target, .. } => {
            let fields:Vec<String>=sqlx::query_scalar("SELECT DISTINCT unnest(fields) FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2 AND registration=$3 AND source=$4 AND epoch=$5 LIMIT 1025")
                .bind(tenant.to_string()).bind(&input.device).bind(target.registration).bind(target.source.as_str()).bind(target.epoch).fetch_all(&mut *c).await?;
            if fields.is_empty() || !fields.contains(&input.field) || fields.len() > 1024 {
                return Err(Error::Denied);
            }
            for name in fields {
                let key = rss_mdm_inventory::FieldKey::parse(&name).map_err(|_| Error::Storage)?;
                let (field, _) = rss_mdm_inventory_postgres::historical_field_in(c, tenant, key)
                    .await
                    .map_err(|_| Error::Storage)?
                    .ok_or(Error::Storage)?;
                if field.sensitivity == rss_mdm_inventory::Sensitivity::Secret {
                    return Err(Error::Denied);
                }
            }
            if let Action::ExpireReceipts { before_micros, .. } = &input.action {
                let now: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
                )
                .fetch_one(&mut *c)
                .await?;
                if *before_micros > now {
                    return Err(Error::Invalid);
                }
            } else {
                if !rss_mdm_registration_service::device::store::collection_stream_retired_on(
                    c,
                    tenant,
                    &input.device,
                    target.registration,
                    target.source,
                    target.epoch,
                )
                .await
                .map_err(|_| Error::Storage)?
                {
                    return Err(Error::Denied);
                }
                let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND registration=$2 AND source=$3 AND epoch=$4 AND delivery<>'published')")
                    .bind(tenant.to_string()).bind(target.registration).bind(target.source.as_str()).bind(target.epoch).fetch_one(c).await?;
                if pending {
                    return Err(Error::Conflict);
                }
            }
        }
        Action::Recompute { spec } => {
            let version = spec.series().definition().spec().version;
            let versions = rss_mdm_inventory_postgres::time_series_versions_in(
                c,
                tenant,
                key,
                version.saturating_sub(1),
                version,
            )
            .await
            .map_err(|_| Error::Storage)?;
            let original = versions.first().ok_or(Error::Invalid)?;
            if original
                .time_series_definition(spec.stream().scope().clone())
                .map_err(|_| Error::Invalid)?
                != *spec.series().definition()
            {
                return Err(Error::Conflict);
            }
        }
        Action::Delete {
            restore_until_micros,
        } => {
            let restore_seconds =
                rss_mdm_inventory_postgres::minimum_restore_seconds_in(c, tenant, key)
                    .await
                    .map_err(|_| Error::Storage)?
                    .ok_or(Error::Invalid)?;
            let now: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
            )
            .fetch_one(c)
            .await?;
            if *restore_until_micros > now.saturating_add(i64::from(restore_seconds) * 1_000_000) {
                return Err(Error::Invalid);
            }
        }
        Action::AdvanceCutoff {
            target,
            before_micros,
        }
        | Action::Prune {
            target,
            raw_before_micros: before_micros,
            ..
        } => {
            rss_mdm_registration_service::device::store::lock_channel(
                c,
                &tenant.to_string(),
                &input.device,
                rss_mdm_inventory::Channel::Agent,
            )
            .await
            .map_err(|_| Error::Storage)?;
            let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2 AND $3=ANY(fields) AND delivery<>'published')")
                .bind(tenant.to_string()).bind(&input.device).bind(&input.field)
                .fetch_one(&mut *c).await?;
            if pending {
                return Err(Error::Conflict);
            }
            let version = target.series.definition().spec().version;
            let versions = rss_mdm_inventory_postgres::time_series_versions_in(
                c,
                tenant,
                key,
                version.saturating_sub(1),
                version,
            )
            .await
            .map_err(|_| Error::Storage)?;
            let original = versions.first().ok_or(Error::Invalid)?;
            if original
                .time_series_definition(target.stream.scope().clone())
                .map_err(|_| Error::Invalid)?
                != *target.series.definition()
            {
                return Err(Error::Conflict);
            }
            let reference = &original
                .time_series
                .as_ref()
                .ok_or(Error::Invalid)?
                .retention;
            let policy = rss_mdm_inventory_postgres::retention_policy_in(
                c,
                tenant,
                &reference.key,
                reference.revision,
            )
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Invalid)?;
            let now: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
            )
            .fetch_one(c)
            .await?;
            if *before_micros
                > now
                    .saturating_sub(i64::from(policy.raw_seconds) * 1_000_000)
                    .max(0)
            {
                return Err(Error::Denied);
            }
            if let Action::Prune {
                summaries_before_micros,
                ..
            } = input.action
                && summaries_before_micros
                    > now
                        .saturating_sub(i64::from(policy.summary_seconds) * 1_000_000)
                        .max(0)
            {
                return Err(Error::Denied);
            }
        }
        Action::Restore { .. } => {}
    }
    Ok(())
}
impl Service {
    /// Persist the audited intent before any backend effect. Retry the same request to
    /// continue or recover; only the RSS maintainer owns progression and deletion fences.
    pub async fn maintenance(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &Request,
        audit: &RequestAudit,
    ) -> Result<Progress, Error> {
        let request = operation(self.tenant, input)?;
        let binding = {
            use sha2::Digest;
            sha2::Sha256::digest(serde_json::to_vec(input)?).to_vec()
        };
        let service = self.clone();
        let actor = proof.clone();
        let intent = input.clone();
        let audit = audit.clone();
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("telemetry-maintenance:{}", input.id),
            202,
            "success",
            None,
        )
        .and_then(|fact| {
            fact.with_details(
                json!({"phase":"intent_accepted","deviceId":input.device,"field":input.field}),
            )
        })
        .map_err(|_| Error::Storage)?;
        let settlement_audit = audit.clone();
        let rejection = Arc::new(Mutex::new(None));
        let rejected = rejection.clone();
        self.runtime.local_tx(self.tenant,crate::deadline(),move|tx|Box::pin(async move {
            service.planning.audit_store.prepare_in(tx, &audit, &[]).await.map_err(crate::storage_error)?;
            let tenant=service.tenant;
            let replayed = tx.with_connection(move|c|Box::pin(async move {
                let result=async {
                    authorize(c,tenant,&actor,&intent).await?;
                    let inserted=sqlx::query("INSERT INTO mdm_telemetry.maintenance(tenant_id,id,binding) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING")
                        .bind(tenant.to_string()).bind(intent.id).bind(binding.as_slice()).execute(&mut *c).await?.rows_affected();
                    let stored:Vec<u8>=sqlx::query_scalar("SELECT binding FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
                        .bind(tenant.to_string()).bind(intent.id).fetch_one(c).await?;
                    if stored.as_slice()!=binding.as_slice() {return Err(Error::Conflict);}
                    Ok(inserted==0)
                }.await;
                result.map_err(|e|{*rejected.lock().expect("maintenance intent")=Some(e);sqlx::Error::Protocol("maintenance intent rejected".into())})
            })).await?;
            (if replayed { Ok(()) } else { service.planning.audit_store.append_in(tx, &fact).await }).map_err(crate::storage_error)?;
            audit.mark_commit_started();
            Ok(())
        })).await.fold(|v|{settlement_audit.mark_committed();Ok(v)},|_|Err(Error::Storage),|_|{settlement_audit.mark_rolled_back();Err(rejection.lock().expect("maintenance intent").unwrap_or(Error::Storage))},|_|{settlement_audit.mark_rollback_failed();Err(Error::Unknown)},|_|Err(Error::Unknown),|_|Err(Error::Storage))?;
        let service = self.clone();
        let proof = proof.clone();
        let input = input.clone();
        let rejection = Arc::new(Mutex::new(None));
        let rejected = rejection.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            step_on(&service, c, &proof, &input, &request)
                                .await
                                .map_err(|e| {
                                    *rejected.lock().expect("maintenance step") = Some(e);
                                    sqlx::Error::Protocol("maintenance step unconfirmed".into())
                                })
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| {
                    Err(rejection
                        .lock()
                        .expect("maintenance step")
                        .unwrap_or(Error::Storage))
                },
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
async fn step_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    input: &Request,
    request: &MaintenanceRequest,
) -> Result<Progress, Error> {
    authorize(c, service.tenant, proof, input).await?;
    let previous:Option<Json>=sqlx::query_scalar("SELECT result FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(service.tenant.to_string()).bind(input.id).fetch_one(&mut *c).await?;
    if previous.as_ref().is_some_and(|v| v["state"] == "complete") {
        return serde_json::from_value(previous.expect("confirmed result"))
            .map_err(|_| Error::Storage);
    }
    let binding = request.binding()?;
    // The backend resumes its durable current step by original identity, including after token expiry.
    let authorized =
        Authorized::<MaintenanceRequest>::verify(&MaintainAuthority(request), request.clone())?;
    let deadline = Deadline::from_timeout(
        &crate::backend::SystemClock,
        std::time::Duration::from_secs(6),
    )
    .map_err(|_| Error::Invalid)?;
    let result = match service
        .backend
        .maintain(&authorized, None, deadline)
        .await?
    {
        Outcome::Unknown => return Err(Error::Unknown),
        Outcome::Accepted(progress) | Outcome::Replay(progress) => match progress {
            MaintenanceProgress::More { processed, next } => Progress::More {
                processed,
                next: next.verify(binding)?.as_str().to_owned(),
            },
            MaintenanceProgress::Complete { processed, fence } => {
                Progress::Complete { processed, fence }
            }
            MaintenanceProgress::Blocked { reason } => Progress::Blocked { reason },
        },
    };
    proof.check_live().map_err(|_| Error::Denied)?;
    if matches!(&result, Progress::Complete { .. })
        && let Action::Reclaim { target } = &input.action
    {
        sqlx::query("UPDATE mdm_telemetry.retention_targets SET phase=2,result=$3 WHERE tenant_id=$1::uuid AND stream=$2")
                .bind(service.tenant.to_string()).bind(serde_json::to_value(target.stream(service.tenant)?)?).bind(sqlx::types::Json(&result)).execute(&mut *c).await?;
    }
    sqlx::query(
        "UPDATE mdm_telemetry.maintenance SET result=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(service.tenant.to_string())
    .bind(input.id)
    .bind(sqlx::types::Json(&result))
    .execute(c)
    .await?;
    Ok(result)
}

/// Product continuation framing over the existing RSS maintenance result.
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Progress {
    More {
        processed: u32,
        next: String,
    },
    Complete {
        processed: u32,
        #[schemars(schema_with = "crate::contract_schema::opaque_id")]
        fence: Id,
    },
    Blocked {
        #[schemars(schema_with = "crate::contract_schema::maintenance_block")]
        reason: MaintenanceBlock,
    },
}
