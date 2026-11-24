//! Explicit bounded lifecycle steps reuse RSS fences and continuation recovery.
use crate::{Error, Service};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_request_context::Deadline;
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use std::{num::NonZeroU32, sync::Arc};
/// Per-invocation work limits; the admitted row/bucket values are frozen with each intent.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub rows: NonZeroU32,
    /// Maximum key and version bytes per immutable publication checked by stream authorization.
    pub authorization_bytes: NonZeroU32,
    pub buckets: NonZeroU32,
    pub step_seconds: u64,
}
impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.step_seconds == 0 || self.step_seconds > i64::MAX as u64 / 1000 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    input: Request,
    rows: NonZeroU32,
    buckets: NonZeroU32,
}
/// Exact device/resource lifecycle request; an id permanently binds its complete action.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub id: uuid::Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
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
            || self.series.subject().as_str() != input.device.to_string()
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
impl Request {
    fn stream_target(&self) -> Option<&StreamTarget> {
        match &self.action {
            Action::CloseStream { target }
            | Action::Reclaim { target }
            | Action::ExpireReceipts { target, .. } => Some(target),
            _ => None,
        }
    }
}
/// Stored source incarnation. Device membership is checked against durable intake records.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamTarget {
    pub source: rss_mdm_inventory::Source,
    pub epoch: uuid::Uuid,
}
impl StreamTarget {
    fn stream(
        &self,
        tenant: rss_request_context::TenantId,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<Stream, Error> {
        if !matches!(
            self.source,
            rss_mdm_inventory::Source::AgentNative
                | rss_mdm_inventory::Source::AgentScript
                | rss_mdm_inventory::Source::AgentOsquery
        ) || self.epoch.is_nil()
        {
            return Err(Error::Invalid);
        }
        Ok(Stream::new(
            Scope::new(tenant, Id::new("mdm.telemetry")?),
            Id::new(format!("{}:{}", device, self.source.as_str()))?,
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
    rows: NonZeroU32,
    buckets: NonZeroU32,
) -> Result<MaintenanceRequest, Error> {
    if input.id.is_nil() {
        return Err(Error::Invalid);
    }
    let selection = Selection::Resource {
        scope: Scope::new(tenant, Id::new("mdm.telemetry")?),
        subject: Id::new(input.device.to_string())?,
        resource: Id::new(&input.resource)?,
        keys: [Id::new(&input.field)?].into(),
    };
    let window = Interval::new(
        Timestamp::new(input.start_micros)?,
        Timestamp::new(input.end_micros)?,
    )?;
    let action = match &input.action {
        Action::CloseStream { target } => MaintenanceAction::CloseStream {
            stream: target.stream(tenant, &input.device)?,
        },
        Action::Reclaim { target } => MaintenanceAction::Reclaim {
            stream: target.stream(tenant, &input.device)?,
        },
        Action::ExpireReceipts {
            target,
            before_micros,
        } => MaintenanceAction::ExpireReceipts {
            stream: target.stream(tenant, &input.device)?,
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
                || spec.series().subject().as_str() != input.device.to_string()
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
        MaintenanceBudget { rows, buckets },
    )?)
}
mod stream_authority;
pub(crate) fn tx_error(error: rss_transactional_messaging_postgres::PgError) -> Error {
    if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed {
        Error::Deadline
    } else {
        Error::Storage
    }
}
async fn authorize(call: &Call<'_>, c: &mut sqlx::PgConnection) -> Result<Qualification, Error> {
    let proof = &call.auth.proof;
    let input = call.input;
    let tenant = proof.binding().tenant();
    proof.check_live().map_err(|_| Error::Denied)?;
    rss_mdm_authorization_service::lock_shared_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        proof.tenant_id(),
        proof.instance_id(),
    )
    .await
    .map_err(crate::authorization_error)?;
    let snapshot = rss_mdm_authorization_service::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        proof.tenant_id(),
        proof.instance_id(),
    )
    .await
    .map_err(crate::authorization_error)?;
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
    // All maintenance actions sharing an original ID serialize before looking at
    // either the disposable prefix or the business receipt.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3252))")
        .bind(format!("{tenant}:{}", input.id))
        .execute(&mut *c)
        .await?;
    let accepted: Option<(Vec<u8>, Option<Json>)> = sqlx::query_as(
        "SELECT binding,result FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant.to_string())
    .bind(input.id)
    .fetch_optional(&mut *c)
    .await?;
    if let Some((bound, result)) = accepted {
        if bound != call.binding {
            return Err(Error::Conflict);
        }
        proof.check_live().map_err(|_| Error::Denied)?;
        if let Some(result) = result
            && result["state"] == "complete"
        {
            return Ok(Qualification::Replay(
                serde_json::from_value(result).map_err(|_| Error::Storage)?,
            ));
        }
        if call.phase == Phase::Execute
            && call.audit.snapshot().write_outcome
                != rss_mdm_audit_integration::WriteOutcome::Committed
        {
            // A fresh request can observe a previously acknowledged intent and
            // dispatch under the current grant in this very transaction.
            call.audit.mark_commit_started();
            call.audit.mark_intent_committed();
        }
    }
    sqlx::query("DELETE FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 AND expires_at<=clock_timestamp()")
        .bind(tenant.to_string()).bind(input.id).execute(&mut *c).await?;
    let conflicting:bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 AND binding<>$3)")
        .bind(tenant.to_string()).bind(input.id).bind(call.binding).fetch_one(&mut *c).await?;
    if conflicting {
        return Err(Error::Conflict);
    }
    if input.stream_target().is_some() {
        stream_authority::lock(c, tenant, input).await?;
    }
    match qualify_action(call, c).await {
        Err(error @ (Error::Denied | Error::Invalid | Error::Capacity | Error::Conflict))
            if input.stream_target().is_some() =>
        {
            stream_authority::clear(c, tenant, input.id, call.binding).await?;
            Ok(Qualification::Rejected(error))
        }
        result => result,
    }
}
async fn qualify_action(
    call: &Call<'_>,
    c: &mut sqlx::PgConnection,
) -> Result<Qualification, Error> {
    let input = call.input;
    let tenant = call.auth.proof.binding().tenant();
    let key = rss_mdm_inventory::FieldKey::parse(&input.field).map_err(|_| Error::Invalid)?;
    let (field, _) = rss_mdm_inventory_postgres::historical_field_in(c, tenant, key)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(
            if matches!(
                input.action,
                Action::CloseStream { .. } | Action::Reclaim { .. } | Action::ExpireReceipts { .. }
            ) {
                Error::Denied
            } else {
                Error::Invalid
            },
        )?;
    if field.sensitivity == rss_mdm_inventory::Sensitivity::Secret {
        return Err(Error::Denied);
    }
    field.time_series.as_ref().ok_or(Error::Invalid)?;
    match &input.action {
        Action::CloseStream { target }
        | Action::Reclaim { target }
        | Action::ExpireReceipts { target, .. } => {
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
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    tenant,
                    &input.device,
                    target.source,
                    target.epoch,
                )
                .await
                .map_err(|_| Error::Storage)?
                {
                    return Err(Error::Denied);
                }
                let pending:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_telemetry.batches WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND source = $3 AND epoch = $4 AND delivery <> 'published')")
                    .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(target.source.as_str()).bind(target.epoch).fetch_one(&mut *c).await?;
                if pending {
                    return Err(Error::Conflict);
                }
            }
            if !stream_authority::advance(call.service, c, tenant, input, target, call.binding)
                .await?
            {
                return Ok(Qualification::Advanced);
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
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant.to_string(),
                &input.device,
                rss_mdm_inventory::Channel::Agent,
            )
            .await
            .map_err(|_| Error::Storage)?;
            let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2 AND $3=ANY(fields) AND delivery<>'published')")
                .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(&input.field)
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
    Ok(Qualification::Ready)
}
enum Qualification {
    Advanced,
    Ready,
    Replay(Progress),
    Rejected(Error),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Scan,
    Admit,
    Execute,
}

enum Pass {
    Advanced,
    Qualified,
    Accepted { new: bool },
    Finished(Progress),
    Rejected(Error),
}

struct Call<'a> {
    service: &'a Service,
    auth: &'a rss_mdm_authorization_service::context::RequestAuth,
    input: &'a Request,
    audit: &'a RequestAudit,
    binding: &'a [u8],
    cutoff: Deadline,
    phase: Phase,
}
impl Call<'_> {
    async fn run_on(&self, c: &mut sqlx::PgConnection) -> Result<Pass, Error> {
        let tenant = self.auth.proof.binding().tenant();
        let qualified = tokio::select! {
            biased;
            () = self.auth.cancellation.cancelled() => return Err(Error::Deadline),
            () = tokio::time::sleep_until(self.cutoff.instant().into()) => return Err(Error::Deadline),
            result = authorize(self, c) => result?,
        };
        match qualified {
            Qualification::Advanced => {
                self.auth.proof.check_live().map_err(|_| Error::Denied)?;
                return Ok(Pass::Advanced);
            }
            Qualification::Rejected(error) => return Ok(Pass::Rejected(error)),
            Qualification::Replay(result) => return Ok(Pass::Finished(result)),
            Qualification::Ready => {}
        }
        match self.phase {
            Phase::Scan => Ok(Pass::Qualified),
            Phase::Admit => {
                crate::selection::lock_read(c, tenant).await?;
                let accepted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2)")
                    .bind(tenant.to_string()).bind(self.input.id).fetch_one(&mut *c).await?;
                if !accepted && crate::selection::pending(c, tenant).await?.is_some() {
                    return Err(Error::Conflict);
                }
                self.auth.proof.check_live().map_err(|_| Error::Denied)?;
                if !accepted {
                    let request = Stored {
                        input: self.input.clone(),
                        rows: self.service.maintenance_policy.rows,
                        buckets: self.service.maintenance_policy.buckets,
                    };
                    sqlx::query("INSERT INTO mdm_telemetry.maintenance(tenant_id,id,binding,request) VALUES($1::uuid,$2,$3,$4)")
                        .bind(tenant.to_string()).bind(self.input.id).bind(self.binding).bind(serde_json::to_value(request)?).execute(c).await?;
                }
                Ok(Pass::Accepted { new: !accepted })
            }
            Phase::Execute => {
                let result = step_on(
                    self.service,
                    c,
                    self.auth,
                    self.input,
                    self.cutoff,
                    self.audit,
                )
                .await?;
                if matches!(result, Progress::Complete { .. })
                    && self.input.stream_target().is_some()
                {
                    stream_authority::clear(c, tenant, self.input.id, self.binding).await?;
                }
                Ok(Pass::Finished(result))
            }
        }
    }
}
impl Service {
    /// Only an acknowledged business intent permits the following transaction to dispatch.
    pub async fn maintenance(
        self: &Arc<Self>,
        auth: &rss_mdm_authorization_service::context::RequestAuth,
        input: &Request,
        audit: &RequestAudit,
    ) -> Result<Progress, Error> {
        use sha2::Digest;
        let execution = auth.proof.binding();
        let cutoff = Deadline::at(auth.deadline).capped(
            &crate::backend::SystemClock,
            std::time::Duration::from_secs(self.maintenance_policy.step_seconds),
        );
        operation(
            execution.tenant(),
            input,
            self.maintenance_policy.rows,
            self.maintenance_policy.buckets,
        )?;
        let binding = sha2::Sha256::digest(serde_json::to_vec(input)?);
        let fact = rss_mdm_audit_integration::Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::Telemetry,
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
        // On the first transaction consult the durable receipt. Even a budget
        // that fits only one final pass can admit now and dispatch on the retry.
        let mut resume = true;
        let mut phase = Phase::Admit;
        loop {
            let mut call = Call {
                service: self,
                auth,
                input,
                audit,
                binding: &binding,
                cutoff,
                phase,
            };
            let mut rejection = None;
            let attempt = self
                .runtime
                .local_tx_with_context(
                    execution,
                    rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                        cutoff,
                        &crate::backend::SystemClock,
                    ),
                    (&mut call, &fact, &mut rejection),
                    move |(call, fact, rejection), tx| {
                        Box::pin(async move {
                            if resume {
                                let existing = tx.with_connection_context(&mut (execution.tenant(),call.input.id),|(tenant,id),c|Box::pin(async move{
                                    sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2)")
                                        .bind(tenant.to_string()).bind(*id).fetch_one(c).await
                                })).await?;
                                if existing {call.phase=Phase::Execute;}
                            }
                            if call.phase == Phase::Admit {
                                call.service
                                    .audit_store
                                    .prepare_in(tx, call.audit, &[])
                                    .await
                                    .map_err(crate::storage_error)?;
                            }
                            let pass = tx
                                .with_connection_context(
                                    &mut (&**call, rejection),
                                    |(call, rejection), c| {
                                        Box::pin(async move {
                                            call.run_on(c).await.map_err(|error| {
                                                rejection.replace(error);
                                                sqlx::Error::Protocol(
                                                    "maintenance step unconfirmed".into(),
                                                )
                                            })
                                        })
                                    },
                                )
                                .await?;
                            if let Pass::Accepted { new } = pass {
                                if new {
                                    call.service
                                        .audit_store
                                        .append_in(tx, fact)
                                        .await
                                        .map_err(crate::storage_error)?;
                                }
                                call.audit.mark_commit_started();
                            }
                            Ok(pass)
                        })
                    },
                )
                .await;
            phase = call.phase;
            resume = false;
            let uncertain = || {
                let state = audit.snapshot();
                (phase == Phase::Execute
                    && state.write_outcome == rss_mdm_audit_integration::WriteOutcome::Committed
                    && !state.intent_only)
                    || (phase == Phase::Admit
                        && state.write_outcome == rss_mdm_audit_integration::WriteOutcome::Unknown)
            };
            let unsettled = |error| {
                Err(if uncertain() {
                    Error::Unknown
                } else {
                    tx_error(error)
                })
            };
            let pass = attempt.fold(
                Ok,
                |e| Err(tx_error(e)),
                |e| {
                    Err(if phase == Phase::Execute && uncertain() {
                        Error::Unknown
                    } else {
                        if phase == Phase::Admit {
                            audit.mark_rolled_back();
                        }
                        rejection.unwrap_or_else(|| tx_error(e))
                    })
                },
                |error| {
                    if phase == Phase::Admit && uncertain() {
                        audit.mark_rollback_failed();
                        Err(Error::Unknown)
                    } else {
                        unsettled(error)
                    }
                },
                unsettled,
                |_| Err(Error::Conflict),
            )?;
            match pass {
                Pass::Advanced => {
                    if phase == Phase::Admit {
                        phase = Phase::Scan;
                    }
                }
                Pass::Qualified => phase = Phase::Admit,
                Pass::Accepted { .. } => {
                    audit.mark_intent_committed();
                    phase = Phase::Execute;
                }
                Pass::Finished(result) => return Ok(result),
                Pass::Rejected(error) => return Err(error),
            }
        }
    }
}

async fn step_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    auth: &rss_mdm_authorization_service::context::RequestAuth,
    input: &Request,
    deadline: Deadline,
    effect: &RequestAudit,
) -> Result<Progress, Error> {
    let proof = &auth.proof;
    let (stored, previous): (Json, Option<Json>) = sqlx::query_as("SELECT request,result FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(proof.binding().tenant().to_string()).bind(input.id).fetch_one(&mut *c).await?;
    let stored: Stored = serde_json::from_value(stored)?;
    if serde_json::to_value(&stored.input)? != serde_json::to_value(input)? {
        return Err(Error::Conflict);
    }
    let request = operation(
        proof.binding().tenant(),
        &stored.input,
        stored.rows,
        stored.buckets,
    )?;
    if previous.as_ref().is_some_and(|v| v["state"] == "complete") {
        return serde_json::from_value(previous.expect("confirmed result"))
            .map_err(|_| Error::Storage);
    }
    let backend = service
        .backend_until(c, proof.binding().tenant(), deadline, true)
        .await?;
    let binding = request.binding()?;
    // The backend resumes its durable current step by original identity, including after token expiry.
    let authorized =
        Authorized::<MaintenanceRequest>::verify(&MaintainAuthority(&request), request.clone())?;
    if auth.cancellation.is_cancelled()
        || deadline.is_expired(rss_request_context::Clock::now(
            &crate::backend::SystemClock,
        ))
    {
        return Err(Error::Deadline);
    }
    proof.check_live().map_err(|_| Error::Denied)?;
    effect.record_intent_dispatch(true);
    let outcome = backend
        .maintain(&authorized, None, deadline)
        .await
        .map_err(|error| {
            // A returned provider error is a definite rejection; unknown settlement has its own Outcome.
            effect.record_intent_dispatch(false);
            Error::from(error)
        })?;
    let result = match outcome {
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
                .bind(proof.binding().tenant().to_string()).bind(serde_json::to_value(target.stream(proof.binding().tenant(), &input.device)?)?).bind(sqlx::types::Json(&result)).execute(&mut *c).await?;
    }
    sqlx::query(
        "UPDATE mdm_telemetry.maintenance SET result=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(proof.binding().tenant().to_string())
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

/// Observe accepted maintenance without constructing a live telemetry backend or advancing it.
pub async fn operation_receipt_on(
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &rss_mdm_authorization_service::Snapshot,
    id: uuid::Uuid,
) -> Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error> {
    use sha2::Digest;
    use sqlx::Row;
    if p.profile() != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Denied);
    }
    let row=sqlx::query("SELECT request,binding,result FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2")
        .bind(p.tenant_id()).bind(id).fetch_optional(c).await?;
    let Some(row) = row else { return Ok(None) };
    let stored: Stored = serde_json::from_value(row.try_get("request")?)?;
    let input = stored.input;
    if input.id != id
        || sha2::Sha256::digest(serde_json::to_vec(&input)?).as_slice()
            != row.try_get::<Vec<u8>, _>("binding")?
    {
        return Err(Error::Storage);
    }
    grant
        .require(p, Permission::InventoryRead, Some(&input.device))
        .map_err(|_| Error::Denied)?;
    grant
        .require(p, Permission::OperationRead, Some(&input.device))
        .map_err(|_| Error::Denied)?;
    let value: Option<Json> = row.try_get("result")?;
    let progress = value.map(serde_json::from_value::<Progress>).transpose()?;
    let mut summary = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
    summary.object = Some(input.resource);
    summary.accepted = Some(true);
    summary.state = Some(
        match progress {
            None => "accepted",
            Some(Progress::More { .. }) => "more",
            Some(Progress::Complete { .. }) => "complete",
            Some(Progress::Blocked { .. }) => "blocked",
        }
        .into(),
    );
    p.check_live().map_err(|_| Error::Denied)?;
    Ok(Some(summary))
}
