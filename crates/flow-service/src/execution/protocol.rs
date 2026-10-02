use super::*;
use crate::device::DevicePrincipal;
use serde_json::{Value, json};
use sqlx::Row;
impl ExecutionService {
    pub async fn management(
        &self,
        windows: Arc<dyn super::channels::Windows>,
        principal: &DevicePrincipal,
        message: &rss_mdm_windows_mdm::syncml::Message,
        bytes: &[u8],
        audit: &RequestAudit,
    ) -> std::result::Result<Vec<u8>, Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, &windows, principal, message, bytes, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, w, p, m, b, a) = *ctx;
                    let tenant = s.tenant.to_string();
                    let instance = s.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    let tenant = s.tenant.to_string();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                                .bind(tenant)
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;
                    storage::lock(tx, p.device()).await?;
                    actions::native_collection::settle_device(s, tx, p.device()).await?;
                    let w = w.clone();
                    let protection = s.protection.clone();
                    let principal = p.clone();
                    let message = m.clone();
                    let bytes = b.to_vec();
                    let audit = a.clone();
                    let reply = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(
                                    w.exchange(
                                        c,
                                        &protection,
                                        &principal,
                                        &message,
                                        &bytes,
                                        &audit,
                                    )
                                    .await,
                                )
                            })
                        })
                        .await?
                        .map_err(Error::from)?;
                    settle_dispatch_failures(s, tx, p, a).await?;
                    settle_reports(s, tx, p, m.header.session_id).await?;
                    actions::native_collection::settle_device(s, tx, p.device()).await?;
                    s.reconcile_agent_install_in(tx, p.device(), a).await?;
                    if !matches!(
                        a.snapshot().management_result,
                        Some(rss_mdm_audit_integration::ManagementResult::Replayed)
                    ) {
                        s.audit_store
                            .append_request_in(tx, a, 200, "success")
                            .await?;
                    }
                    let super::channels::Reply { bytes, facts } = reply;
                    for fact in &facts {
                        s.audit_store
                            .append_in(tx, fact, false)
                            .await
                            .map_err(Error::from)?;
                    }
                    Ok(bytes)
                })
            },
            crate::transaction::TransactionOwner::Execution,
        )
        .await
    }
}
pub(super) async fn settle_reports(
    s: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    session: u32,
) -> Result<()> {
    let tenant = s.tenant.to_string();
    let registration = p.registration();
    let generation = p.generation();
    let ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT DISTINCT o.id FROM mdm_commands.operations o JOIN mdm_commands.attempts a ON(a.tenant_id,a.operation)=(o.tenant_id,o.id) JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND a.session=$4 AND i.receipt_accepted AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64").bind(tenant).bind(registration).bind(generation).bind(i64::from(session)).fetch_all(c).await})).await?;
    for id in ids {
        settle_one(s, tx, id).await?;
    }
    Ok(())
}
async fn settle_one(s: &ExecutionService, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    let op = storage::load(tx, &s.protection, id).await?;
    let command = s.required_command(tx, &op).await?;
    if command.status().is_terminal() {
        return Ok(());
    }
    let now = storage::now(tx).await?;
    if now >= op.request.deadline || !storage::approval_valid(&s.protection, tx, &op, now).await? {
        return Ok(());
    }
    let tenant = s.tenant.to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT a.phase,i.kind,i.status,i.value,i.receipt_accepted,i.result_accepted FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND (a.phase='execute' OR(a.phase='prepare' AND (i.status>=400 OR i.status IN (215,216)))) AND a.ordinal=(SELECT max(last.ordinal) FROM mdm_commands.attempts last WHERE last.tenant_id=a.tenant_id AND last.operation=a.operation AND last.phase=a.phase) ORDER BY i.command,i.item_ordinal").bind(tenant).bind(id).fetch_all(c).await})).await?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut rejected = false;
    let mut complete = true;
    let mut query = true;
    let mut has_query = false;
    let mut values = true;
    let mut prepare = false;
    for row in rows {
        let accepted = row.try_get::<Option<bool>, _>("receipt_accepted")? == Some(true);
        let status: Option<i32> = row.try_get("status")?;
        rejected |= accepted && status.is_some_and(super::native::rejected_status);
        let kind: String = row.try_get("kind")?;
        complete &= accepted && status.is_some_and(|s| super::native::successful_status(&kind, s));
        query &= matches!(kind.as_str(), "get" | "atomic" | "sequence");
        if kind == "get" {
            has_query = true;
            values &= (accepted && status == Some(204))
                || (row.try_get::<Option<Vec<u8>>, _>("value")?.is_some()
                    && row.try_get::<Option<bool>, _>("result_accepted")? == Some(true));
        }
        prepare |= row.try_get::<String, _>("phase")? == "prepare";
    }
    let event = if rejected {
        dc::DeviceEvent::Rejected
    } else if complete && !prepare {
        dc::DeviceEvent::Received
    } else {
        return Ok(());
    };
    let mut report = dc::DeviceReport {
        scope: op.scope,
        command_id: op.command_id()?,
        coordinate: op.coordinate,
        event,
    };
    let result = s.store.report(tx, &report).await?;
    if result.outcome == dc::Outcome::OutOfOrder {
        return Ok(());
    }
    if !rejected
        && ((complete && query && has_query && values)
            || (values && effect_assessment(&s.protection, tx, &op).await?.state == rss_mdm_windows_mdm::native::verification::EffectState::Verified))
        && !result.command.status().is_terminal()
    {
        report.event =
            dc::DeviceEvent::Reported(op.request.digest(&s.protection, s.tenant, &op.device)?);
        if s.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    crate::planning::policies::reconcile::wake_native_in(tx, &op.device).await?;
    Ok(())
}
pub async fn observation(
    tx: &mut PgTransaction<'_>,
    service: &ExecutionService,
    op: &storage::Operation,
    command_status: dc::Status,
) -> Result<Value> {
    if matches!(op.request.task, Task::Macos { .. }) {
        return super::apple::observation(tx, service.apple_store.clone(), op, command_status)
            .await;
    }
    let tenant = tx.tenant_id();
    let id = op.id;
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT a.id AS attempt,a.phase,a.ordinal,a.session,a.message,i.command,i.parent_command,i.item_ordinal,i.kind,i.uri,i.status,i.value,i.receipt_accepted,i.received_at,i.result_accepted,i.result_received_at FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 ORDER BY a.ordinal,i.command,i.item_ordinal").bind(tenant.to_string()).bind(id).fetch_all(c).await})).await?;
    let sensitive = op.request.task.permissions()?.iter().any(|p| {
        matches!(
            p,
            crate::authorization::Permission::SecurityOperate
                | crate::authorization::Permission::Credentials
                | crate::authorization::Permission::AccountWrite
        )
    });
    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        let value = if sensitive {
            None
        } else {
            result_value(&service.protection, tenant, op, &row)?
        };
        let mut receipt = json!({
            "phase":row.try_get::<String,_>("phase")?,
            "ordinal":row.try_get::<i64,_>("ordinal")?,
            "session":row.try_get::<i64,_>("session")?,
            "message":row.try_get::<i64,_>("message")?,
            "command":row.try_get::<i64,_>("command")?,
            "parentCommand":row.try_get::<Option<i64>,_>("parent_command")?,
            "item":row.try_get::<i32,_>("item_ordinal")?,
            "kind":row.try_get::<String,_>("kind")?,
            "uri":row.try_get::<Option<String>,_>("uri")?,
            "status":row.try_get::<Option<i32>,_>("status")?,
            "value":value,
            "accepted":row.try_get::<Option<bool>,_>("receipt_accepted")?,
            "receivedAt":row.try_get::<Option<i64>,_>("received_at")?,
            "resultAccepted":row.try_get::<Option<bool>,_>("result_accepted")?,
            "resultReceivedAt":row.try_get::<Option<i64>,_>("result_received_at")?
        });
        if sensitive {
            receipt["redacted"] = json!(true);
        }
        receipts.push(receipt);
    }
    let assessment = effect_assessment(&service.protection, tx, op).await?;
    Ok(json!({"protocol":"syncml","observationScope":"native_objects","receipts":receipts,"progress":super::service::status(command_status),"effect":assessment.state,"effectReason":assessment.reason}))
}
fn result_value(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    op: &storage::Operation,
    row: &sqlx::postgres::PgRow,
) -> Result<Option<String>> {
    let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("value")? else {
        return Ok(None);
    };
    let aad = super::native::result_aad(
        tenant,
        op.registration,
        op.registration_generation,
        row.try_get("attempt")?,
        row.try_get("command")?,
        row.try_get("item_ordinal")?,
    )?;
    let plain = protection
        .open_bytes(&sealed, &aad)
        .map_err(|_| Error::Unavailable(Failure::NativeProtection))?;
    Ok(Some(
        String::from_utf8(plain.expose().to_vec()).map_err(|_| Error::Malformed)?,
    ))
}

async fn effect_assessment(
    protection: &rss_mdm_native_protection::Protector,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<rss_mdm_windows_mdm::native::verification::EffectAssessment> {
    use rss_mdm_windows_mdm::native::{Context, Execution, verification::{EffectAssessment, EffectFact, EffectState}};
    let Task::Windows { request: Execution::SyncMl { request } } = &op.request.task else {
        return Ok(EffectAssessment { state: EffectState::Unverifiable, reason: Some("software_requires_installation_evidence") });
    };
    let tenant = tx.tenant_id().to_string();
    let id = op.id;
    let state=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<Value>>("SELECT platform FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' ORDER BY ordinal DESC LIMIT 1").bind(tenant).bind(id).fetch_optional(c).await})).await?.flatten();
    let Some(state) = state else { return Ok(EffectAssessment::waiting("missing_target_evidence")); };
    let context: Context = stored(serde_json::from_value(state))?;
    let plan = request.effect_plan(context).map_err(|_| Error::Unsupported)?;
    if plan.readback().is_none() { return Ok(plan.assess(&[])); }
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT a.id AS attempt,i.command,i.item_ordinal,i.kind,i.uri,i.status,i.value,i.receipt_accepted,i.result_accepted FROM mdm_commands.attempt_items i JOIN mdm_commands.attempts a ON(a.tenant_id,a.id)=(i.tenant_id,i.attempt) WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND a.phase='observe' AND a.ordinal=(SELECT max(ordinal) FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='observe') ORDER BY i.command,i.item_ordinal").bind(tenant).bind(id).fetch_all(c).await})).await?;
    let mut facts = Vec::new();
    for row in rows {
        facts.push(EffectFact {
            uri: row.try_get::<Option<String>, _>("uri")?.unwrap_or_default(),
            status: row.try_get("status")?,
            value: result_value(protection, tx.tenant_id(), op, &row)?,
            receipt_accepted: row.try_get::<Option<bool>, _>("receipt_accepted")? == Some(true),
            result_accepted: row.try_get::<Option<bool>, _>("result_accepted")? == Some(true),
        });
    }
    Ok(plan.assess(&facts))
}

/// A server-side native validation failure cancels dispatch; it is never a device rejection.
pub(super) async fn settle_dispatch_failures(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    audit: &RequestAudit,
) -> Result<()> {
    use rss_mdm_audit_integration::Fact;
    let tenant = tx.tenant_id().to_string();
    let registration = principal.registration();
    let generation = principal.generation();
    let ids = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, Uuid>("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.dispatch_failure IS NOT NULL AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, &service.protection, id).await?;
        let transition = service
            .store
            .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
        let evidence = stored(serde_json::to_vec(&op.dispatch_failure))?;
        let fact = Fact::business(
            audit,
            &format!("native-dispatch-failure:{id}"),
            &evidence,
            200,
            "failed",
            None,
        )?
        .with_details(json!({"operation":id,"failure":op.dispatch_failure}))?;
        service.audit_store.append_in(tx, &fact, false).await?;
        crate::planning::policies::reconcile::wake_native_in(tx, &op.device).await?;
    }
    Ok(())
}
