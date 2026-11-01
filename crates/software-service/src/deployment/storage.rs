use super::*;
pub use crate::deployment::action_admission::{authorized, now};
pub(crate) use crate::deployment::action_admission::{lock_action_request, lock_device};
use crate::deployment::authority::Authority;
use sqlx::{PgConnection, Row};

/// Bind the shared command component on the caller's existing transaction.
/// The caller owns its product admission, tenant authorization and transaction settlement.
pub async fn bind_command_in(
    runtime: Arc<PgRuntime>,
    tx: &mut PgTransaction<'_>,
    clock: rss_device_command_postgres::CommandClock,
) -> std::result::Result<
    (
        Arc<PgOutboxStore<()>>,
        rss_device_command_postgres::PgStore<()>,
    ),
    PgError,
> {
    runtime.validate_transaction(tx)?;
    let budget = rss_transactional_messaging::policy::DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(6),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .map_err(|_| sqlx::Error::Protocol("command delivery budget".into()))?;
    let outbox = Arc::new(PgOutboxStore::new(runtime, messaging_domain(), budget)?);
    let callers = rss_device_command_postgres::CallerRoles::new(&[
        "mdm_command_runtime",
        "mdm_policy_runtime",
    ])
    .map_err(|_| PgError::from(sqlx::Error::Protocol("command caller declaration".into())))?;
    let store =
        rss_device_command_postgres::PgStore::new(tx, outbox.clone(), clock, &callers).await?;
    Ok((outbox, store))
}

pub struct Operation {
    pub id: Uuid,
    pub device: String,
    pub request: Create,
    pub authority: Authority,
    pub revision: i64,
    pub dispatch_failure: Option<crate::deployment::DispatchFailure>,
    pub scope: dc::Scope,
    pub coordinate: dc::Coordinate,
    pub registration: Uuid,
    pub registration_generation: i64,
}
impl Operation {
    pub fn command_id(&self) -> Result<dc::CommandId> {
        checked_input(dc::CommandId::parse(&self.id.to_string()))
    }
}

pub async fn load(
    tx: &mut PgTransaction<'_>,
    protection: &rss_mdm_native_protection::Protector,
    id: Uuid,
) -> Result<Operation> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(&mut (protection, id), move |args, c| {
        Box::pin(async move { Ok(load_on(c, tenant, args.0, args.1).await) })
    })
    .await?
}

pub async fn load_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    id: Uuid,
) -> Result<Operation> {
    let row={ let c = &mut *c; sqlx::query("SELECT o.device,o.dispatch_failure,o.request,o.input_context,o.authority::text,o.revision,o.generation,o.epoch,o.registration,o.registration_generation,o.gateway_accepted,d.command_device::text FROM mdm_software_deployment.operations o JOIN mdm_access.command_authorities d USING(tenant_id,device) WHERE o.tenant_id=$1::uuid AND o.id=$2::uuid").bind(tenant.to_string()).bind(id.to_string()).fetch_optional(c).await }?.ok_or(Error::Execution(crate::deployment::missing::ExecutionError::MissingOperation))?;
    decode_operation(protection, tenant, id, &row)
}
fn decode_operation(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    id: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<Operation> {
    Ok(Operation {
        id,
        device: row.try_get("device")?,
        request: crate::deployment::input_storage::open_row(
            protection, tenant, id, row, "request",
        )?,
        authority: stored(serde_json::from_str(
            &row.try_get::<String, _>("authority")?,
        ))?,
        revision: row.try_get("revision")?,
        dispatch_failure: row
            .try_get::<Option<serde_json::Value>, _>("dispatch_failure")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
        scope: dc::Scope::new(
            tenant,
            stored(dc::DeviceId::parse(
                &row.try_get::<String, _>("command_device")?,
            ))?,
        ),
        coordinate: stored(dc::Coordinate::new(
            row.try_get("generation")?,
            row.try_get("epoch")?,
        ))?,
        registration: row.try_get("registration")?,
        registration_generation: row.try_get("registration_generation")?,
    })
}

/// One bounded provider read for the current authorized page's protected inputs.
pub(crate) async fn load_many_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    ids: Vec<Uuid>,
) -> Result<std::collections::BTreeMap<Uuid, Operation>> {
    if ids.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    if ids.is_empty() {
        return Ok(Default::default());
    }
    let count = ids.len();
    let rows = {
        let c = &mut *c;
        sqlx::query("WITH selected AS MATERIALIZED (SELECT o.id,o.device,o.dispatch_failure,o.request,o.input_context,o.authority::text,o.revision,o.generation,o.epoch,o.registration,o.registration_generation,o.gateway_accepted,d.command_device::text FROM mdm_software_deployment.operations o JOIN mdm_access.command_authorities d USING(tenant_id,device) WHERE o.tenant_id=$1::uuid AND o.id=ANY($2)), budget AS (SELECT coalesce(sum(octet_length(request)+octet_length(authority)+octet_length(input_context::text)+coalesce(octet_length(dispatch_failure::text),0)+1024),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes AS input_bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216")
  .bind(tenant.to_string()).bind(ids).fetch_all(c).await
    }?;
    rss_mdm_query_postgres::observe_rows("execution.inputs", &rows)?;
    let bytes: i64 = rows
        .first()
        .ok_or(Error::Conflict)?
        .try_get("input_bytes")?;
    if !rss_mdm_query_postgres::within_budget(
        "execution.inputs",
        count as u64,
        bytes as u64,
        1000,
        16 * 1024 * 1024,
    ) {
        return Err(Error::Unavailable(Failure::Capacity).into());
    }
    if rows.len() != count
        || rows
            .first()
            .is_some_and(|r| r.try_get::<Option<Uuid>, _>("id").ok().flatten().is_none())
    {
        return Err(Error::Conflict.into());
    }
    let mut result = std::collections::BTreeMap::new();
    for row in rows {
        let id = row.try_get("id")?;
        result.insert(id, decode_operation(protection, tenant, id, &row)?);
    }
    Ok(result)
}

/// Existing execute evidence may settle after source retirement; it cannot authorize a new attempt.
pub async fn execution_started(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' AND state <> 'pending')")
            .bind(tenant).bind(id).fetch_one(c).await
    })).await?)
}

pub async fn authority_decision(
    source: &Arc<dyn crate::deployment::scope::Sources>,
    lifecycle: &Arc<dyn crate::deployment::retirement::Lifecycle>,
    key: &Arc<rss_mdm_native_protection::Protector>,
    tx: &mut PgTransaction<'_>,
    operation: &Operation,
    now: i64,
) -> Result<crate::deployment::authorization_decision::Authorization> {
    let tenant = tx.tenant_id().to_string();
    let device = operation.device.clone();
    let id = operation.id;
    let lifecycle_port = lifecycle.clone();
    let allowed = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(lifecycle_port
                    .execution_allowed_on(c, &tenant, &device, id)
                    .await)
            })
        })
        .await??;
    let preliminary = crate::deployment::authorization_decision::decide(
        operation,
        allowed,
        Some((operation.registration, operation.registration_generation)),
        true,
    )?;
    if !preliminary.is_authorized() {
        return Ok(preliminary);
    }
    let registration = match current_registration(
        tx,
        &operation.device,
        operation.request.task.purpose()?,
    )
    .await
    {
        Ok(current) => Some(current),
        Err(Fault::Request(Error::Conflict | Error::WindowsDeclaredEnrollmentNotReady)) => None,
        Err(e) => return Err(e),
    };
    let decision =
        crate::deployment::authorization_decision::decide(operation, allowed, registration, true)?;
    if !decision.is_authorized() {
        return Ok(decision);
    }
    let key = key.clone();
    let source = source.clone();
    let lifecycle = lifecycle.clone();
    let authority = operation.authority.clone();
    let permissions = operation.request.task.permissions()?;
    let valid = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(authority
                    .valid(
                        source.as_ref(),
                        lifecycle.as_ref(),
                        c,
                        &key,
                        &permissions,
                        now,
                    )
                    .await)
            })
        })
        .await??;
    crate::deployment::authorization_decision::decide(operation, allowed, registration, valid)
}

pub async fn receipt_valid(
    source: &Arc<dyn crate::deployment::scope::Sources>,
    lifecycle: &Arc<dyn crate::deployment::retirement::Lifecycle>,
    key: &Arc<rss_mdm_native_protection::Protector>,
    tx: &mut PgTransaction<'_>,
    operation: &Operation,
    now: i64,
) -> Result<bool> {
    match current_registration(tx, &operation.device, operation.request.task.purpose()?).await {
        Ok(current) if current == (operation.registration, operation.registration_generation) => {}
        Ok(_) | Err(Fault::Request(Error::Conflict | Error::WindowsDeclaredEnrollmentNotReady)) => {
            return Ok(false);
        }
        Err(e) => return Err(e),
    }
    let key = key.clone();
    let source = source.clone();
    let lifecycle = lifecycle.clone();
    let authority = operation.authority.clone();
    let permissions = operation.request.task.permissions()?;
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(authority
                    .receipt_valid(
                        source.as_ref(),
                        lifecycle.as_ref(),
                        c,
                        &key,
                        &permissions,
                        now,
                    )
                    .await)
            })
        })
        .await??)
}
pub async fn current_registration(
    tx: &mut PgTransaction<'_>,
    device: &str,
    purpose: rss_mdm_registration_service::Purpose,
) -> Result<(Uuid, i64)> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let t = tenant.clone();
    let d = device.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::deployment::device::store::lock_channel(
                c,
                &t,
                &d,
                rss_mdm_inventory::Channel::Mdm,
            )
            .await)
        })
    })
    .await??;
    let rows = tx
        .with_connection(move |c| {
            Box::pin(crate::deployment::device::read::active_channel_in(
                c,
                tenant,
                vec![device],
                rss_mdm_inventory::Channel::Mdm,
                purpose,
            ))
        })
        .await?;
    if rows.len() != 1 {
        return Err(
            if purpose == rss_mdm_registration_service::Purpose::WindowsDeclared {
                Error::WindowsDeclaredEnrollmentNotReady
            } else {
                Error::Conflict
            }
            .into(),
        );
    }
    Ok((rows[0].1, rows[0].2))
}

pub async fn read_on(
    conn: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    actor: &str,
) -> std::result::Result<Option<(Vec<u8>, serde_json::Value)>, sqlx::Error> {
    let row=sqlx::query("SELECT fingerprint,response::text FROM mdm_software_deployment.requests WHERE tenant_id=$1::uuid AND id=$2::uuid AND actor=$3").bind(tenant).bind(id.to_string()).bind(actor).fetch_optional(conn).await?;
    row.map(|r| {
        Ok((
            r.try_get("fingerprint")?,
            serde_json::from_str(&r.try_get::<String, _>("response")?)
                .map_err(|_| sqlx::Error::Protocol("stored request".into()))?,
        ))
    })
    .transpose()
}

pub async fn require_source(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    source: rss_mdm_inventory::ReportSource,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let valid = tx
        .with_connection(move |c| {
            Box::pin(crate::deployment::device::read::enabled_source_in(
                c,
                tenant,
                registration,
                source,
            ))
        })
        .await?;
    if !valid {
        return Err(Error::Conflict.into());
    }
    Ok(())
}

pub async fn authorized_native(
    tx: &mut PgTransaction<'_>,
    proof: &crate::deployment::authorization::context::AuthorizedPrincipal,
    device: &str,
    permissions: &[crate::deployment::authorization::Permission],
) -> Result<crate::deployment::authorization::Snapshot> {
    if permissions.is_empty() {
        return Err(Error::Forbidden.into());
    }
    let snapshot = crate::deployment::action_admission::current(tx, proof).await?;
    for &permission in permissions {
        snapshot.require(proof, permission, permission.device().then_some(device))?;
    }
    Ok(snapshot)
}

/// 固定租户的比较身份；密文写钥可独立轮换，重启不能创建第二个比较空间。
pub async fn bind_native_key(
    runtime: &PgRuntime,
    tenant: TenantId,
    key_id: &str,
) -> std::result::Result<(), Error> {
    let result = runtime
        .local_tx_with_context(tenant, deadline(), key_id, |key_id, tx| {
            Box::pin(async move { rss_mdm_native_protection::binding::bind_in(tx, key_id).await })
        })
        .await;
    result.fold(
        |_| Ok(()),
        |_| Err(Error::Unavailable(Failure::NativeProtection)),
        |_| Err(Error::Unavailable(Failure::NativeProtection)),
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::NativeProtection)),
    )
}

/// Admit the exact Policy intent participant without adopting the Command worker profile.
pub(crate) async fn admit_policy_participant(
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), PgError> {
    let valid = tx
        .with_connection(|c| {
            Box::pin(async move {
                crate::deployment::verify_authority(c).await?;
                let role: String = sqlx::query_scalar("SELECT current_user::text")
                    .fetch_one(&mut *c)
                    .await?;
                if role == "mdm_command_runtime" {
                    return Ok(true);
                }
                if role != "mdm_policy_runtime" {
                    return Ok(false);
                }
                rss_mdm_inventory_postgres::verify_asset_history(c).await?;
                sqlx::query_scalar::<_, bool>(include_str!("policy-participant-admission.sql"))
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol("Policy execution participant admission".into()).into());
    }
    Ok(())
}

/// Membership is an identity fact, independent of current eligibility.
pub async fn owns_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> std::result::Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.operations WHERE tenant_id=$1::uuid AND id=$2)",
    )
    .bind(tenant.to_string())
    .bind(id)
    .fetch_one(c)
    .await
}

/// Bounded immutable ownership probe; authorization does not affect persistent membership.
pub async fn owned_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> std::result::Result<std::collections::BTreeSet<Uuid>, sqlx::Error> {
    if ids.len() > 1000 {
        return Err(sqlx::Error::Protocol("ownership batch limit".into()));
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM mdm_software_deployment.operations WHERE tenant_id=$1::uuid AND id=ANY($2)",
    )
    .bind(tenant.to_string())
    .bind(ids)
    .fetch_all(c)
    .await?;
    Ok(ids.into_iter().collect())
}
