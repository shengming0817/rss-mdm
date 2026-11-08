use super::*;
use sqlx::Row;
pub struct Operation {
    pub id: Uuid,
    pub device: String,
    pub request: Create,
    pub authority: authority::Authority,
    pub revision: i64,
    pub dispatch_failure: Option<model::DispatchFailure>,
    pub scope: dc::Scope,
    pub coordinate: dc::Coordinate,
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
    let row={ let c = &mut *c; sqlx::query("SELECT o.device, o.dispatch_failure, o.request, o.input_context, CAST(o.authority AS text), o.revision, o.generation, o.epoch, o.gateway_accepted, CAST(d.command_device AS text) FROM mdm_planning.configuration_operations AS o INNER JOIN mdm_access.command_authorities AS d USING (tenant_id, device) WHERE o.tenant_id = CAST($1 AS uuid) AND o.id = CAST($2 AS uuid)").bind(tenant.to_string()).bind(id.to_string()).fetch_optional(c).await }?.ok_or(Error::NotFound)?;
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
        request: super::input_storage::open_row(protection, tenant, id, row, "request")?,
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
    })
}

pub async fn current_registration(
    tx: &mut PgTransaction<'_>,
    device: &str,
    purpose: rss_mdm_registration_service::Purpose,
) -> Result<String> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let t = tenant.clone();
    let d = device.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(rss_mdm_registration_service::device::store::lock_channel(
                rss_mdm_install_support::StorageProfile::Mdm,
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
            Box::pin(
                rss_mdm_registration_service::device::read::active_channel_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    tenant,
                    vec![device],
                    rss_mdm_inventory::Channel::Mdm,
                    purpose,
                ),
            )
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
    Ok(rows.into_iter().next().ok_or(Error::Conflict)?)
}

pub async fn require_source(
    tx: &mut PgTransaction<'_>,
    registration: String,
    source: rss_mdm_inventory::ReportSource,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let valid = tx
        .with_connection(move |c| {
            Box::pin(
                rss_mdm_registration_service::device::read::enabled_source_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    tenant,
                    registration,
                    source,
                ),
            )
        })
        .await?;
    if !valid {
        return Err(Error::Conflict.into());
    }
    Ok(())
}

pub async fn owns_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> std::result::Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant.to_string()).bind(id).fetch_one(c).await
}

pub use crate::action_admission::now;
pub async fn lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(rss_mdm_registration_service::device::store::lock_channel(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant,
                &device,
                rss_mdm_inventory::Channel::Mdm,
            )
            .await)
        })
    })
    .await??;
    Ok(())
}

/// Current-generation eligibility is distinct from historical receipt admission.
pub async fn authority_decision(
    source: &Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    key: &Arc<rss_mdm_native_protection::Protector>,
    tx: &mut PgTransaction<'_>,
    operation: &Operation,
    now: i64,
) -> Result<Authorization> {
    let current = match current_registration(
        tx,
        &operation.device,
        operation.request.task.purpose()?,
    )
    .await
    {
        Ok(current) => current,
        Err(Fault::Request(Error::Conflict | Error::WindowsDeclaredEnrollmentNotReady)) => {
            return Ok(Authorization(false));
        }
        Err(e) => return Err(e),
    };
    if current != operation.device.clone() {
        return Ok(Authorization(false));
    }
    let tenant = tx.tenant_id().to_string();
    let device = operation.device.clone();
    let id = operation.id;
    let allowed = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    rss_mdm_device_service::lifecycle::execution_allowed_in(
                        c, &tenant, &device, id,
                    )
                    .await
                    .map_err(Error::from),
                )
            })
        })
        .await??;
    if !allowed {
        return Ok(Authorization(false));
    }
    let permissions = operation.request.task.permissions()?;
    Ok(Authorization(
        tx.with_connection_context(
            &mut (source, key, &operation.authority, &permissions),
            move |ctx, c| {
                Box::pin(async move { Ok(ctx.2.valid(ctx.0, c, ctx.1, ctx.3, now).await) })
            },
        )
        .await??,
    ))
}
pub struct Authorization(bool);
impl Authorization {
    pub fn is_authorized(&self) -> bool {
        self.0
    }
}

pub async fn receipt_valid(
    key: &Arc<rss_mdm_native_protection::Protector>,
    tx: &mut PgTransaction<'_>,
    operation: &Operation,
) -> Result<bool> {
    match current_registration(tx, &operation.device, operation.request.task.purpose()?).await {
        Ok(current) if current == operation.device.clone() => {}
        Ok(_) | Err(Fault::Request(Error::Conflict | Error::WindowsDeclaredEnrollmentNotReady)) => {
            return Ok(false);
        }
        Err(e) => return Err(e),
    }
    let key = key.clone();
    let authority = operation.authority.clone();
    let permissions = operation.request.task.permissions()?;
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(authority.receipt_valid(c, &key, &permissions).await) })
        })
        .await??)
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
        sqlx::query("WITH selected AS MATERIALIZED (SELECT o.id, o.device, o.dispatch_failure, o.request, o.input_context, CAST(o.authority AS text), o.revision, o.generation, o.epoch, o.gateway_accepted, CAST(d.command_device AS text) FROM mdm_planning.configuration_operations AS o INNER JOIN mdm_access.command_authorities AS d USING (tenant_id, device) WHERE o.tenant_id = CAST($1 AS uuid) AND o.id = ANY($2)), budget AS (SELECT CAST(COALESCE(sum(octet_length(request) + octet_length(authority) + octet_length(CAST(input_context AS text)) + COALESCE(octet_length(CAST(dispatch_failure AS text)), 0) + 1024), 0) AS bigint) AS bytes FROM selected) SELECT selected.*, budget.bytes AS input_bytes FROM budget LEFT JOIN selected ON budget.bytes <= 16777216")
  .bind(tenant.to_string()).bind(ids).fetch_all(c).await
    }?;
    rss_mdm_query_postgres::observe_rows("configuration.inputs", &rows)?;
    let bytes: i64 = rows
        .first()
        .ok_or(Error::Conflict)?
        .try_get("input_bytes")?;
    if !rss_mdm_query_postgres::within_budget(
        "configuration.inputs",
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

/// Immutable Timeline association, independent of the operation's current authorization.
pub async fn association_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> std::result::Result<Option<(String, Option<Uuid>)>, sqlx::Error> {
    sqlx::query_as("SELECT device,NULL::uuid FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await
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
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND id=ANY($2)").bind(tenant.to_string()).bind(ids).fetch_all(c).await?;
    Ok(ids.into_iter().collect())
}
