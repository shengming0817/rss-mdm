//! Caller-owned transactions; all association writes share the registration lifecycle fence.
use super::*;
use crate::database::db;
use rss_mdm_agent_wire::runtime::AccessResult;
use rss_mdm_inventory::Channel;
use sqlx::PgConnection;

fn write_error(e: sqlx::Error) -> Error {
    if e.as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        Error::Conflict
    } else {
        db(e)
    }
}

pub async fn lock_registration(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &str,
    registration: Uuid,
    generation: i64,
) -> Result<(), Error> {
    let tenant = tenant.to_string();
    crate::lifecycle::require_work_in(c, &tenant, device).await?;
    crate::device::endpoints::lock_in(c, &tenant, device, Channel::Agent).await?;
    let current = crate::device::endpoints::current_in(c, &tenant, device, Channel::Agent)
        .await?
        .ok_or(Error::Conflict)?;
    if current.registration_id != registration || current.generation != generation {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub async fn get_in(c: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<Binding, Error> {
    let value: serde_json::Value = sqlx::query_scalar(
        "SELECT document FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(c)
    .await
    .map_err(db)?
    .ok_or(Error::NotFound)?;
    let binding: Binding = serde_json::from_value(value).map_err(|_| Error::Corrupt)?;
    binding.validate().map_err(|_| Error::Corrupt)?;
    if binding.tenant != tenant || binding.id != id {
        return Err(Error::Corrupt);
    }
    Ok(binding)
}

pub async fn locked_in(c: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<Binding, Error> {
    let first = get_in(c, tenant, id).await?;
    crate::lifecycle::require_work_in(c, &tenant.to_string(), &first.device).await?;
    locked_observation_in(c, tenant, id).await
}

/// Factual completion is accepted while retirement drains work; it cannot admit new work.
pub async fn locked_observation_in(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
) -> Result<Binding, Error> {
    let first = get_in(c, tenant, id).await?;
    crate::device::endpoints::lock_in(c, &tenant.to_string(), &first.device, Channel::Agent)
        .await?;
    let current =
        crate::device::endpoints::current_in(c, &tenant.to_string(), &first.device, Channel::Agent)
            .await?
            .ok_or(Error::Conflict)?;
    if current.registration_id != first.registration
        || current.generation != first.registration_generation
    {
        return Err(Error::Conflict);
    }
    sqlx::query(
        "SELECT id FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(id)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    get_in(c, tenant, id).await
}

/// Historical bindings deliberately participate: an unlink never resets self-enrollment.
pub async fn first_in(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &str,
    registration: Uuid,
    _person: &Person,
    _account: &AccessAccount,
) -> Result<bool, Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND device=$2 AND registration=$3)")
        .bind(tenant).bind(device).bind(registration).fetch_one(c).await.map_err(db)?;
    Ok(!exists)
}

pub async fn insert_in(c: &mut PgConnection, b: &Binding) -> Result<(), Error> {
    b.validate()?;
    lock_registration(
        c,
        b.tenant,
        &b.device,
        b.registration,
        b.registration_generation,
    )
    .await?;
    require_retired_in(c, b).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND device=$2 AND registration=$3")
        .bind(b.tenant).bind(&b.device).bind(b.registration).fetch_one(&mut *c).await.map_err(db)?;
    if count >= 128 {
        return Err(Error::Capacity);
    }
    sqlx::query("INSERT INTO mdm_access.device_access_bindings(tenant_id,id,device,registration,registration_generation,instance,principal,generation,revision,state,account,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(b.tenant).bind(b.id).bind(&b.device).bind(b.registration).bind(b.registration_generation)
        .bind(b.person.instance).bind(b.person.principal).bind(b.generation).bind(b.revision).bind(state(b.state))
        .bind(b.account.as_ref().map(serde_json::to_value).transpose().map_err(|_| Error::Malformed)?)
        .bind(serde_json::to_value(b).map_err(|_| Error::Malformed)?).execute(c).await.map_err(write_error)?;
    Ok(())
}

pub async fn save_in(c: &mut PgConnection, b: &Binding, expected: i64) -> Result<(), Error> {
    b.validate()?;
    let result = sqlx::query("UPDATE mdm_access.device_access_bindings SET instance=$3,principal=$4,generation=$5,revision=$6,state=$7,account=$8,document=$9 WHERE tenant_id=$1 AND id=$2 AND revision=$10")
        .bind(b.tenant).bind(b.id).bind(b.person.instance).bind(b.person.principal).bind(b.generation).bind(b.revision).bind(state(b.state))
        .bind(b.account.as_ref().map(serde_json::to_value).transpose().map_err(|_| Error::Malformed)?)
        .bind(serde_json::to_value(b).map_err(|_| Error::Malformed)?).bind(expected).execute(c).await.map_err(write_error)?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Recheck for a trusted platform verifier or credential consumer on its borrowed connection.
pub async fn require_active_in(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    generation: i64,
) -> Result<Binding, Error> {
    let b = locked_in(c, tenant, id).await?;
    if b.generation != generation || !accepts_login_in(c, &b).await? {
        return Err(Error::Forbidden);
    }
    Ok(b)
}

/// Read the same persisted readiness predicate used by bounded qualification projections.
/// This borrows the caller's existing binding/lifecycle locks and never takes another lock.
pub async fn accepts_login_in(c: &mut PgConnection, binding: &Binding) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT mdm_access.access_binding_ready($1)")
        .bind(serde_json::to_value(binding).map_err(|_| Error::Corrupt)?)
        .fetch_one(c)
        .await
        .map_err(db)
}

/// Called only after execution authenticates the task/attempt and its frozen definition.
/// Old-generation results are retained as history without promoting a current association.
pub async fn result_in(
    c: &mut PgConnection,
    tenant: Uuid,
    task: Uuid,
    attempt: Uuid,
    event: Uuid,
    report: &AccessResult,
    project: bool,
) -> Result<bool, Error> {
    use sha2::{Digest, Sha256};
    if task.is_nil() || attempt.is_nil() || event.is_nil() {
        return Err(Error::Malformed);
    }
    let mut b = locked_observation_in(c, tenant, report.binding_id).await?;
    report
        .validate_for(b.intent.platform())
        .map_err(|_| Error::Malformed)?;
    let bytes = serde_json::to_vec(report).map_err(|_| Error::Malformed)?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if let Some(old) = sqlx::query_scalar::<_,Vec<u8>>("SELECT digest FROM mdm_access.device_access_results WHERE tenant_id=$1 AND task=$2 AND attempt=$3 AND event=$4")
        .bind(tenant).bind(task).bind(attempt).bind(event).fetch_optional(&mut *c).await.map_err(db)? {
        return if old == digest { Ok(false) } else { Err(Error::Conflict) };
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_access.device_access_results WHERE tenant_id=$1 AND binding=$2",
    )
    .bind(tenant)
    .bind(b.id)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if count >= 4096 {
        return Err(Error::Capacity);
    }
    sqlx::query("INSERT INTO mdm_access.device_access_results(tenant_id,task,attempt,event,binding,digest,document) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(tenant).bind(task).bind(attempt).bind(event).bind(b.id).bind(digest.as_slice())
        .bind(serde_json::to_value(report).map_err(|_| Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
    if !project
        || report.binding_generation != b.generation
        || report.revision != b.revision
        || report.definition_digest != b.definition_digest()?
    {
        // Preserve the stable creation fact across policy/personnel revisions or unlinking, without
        // promoting the old configuration or personnel grant.
        if b.created_by_rss
            && b.account.is_none()
            && let AccessEffect::Applied { account, .. } = &report.effect
        {
            b.account = Some(account.clone());
            save_in(c, &b, b.revision).await?;
        }
        return Ok(false);
    }
    match &report.effect {
        AccessEffect::Applied {
            account,
            role,
            windows,
            ..
        } => {
            if windows.as_ref().is_some_and(|facts| {
                facts.factor_generation() != b.factor_generation
                    || !facts.matches(&b.configuration.windows)
            }) {
                return Err(Error::Conflict);
            }
            let required = b
                .configuration
                .role
                .or(if b.account.is_none() && b.created_by_rss {
                    Some(rss_mdm_agent_wire::runtime::AccessRole::Standard)
                } else {
                    None
                });
            if required.is_some_and(|expected| expected != *role) {
                return Err(Error::Conflict);
            }
            if b.state == State::Revoked || b.account.as_ref().is_some_and(|old| old != account) {
                return Err(Error::Conflict);
            }
            b.account = Some(account.clone());
            // Current observations remain in effect. Incomplete enrollment must not erase
            // the last verified key used to fence subsequent reset attempts.
            if report
                .effect
                .complete(&b.configuration, b.intent.platform())
            {
                b.applied_windows = windows.clone();
            }
            if report
                .effect
                .complete(&b.configuration, b.intent.platform())
            {
                b.state = State::Active;
            }
        }
        AccessEffect::WhfbRetired {
            account,
            disposition,
            facts,
        } => {
            if b.state != State::Revoked
                || b.account.as_ref() != Some(account)
                || *disposition != b.account_disposition
                || facts.factor_generation != b.factor_generation
                || !matches!(
                    b.configuration.windows,
                    rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::Whfb
                )
            {
                return Err(Error::Conflict);
            }
            b.applied_windows = Some(rss_mdm_agent_wire::runtime::AccessWindowsFacts::Whfb(
                facts.clone(),
            ));
        }
        AccessEffect::Unbound { disposition }
            if b.state != State::Revoked
                || *disposition != b.account_disposition
                || (b.intent.platform() == TaskPlatform::Windows
                    && matches!(
                        b.configuration.windows,
                        rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::Whfb
                    )) =>
        {
            return Err(Error::Conflict);
        }
        _ => {}
    }
    if b.applied_revision == Some(b.revision)
        && !report
            .effect
            .complete(&b.configuration, b.intent.platform())
    {
        return Ok(false);
    }
    b.received_revision = Some(b.revision);
    if report
        .effect
        .complete(&b.configuration, b.intent.platform())
    {
        b.applied_revision = Some(b.revision);
    }
    b.effect = Some(report.effect.clone());
    save_in(c, &b, b.revision).await?;
    let phase = match &report.effect {
        AccessEffect::Unknown => "unknown",
        AccessEffect::Failed { .. } => "failed",
        effect if effect.complete(&b.configuration, b.intent.platform()) => "applied",
        _ => "pending",
    };
    super::lifecycle::emit_on(c, &b, None, event, phase).await?;
    Ok(true)
}

pub async fn received_in(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    generation: i64,
    revision: i64,
    digest: [u8; 32],
) -> Result<(), Error> {
    let mut b = locked_in(c, tenant, id).await?;
    if b.generation != generation || b.revision != revision || b.definition_digest()? != digest {
        return Err(Error::Conflict);
    }
    b.received_revision = Some(revision);
    save_in(c, &b, revision).await
}

/// Retirement already holds the lifecycle locks; never reopen them after marking it retired.
pub async fn retire_in(
    c: &mut PgConnection,
    tenant: &str,
    registration: Uuid,
) -> Result<(), Error> {
    let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT document FROM mdm_access.device_access_bindings WHERE tenant_id=$1::uuid AND registration=$2 AND state<>'revoked' ORDER BY id FOR UPDATE")
        .bind(tenant).bind(registration).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let mut b: Binding = serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
        let expected = b.revision;
        b.generation = b.generation.checked_add(1).ok_or(Error::Capacity)?;
        b.revision = b.revision.checked_add(1).ok_or(Error::Capacity)?;
        b.state = State::Revoked;
        b.configuration.enabled = false;
        save_in(c, &b, expected).await?;
        super::lifecycle::emit_on(c, &b, None, b.id, "retired").await?;
    }
    Ok(())
}

fn state(value: State) -> &'static str {
    match value {
        State::Pending => "pending",
        State::Active => "active",
        State::Revoked => "revoked",
    }
}

/// A started, correlated task reports native account identity without completing configuration.
pub async fn prepared_in(
    c: &mut PgConnection,
    tenant: Uuid,
    value: &rss_mdm_agent_wire::runtime::AccessPrepared,
) -> Result<(), Error> {
    value.account.validate().map_err(|_| Error::Malformed)?;
    let mut b = locked_observation_in(c, tenant, value.binding_id).await?;
    if b.intent.platform() != value.account.platform()
        || b.account.as_ref().is_some_and(|a| a != &value.account)
    {
        return Err(Error::Conflict);
    }
    if b.state == State::Revoked
        || b.generation != value.binding_generation
        || b.revision != value.revision
        || b.definition_digest()? != value.definition_digest
    {
        // The caller correlated the signed Start. Remember a created account for eventual cleanup only.
        if !b.created_by_rss || b.account.is_some() {
            return Ok(());
        }
    }
    b.account = Some(value.account.clone());
    save_in(c, &b, b.revision).await
}

/// Resolve one current device-wide Mac configuration from eligible Policy publications.
/// Multiple matching policies may agree; conflicting settings cannot be deployed.
pub async fn mac_configuration_in(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &str,
) -> Result<rss_mdm_agent_wire::platform_sso::LoginConfiguration, Error> {
    // Apply the budget to eligible Mac configurations, not unrelated tenant policies.
    let candidates: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT q.result->'configuration' FROM mdm_policy.policies p
         JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(p.tenant_id,p.current_version)
         CROSS JOIN LATERAL (SELECT mdm_commands.access_policy(p.id,$2,
             floor(extract(epoch FROM statement_timestamp()))::bigint) AS result OFFSET 0) q
         WHERE p.tenant_id=$1 AND p.state='enabled' AND v.action_kind='device_access'
           AND q.result->>'state'='eligible'
           AND q.result#>>'{configuration,enabled}'='true'
           AND q.result#>'{configuration,mac}' IS NOT NULL
           AND q.result#>'{configuration,mac}' <> 'null'::jsonb
         ORDER BY p.id LIMIT 129",
    )
    .bind(tenant)
    .bind(device)
    .fetch_all(&mut *c)
    .await
    .map_err(db)?;
    if candidates.len() > 128 {
        return Err(Error::Capacity);
    }
    let mut selected = None;
    for configuration in candidates {
        let config: AccessConfiguration =
            serde_json::from_value(configuration).map_err(|_| Error::Corrupt)?;
        config.validate().map_err(|_| Error::Corrupt)?;
        if let Some(mac) = config.mac {
            if selected.as_ref().is_some_and(|old| old != &mac) {
                return Err(Error::Conflict);
            }
            selected = Some(mac);
        }
    }
    selected.ok_or(Error::NotFound)
}

/// Registration-locked admission: a new binding cannot race an old native key cleanup.
pub async fn require_retired_in(c: &mut PgConnection, b: &Binding) -> Result<(), Error> {
    let Some(account @ AccessAccount::Windows { .. }) = &b.account else {
        return Ok(());
    };
    let configuration =
        serde_json::to_value(&b.configuration.windows).map_err(|_| Error::Malformed)?;
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND account=$4 AND state='revoked' AND (document->'appliedRevision' IS DISTINCT FROM document->'revision') AND (document#>>'{configuration,windows,kind}'='whfb' OR document#>>'{configuration,windows,kind}' IS DISTINCT FROM $5))")
        .bind(b.tenant).bind(&b.device).bind(b.registration).bind(serde_json::to_value(account).map_err(|_| Error::Malformed)?).bind(configuration["kind"].as_str().ok_or(Error::Malformed)?)
        .fetch_one(c).await.map_err(db)?;
    if pending {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}
