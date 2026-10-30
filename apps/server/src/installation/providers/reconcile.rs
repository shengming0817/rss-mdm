//! 部署进程消费领域待办；运行服务不持有供应方管理员凭据。
use super::storage::{self, Workload};
use crate::installation::{Error, Result, install::Input};
use rss_mdm_content_service::connections;
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

async fn scope(c: &mut PgConnection, tenant: Uuid) -> Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}
pub async fn storage(
    input: &Input,
    config: &crate::config::Config,
    c: &mut PgConnection,
) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    if input.storage_profiles.iter().any(|p| !ids.insert(&p.id)) {
        return Err(Error::Input);
    }
    let tenants: Vec<Uuid> = sqlx::query_scalar(
        "SELECT tenant_id FROM public.mdm_tenants WHERE NOT deleted ORDER BY tenant_id",
    )
    .fetch_all(&mut *c)
    .await
    .map_err(|_| Error::Storage)?;
    for tenant in tenants {
        storage_tenant(input, config, c, tenant).await?;
    }
    Ok(())
}

/// WNS 只对固定 Microsoft OAuth 入口验证；不把令牌取得等同于设备送达。
pub async fn wns(input: &Input, c: &mut PgConnection) -> Result<()> {
    let hosts:Vec<(Uuid,String)>=sqlx::query_as("SELECT tenant_id,receipt->'result'->>'hostId' FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id").fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
    for (tenant, host) in hosts {
        wns_host(input, c, tenant, host).await?;
    }
    Ok(())
}

async fn storage_tenant(
    input: &Input,
    config: &crate::config::Config,
    c: &mut PgConnection,
    tenant: Uuid,
) -> Result<()> {
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let operations: Vec<Uuid> = sqlx::query_scalar("SELECT operation_id FROM mdm_content_connections.versions WHERE tenant_id=$1 AND state='pending' AND NOT revoked ORDER BY attempted_at NULLS FIRST,revision LIMIT 8").bind(tenant).fetch_all(&mut *tx).await.map_err(|_| Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let host:Option<String>=sqlx::query_scalar("SELECT receipt->'result'->>'hostId' FROM public.mdm_tenant_operations WHERE tenant_id=$1 AND action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id LIMIT 1").bind(tenant).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
    let protection = if let Some(host) = host {
        let host = Uuid::parse_str(&host).map_err(|_| Error::Corrupt)?;
        let journal = crate::installation::local::Journal::open(
            &input.directory.join(format!("rss-mdm-{}", host.simple())),
        )?;
        let runtime: crate::config::Config = journal
            .load("requested-runtime.json")?
            .ok_or(Error::Corrupt)?;
        runtime.native_protector().map_err(|_| Error::Corrupt)?
    } else {
        config.native_protector().map_err(|_| Error::Corrupt)?
    };
    for operation in operations {
        if !storage_attempt(c, tenant, operation).await? {
            continue;
        }
        if let Err(error) =
            storage_operation(input, c, tenant, operation, protection.as_ref()).await
        {
            storage_failure(c, tenant, operation, error).await?;
        }
    }

    activate_latest(c, tenant, protection.as_ref()).await?;

    Ok(())
}

async fn wns_host(input: &Input, c: &mut PgConnection, tenant: Uuid, host: String) -> Result<()> {
    let host = Uuid::parse_str(&host).map_err(|_| Error::Corrupt)?;
    let journal = crate::installation::local::Journal::open(
        &input.directory.join(format!("rss-mdm-{}", host.simple())),
    )?;
    let runtime: crate::config::Config = journal
        .load("requested-runtime.json")?
        .ok_or(Error::Corrupt)?;
    let key = runtime.native_protector().map_err(|_| Error::Corrupt)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let revision:Option<i64>=sqlx::query_scalar("SELECT v.revision FROM mdm_wns.versions v JOIN mdm_wns.heads h USING(tenant_id,revision) WHERE v.tenant_id=$1 AND NOT revoked AND qualified_at IS NULL AND (attempted_at IS NULL OR attempted_at<extract(epoch FROM clock_timestamp())-60)").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
    let Some(revision) = revision else {
        tx.rollback().await.map_err(|_| Error::Storage)?;
        return Ok(());
    };
    let push = rss_mdm_windows_channel::wns_materials::load(
        &mut tx,
        &tenant.to_string(),
        revision,
        &key,
        crate::clock::monotonic(),
        false,
    )
    .await
    .map_err(|_| Error::Corrupt)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    let result = push.validate_credentials().await;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    if result.is_err() {
        sqlx::query("UPDATE mdm_wns.versions SET attempted_at=floor(extract(epoch FROM clock_timestamp()))::bigint,failure_reason='oauth_validation_failed' WHERE tenant_id=$1 AND revision=$2 AND qualified_at IS NULL").bind(tenant).bind(revision).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    }
    if result.is_ok() {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
        rss_mdm_windows_channel::wns_materials::qualify(
            &mut tx,
            &tenant.to_string(),
            revision,
            now,
        )
        .await
        .map_err(|_| Error::Conflict)?;
    }
    tx.commit().await.map_err(|_| Error::Storage)?;

    Ok(())
}

async fn storage_operation(
    input: &Input,
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<()> {
    let id = TenantId::parse(&tenant.to_string()).map_err(|_| Error::Corrupt)?;

    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let pending = connections::pending(&mut tx, id, operation, protection)
        .await
        .map_err(connection_error)?;
    let Some(profile) = input
        .storage_profiles
        .iter()
        .find(|p| p.id == pending.receipt.profile)
    else {
        sqlx::query("UPDATE mdm_content_connections.versions SET failure_reason='profile_unavailable' WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(operation).execute(&mut *tx).await.map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
        return Ok(());
    };
    let metadata = connections::Metadata {
        endpoint: profile.endpoint.clone(),
        region: profile.region.clone(),
        bucket: profile.bucket.clone(),
        namespace: profile.namespace.clone(),
        private_ca: crate::config::read(&profile.ca_file, 1024 * 1024, false)
            .map_err(|_| Error::Input)?
            .to_vec(),
    };
    connections::bind_metadata(&mut tx, id, operation, &metadata)
        .await
        .map_err(connection_error)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let material = Workload {
        create_identity: pending.generated,
        access: pending.credentials.access_key,
        secret: pending.credentials.secret_key,
        token: pending.credentials.session_token,
    };
    let result = storage::prepare(&input.directory, profile, tenant, operation, &material).await;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    match result {
        Ok(evidence) => {
            connections::qualify(&mut tx, id, operation, &metadata, evidence.qualified_at)
                .await
                .map_err(connection_error)?;
        }
        Err(_) => {
            // 保留原操作和原凭据，下一次从已记录的外部结果恢复。
            sqlx::query("UPDATE mdm_content_connections.versions SET failure_reason='provider_qualification_failed' WHERE tenant_id=$1 AND operation_id=$2 AND state='pending'").bind(tenant).bind(operation).execute(&mut *tx).await.map_err(|_| Error::Storage)?;
        }
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    Ok(())
}

fn connection_error(error: rss_mdm_content_service::Error) -> Error {
    match error {
        rss_mdm_content_service::Error::Conflict => Error::Conflict,
        rss_mdm_content_service::Error::Configuration
        | rss_mdm_content_service::Error::Malformed => Error::Input,
        rss_mdm_content_service::Error::Metadata | rss_mdm_content_service::Error::Invariant => {
            Error::Corrupt
        }
        _ => Error::Storage,
    }
}
async fn storage_attempt(c: &mut PgConnection, tenant: Uuid, operation: Uuid) -> Result<bool> {
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let state: Option<String> = sqlx::query_scalar("UPDATE mdm_content_connections.versions SET attempted_at=clock_timestamp(),state=CASE WHEN expires_at<=extract(epoch FROM statement_timestamp()) THEN 'rejected' ELSE state END,failure_reason=CASE WHEN expires_at<=extract(epoch FROM statement_timestamp()) THEN 'credentials_expired' ELSE failure_reason END WHERE tenant_id=$1 AND operation_id=$2 AND state='pending' AND NOT revoked RETURNING state")
        .bind(tenant).bind(operation).fetch_optional(&mut *tx).await.map_err(|_| Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    Ok(state.as_deref() == Some("pending"))
}
async fn storage_failure(
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    error: Error,
) -> Result<()> {
    let (rejected, reason) = match error {
        Error::Storage => return Err(Error::Storage),
        Error::Conflict => (true, "qualification_rejected"),
        Error::Corrupt => (true, "invalid_candidate_material"),
        Error::Input => (false, "provider_configuration_unavailable"),
        Error::Busy => (false, "operation_busy"),
    };
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    sqlx::query("UPDATE mdm_content_connections.versions SET failure_reason=$3,state=CASE WHEN $4 THEN 'rejected' ELSE state END WHERE tenant_id=$1 AND operation_id=$2 AND state='pending'")
        .bind(tenant).bind(operation).bind(reason).bind(rejected).execute(&mut *tx).await.map_err(|_| Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)
}

async fn activate_latest(
    c: &mut PgConnection,
    tenant: Uuid,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<()> {
    // Qualification and activation have different external failure boundaries. Retry the
    // latest qualified material even when a previous process stopped after qualification.
    let id = TenantId::parse(&tenant.to_string()).map_err(|_| Error::Corrupt)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let qualified:Option<i64>=sqlx::query_scalar("SELECT v.revision FROM mdm_content_connections.versions v JOIN mdm_content_connections.heads h USING(tenant_id,revision) WHERE tenant_id=$1 AND state='qualified' AND NOT revoked AND (expires_at IS NULL OR expires_at>extract(epoch FROM clock_timestamp()))")
        .bind(tenant).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    if let Some(revision) = qualified {
        let result = connections::activate_rotation(
            c,
            id,
            revision as u64,
            protection,
            std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        )
        .await;
        let reason = match result {
            Ok(true) => None,
            Ok(false) => Some("migration_or_maintenance_required"),
            Err(_) => Some("activation_unconfirmed"),
        };
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        scope(&mut tx, tenant).await?;
        sqlx::query("UPDATE mdm_content_connections.versions SET failure_reason=$3 WHERE tenant_id=$1 AND revision=$2 AND state='qualified'")
            .bind(tenant).bind(revision).bind(reason).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/setup/reconcile.rs"]
mod tests;
