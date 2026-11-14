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
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: Input,
    pub tenant: Uuid,
}
/// Explicit tenant material maintenance using the installation's shared keys and original owners.
pub async fn run(request: Request) -> Result<()> {
    let input = &request.installation;
    if request.tenant.is_nil() {
        return Err(Error::Input);
    }
    let root = crate::installation::local::Journal::open(&input.directory)?;
    let config: crate::config::Config = root.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let mut c = PgConnection::connect_with(
        &input
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    crate::migration::verify_identity(
        &mut c,
        &crate::migration::Installation {
            instance_id: config.identity.instance_id.clone(),
            target: config.storage_binding.target,
            lineage: config.storage_binding.lineage,
            audit_mode: config.audit.mode(),
        },
    )
    .await
    .map_err(|_| Error::Conflict)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM public.mdm_tenants WHERE tenant_id=$1 AND NOT deleted AND tenant_id<>(SELECT management_tenant_id FROM public.mdm_installation))")
        .bind(request.tenant).fetch_one(&mut c).await.map_err(|_|Error::Storage)?;
    if !exists {
        return Err(Error::Input);
    }
    storage_tenant(input, &config, &mut c, request.tenant).await?;
    wns_tenant(&config, &mut c, request.tenant).await?;
    super::mail::qualify_tenant(input, &config, &mut c, request.tenant).await?;
    super::webhook::qualify_tenant(input, &mut c, request.tenant).await?;
    c.close().await.map_err(|_| Error::Storage)
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
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
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

async fn wns_tenant(
    runtime: &crate::config::Config,
    c: &mut PgConnection,
    tenant: Uuid,
) -> Result<()> {
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
