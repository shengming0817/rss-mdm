//! 部署进程消费领域待办；运行服务不持有供应方管理员凭据。
use super::storage::{self, Workload};
use crate::setup::{Error, Result, installation::Input};
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
        let id: TenantId = TenantId::parse(&tenant.to_string()).map_err(|_| Error::Corrupt)?;
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        scope(&mut tx, tenant).await?;
        let operations: Vec<Uuid> = sqlx::query_scalar("SELECT operation_id FROM mdm_content_connections.versions WHERE tenant_id=$1 AND state='pending' AND NOT revoked ORDER BY revision LIMIT 8").bind(tenant).fetch_all(&mut *tx).await.map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
        if operations.is_empty() {
            continue;
        }
        let host:Option<String>=sqlx::query_scalar("SELECT receipt->'result'->>'hostId' FROM public.mdm_tenant_operations WHERE tenant_id=$1 AND action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id LIMIT 1").bind(tenant).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
        let protection = if let Some(host) = host {
            let host = Uuid::parse_str(&host).map_err(|_| Error::Corrupt)?;
            let journal = crate::setup::local::Journal::open(
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
            let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
            scope(&mut tx, tenant).await?;
            let pending = connections::pending(&mut tx, id, operation, &protection)
                .await
                .map_err(|_| Error::Corrupt)?;
            let Some(profile) = input
                .storage_profiles
                .iter()
                .find(|p| p.id == pending.receipt.profile)
            else {
                sqlx::query("UPDATE mdm_content_connections.versions SET failure_reason='profile_unavailable' WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(operation).execute(&mut *tx).await.map_err(|_| Error::Storage)?;
                tx.commit().await.map_err(|_| Error::Storage)?;
                continue;
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
                .map_err(|_| Error::Conflict)?;
            tx.commit().await.map_err(|_| Error::Storage)?;
            let material = Workload {
                create_identity: pending.generated,
                access: pending.credentials.access_key,
                secret: pending.credentials.secret_key,
                token: pending.credentials.session_token,
            };
            let result =
                storage::prepare(&input.directory, profile, tenant, operation, &material).await;
            let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
            scope(&mut tx, tenant).await?;
            match result {
                Ok(evidence) => {
                    connections::qualify(&mut tx, id, operation, &metadata, evidence.qualified_at)
                        .await
                        .map_err(|_| Error::Conflict)?;
                }
                Err(_) => {
                    // 保留原操作和原凭据，下一次从已记录的外部结果恢复。
                    sqlx::query("UPDATE mdm_content_connections.versions SET failure_reason='provider_qualification_failed' WHERE tenant_id=$1 AND operation_id=$2 AND state='pending'").bind(tenant).bind(operation).execute(&mut *tx).await.map_err(|_| Error::Storage)?;
                }
            }
            tx.commit().await.map_err(|_| Error::Storage)?;
        }
    }
    Ok(())
}
