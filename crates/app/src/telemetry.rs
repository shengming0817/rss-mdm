//! Tenant-bound telemetry assembly. Runtime opens only already-installed, admitted stores.
use crate::{
    Error, Failure,
    config::{Database, read, secret},
};
use rss_mdm_telemetry_service::{
    Service,
    backend::{Backend, SystemClock},
};
use rss_request_context::{Deadline, TenantId};
use rss_timeseries_postgres::{StorageProfile, StoreConnections};
use serde::{Deserialize, Serialize};
use std::{
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Config {
    pub backend: Storage,
    pub ingress: rss_mdm_telemetry_service::Limits,
    pub limits: Limits,
    pub cursor_key_file: PathBuf,
    pub connections: NonZeroU32,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Limits {
    pub max_points: NonZeroU32,
    pub max_series: NonZeroU32,
    pub max_bytes: NonZeroU32,
    pub replay_micros: NonZeroU64,
    pub cursor_micros: NonZeroU64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "snake_case",
    deny_unknown_fields
)]
pub enum Storage {
    Postgres {
        database: Database,
    },
    TimescaleShared {
        database: Database,
        chunk_micros: NonZeroU64,
    },
    TimescaleDedicated {
        database: Database,
        maintenance: Database,
        maintenance_owner: String,
        tenant: String,
        chunk_micros: NonZeroU64,
        resolutions: Vec<NonZeroU64>,
    },
    ClickHouse {
        control: Database,
        endpoint: String,
        ca_file: PathBuf,
        reader: Credential,
        writer: Credential,
        maintenance: Credential,
        max_scan_rows: NonZeroU64,
        max_scan_bytes: NonZeroU64,
        max_memory_bytes: NonZeroU64,
    },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Credential {
    pub user: String,
    pub password_file: PathBuf,
}
fn invalid() -> Error {
    Error::Malformed
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Database)
}
impl Credential {
    fn load(&self) -> Result<rss_timeseries_clickhouse::Credentials, Error> {
        rss_timeseries_clickhouse::Credentials::new(
            self.user.clone(),
            secret(&self.password_file)?.to_string(),
        )
        .map_err(|_| invalid())
    }
}
async fn pool(database: &Database, max: NonZeroU32) -> Result<sqlx::PgPool, Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max.get())
        .acquire_timeout(Duration::from_secs(6))
        .connect_with(database.options()?)
        .await
        .map_err(|_| unavailable())
}
impl Config {
    pub(crate) fn validate(&self, tenant: TenantId) -> Result<(), Error> {
        self.ingress.validate().map_err(|_| invalid())?;
        self.profile(tenant)?;
        if self.connections.get() > 64
            || self.limits.max_points.get() > 4096
            || self.limits.max_series.get() > 4096
            || self.limits.max_bytes.get() > 4 * 1024 * 1024
        {
            return Err(invalid());
        }
        if let Storage::TimescaleDedicated {
            database,
            maintenance,
            maintenance_owner,
            ..
        } = &self.backend
        {
            identifier(maintenance_owner)?;
            if database.host != maintenance.host
                || database.port != maintenance.port
                || database.name != maintenance.name
                || database.user == maintenance.user
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(crate) fn profile(&self, tenant: TenantId) -> Result<Option<StorageProfile>, Error> {
        use rss_timeseries_postgres::timescale::{DedicatedTenant, Hypertable};
        Ok(Some(match &self.backend {
            Storage::Postgres { .. } => StorageProfile::PostgreSQL,
            Storage::TimescaleShared { chunk_micros, .. } => StorageProfile::TimescaleSharedRls(
                Hypertable::new(*chunk_micros).map_err(|_| invalid())?,
            ),
            Storage::TimescaleDedicated {
                tenant: fixed,
                chunk_micros,
                resolutions,
                ..
            } => {
                if TenantId::parse(fixed).map_err(|_| invalid())? != tenant {
                    return Err(invalid());
                }
                StorageProfile::TimescaleDedicatedTenant(
                    DedicatedTenant::new(
                        tenant,
                        Hypertable::new(*chunk_micros).map_err(|_| invalid())?,
                        resolutions,
                    )
                    .map_err(|_| invalid())?,
                )
            }
            Storage::ClickHouse { .. } => return Ok(None),
        }))
    }
    pub(crate) async fn open(
        &self,
        flow: &Arc<crate::flow::Flow>,
        execution: Arc<rss_mdm_execution_service::ExecutionService>,
    ) -> Result<Arc<Service>, Error> {
        let tenant = flow.planning.tenant;
        let backend = self.open_backend(tenant).await?;
        let admitted = async {
            let binding =
                tokio::time::timeout(Duration::from_secs(6), self.configuration_binding())
                    .await
                    .map_err(|_| unavailable())??;
            rss_mdm_telemetry_service::admit_configuration(&flow.runtime, tenant, binding)
                .await
                .map_err(|_| invalid())
        }
        .await;
        if let Err(error) = admitted {
            let cutoff = Deadline::from_timeout(&SystemClock, Duration::from_secs(10))
                .map_err(|_| unavailable())?;
            backend.close(cutoff).await.map_err(|_| unavailable())?;
            return Err(error);
        }
        match Service::new(
            tenant,
            flow.runtime.clone(),
            flow.planning.clone(),
            backend,
            execution,
            self.ingress.clone(),
            rss_mdm_telemetry_service::StorageBudget {
                points: self.limits.max_points,
                series: self.limits.max_series,
                bytes: self.limits.max_bytes,
            },
        ) {
            Ok(service) => Ok(Arc::new(service)),
            Err(_) => Err(invalid()),
        }
    }
    async fn configuration_binding(&self) -> Result<[u8; 32], Error> {
        use sha2::{Digest, Sha256};
        use sqlx::Connection;
        let coordinate =
            |database: &Database| (database.host.clone(), database.port, database.name.clone());
        let backend = match &self.backend {
            Storage::Postgres { database } => serde_json::json!(["postgres", coordinate(database)]),
            Storage::TimescaleShared {
                database,
                chunk_micros,
            } => serde_json::json!(["timescale_shared", coordinate(database), chunk_micros]),
            Storage::TimescaleDedicated {
                database,
                tenant,
                chunk_micros,
                resolutions,
                ..
            } => {
                let mut resolutions = resolutions.clone();
                resolutions.sort();
                serde_json::json!([
                    "timescale_dedicated",
                    coordinate(database),
                    tenant,
                    chunk_micros,
                    resolutions
                ])
            }
            Storage::ClickHouse {
                control, endpoint, ..
            } => serde_json::json!(["click_house", coordinate(control), endpoint]),
        };
        let mut connection = sqlx::PgConnection::connect_with(&self.database().options()?)
            .await
            .map_err(|_| unavailable())?;
        let identity: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM public.mdm_telemetry_installation")
                .fetch_one(&mut connection)
                .await
                .map_err(|_| unavailable())?;
        connection.close().await.map_err(|_| unavailable())?;
        let cursor = Sha256::digest(read(&self.cursor_key_file, 32, true)?);
        Ok(Sha256::digest(
            serde_json::to_vec(&(
                "mdm.telemetry.storage.v1",
                identity,
                backend,
                &self.ingress,
                &self.limits,
                cursor.as_slice(),
            ))
            .map_err(|_| invalid())?,
        )
        .into())
    }
    pub(crate) fn database(&self) -> &Database {
        match &self.backend {
            Storage::Postgres { database }
            | Storage::TimescaleShared { database, .. }
            | Storage::TimescaleDedicated { database, .. } => database,
            Storage::ClickHouse { control, .. } => control,
        }
    }
    pub(crate) async fn open_backend(&self, tenant: TenantId) -> Result<Backend, Error> {
        self.validate(tenant)?;
        let profile = self.profile(tenant)?;
        let key: [u8; 32] = read(&self.cursor_key_file, 32, true)?
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        let deadline =
            Deadline::from_timeout(&SystemClock, Duration::from_secs(30)).map_err(|_| invalid())?;
        let limits = rss_timeseries_postgres::Limits {
            max_points: self.limits.max_points,
            max_series: self.limits.max_series,
            max_bytes: self.limits.max_bytes,
            replay_micros: self.limits.replay_micros,
            cursor_micros: self.limits.cursor_micros,
        };
        let backend = match &self.backend {
            Storage::Postgres { database }
            | Storage::TimescaleShared { database, .. }
            | Storage::TimescaleDedicated { database, .. } => {
                let runtime = pool(database, self.connections).await?;
                let maintenance = if let Storage::TimescaleDedicated {
                    maintenance,
                    maintenance_owner,
                    ..
                } = &self.backend
                {
                    match owner_pool(maintenance, self.connections, maintenance_owner).await {
                        Ok(p) => Some(p),
                        Err(e) => {
                            runtime.close().await;
                            return Err(e);
                        }
                    }
                } else {
                    None
                };
                let connections = match &maintenance {
                    Some(maintenance) => StoreConnections::Native {
                        runtime: runtime.clone(),
                        maintenance: maintenance.clone(),
                    },
                    None => StoreConnections::Runtime(runtime.clone()),
                };
                match rss_timeseries_postgres::PgStore::new(
                    profile.ok_or_else(invalid)?,
                    connections,
                    SystemClock,
                    limits,
                    rss_timeseries_postgres::CursorKey::new(key),
                    deadline,
                )
                .await
                {
                    Ok(store) => Backend::Postgres(store),
                    Err(_) => {
                        runtime.close().await;
                        if let Some(p) = maintenance {
                            p.close().await;
                        }
                        return Err(unavailable());
                    }
                }
            }
            Storage::ClickHouse {
                control,
                endpoint,
                ca_file,
                reader,
                writer,
                maintenance,
                max_scan_rows,
                max_scan_bytes,
                max_memory_bytes,
            } => {
                let connections = rss_timeseries_clickhouse::Connections::new(
                    endpoint,
                    &read(ca_file, 1024 * 1024, false)?,
                    reader.load()?,
                    writer.load()?,
                    maintenance.load()?,
                )
                .map_err(|_| invalid())?;
                let runtime = pool(control, self.connections).await?;
                let limits = rss_timeseries_clickhouse::Limits {
                    max_points: limits.max_points,
                    max_series: limits.max_series,
                    max_bytes: limits.max_bytes,
                    replay_micros: limits.replay_micros,
                    cursor_micros: limits.cursor_micros,
                    max_scan_rows: *max_scan_rows,
                    max_scan_bytes: *max_scan_bytes,
                    max_memory_bytes: *max_memory_bytes,
                };
                match rss_timeseries_clickhouse::ChStore::new(
                    tenant,
                    runtime.clone(),
                    connections,
                    SystemClock,
                    limits,
                    rss_timeseries_clickhouse::CursorKey::new(key),
                    deadline,
                )
                .await
                {
                    Ok(store) => Backend::ClickHouse(store),
                    Err(_) => {
                        runtime.close().await;
                        return Err(unavailable());
                    }
                }
            }
        };
        Ok(backend)
    }
}
pub(crate) struct Resource(pub Arc<Service>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "telemetry-storage"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        let deadline = Deadline::from_timeout(&SystemClock, Duration::from_secs(10))
            .map_err(rss_runtime::ShutdownError::new)?;
        self.0
            .close(deadline)
            .await
            .map_err(rss_runtime::ShutdownError::new)
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}
pub(crate) fn registration(
    service: Arc<Service>,
    relay_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("telemetry-relay", Duration::from_secs(15));
    task.into_registration(move |cancel| async move {
        service
            .run(relay_runtime, cancel)
            .await
            .map_err(rss_runtime::ShutdownError::new)
    })
}

pub(crate) fn identifier(value: &str) -> Result<String, Error> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid());
    }
    Ok(format!("\"{value}\""))
}
async fn owner_pool(
    database: &Database,
    max: NonZeroU32,
    owner: &str,
) -> Result<sqlx::PgPool, Error> {
    let sql = format!("SET ROLE {}", identifier(owner)?);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max.get())
        .acquire_timeout(Duration::from_secs(6))
        .after_connect(move |connection, _| {
            let sql = sql.clone();
            Box::pin(async move {
                sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(database.options()?)
        .await
        .map_err(|_| unavailable())
}

#[cfg(test)]
#[path = "../tests/telemetry/storage.rs"]
mod tests;

#[cfg(test)]
pub(crate) struct FixtureTask(tokio::sync::Mutex<Option<rss_runtime::ShutdownStack>>);
#[cfg(test)]
pub(crate) fn fixture_task(
    service: Arc<Service>,
    relay_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    options: sqlx::postgres::PgConnectOptions,
    tenant: TenantId,
) -> Result<FixtureTask, Error> {
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15)).map_err(|_| unavailable())?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .map_err(|_| unavailable())?;
    let mut startup = stack.startup().map_err(|_| unavailable())?;
    let listener = crate::worker_wake::Listener::new(options, tenant);
    let signals = listener.signals.clone();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(listener.clone()));
    let mut launch = startup.commit();
    launch.stage_task_with_token(listener.registration().critical());
    launch.stage_deferred_task_with_token(
        inventory
            .registration(signals.handle(crate::worker_wake::Work::Inventory))
            .critical(),
    );
    launch.stage_deferred_task_with_token(registration(service, relay_runtime).critical());
    launch.finish();
    Ok(FixtureTask(tokio::sync::Mutex::new(Some(stack))))
}
#[cfg(test)]
impl rss_runtime::ManagedResource for FixtureTask {
    fn name(&self) -> &str {
        "fixture-telemetry-worker"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(16)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        let stack = self.0.lock().await.take();
        if let Some(stack) = stack {
            let receipt = stack
                .shutdown()
                .join()
                .await
                .map_err(rss_runtime::ShutdownError::new)?;
            if !receipt.is_clean() {
                return Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                    "telemetry fixture worker did not close cleanly",
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/telemetry/ingress.rs"]
mod ingress;
