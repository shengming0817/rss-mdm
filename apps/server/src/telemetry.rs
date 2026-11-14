//! Installation-owned telemetry resources. Runtime opens only already-installed, admitted stores.
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
    pub resource_id: uuid::Uuid,
    pub backend: Storage,
    pub ingress: rss_mdm_telemetry_service::Limits,
    pub maintenance: rss_mdm_telemetry_service::maintenance::Policy,
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
        tenant: String,
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
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.resource_id.is_nil() {
            return Err(invalid());
        }
        self.ingress.validate().map_err(|_| invalid())?;
        self.maintenance.validate().map_err(|_| invalid())?;
        self.profile()?;
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

    pub(crate) fn profile(&self) -> Result<Option<StorageProfile>, Error> {
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
                let tenant = TenantId::parse(fixed).map_err(|_| invalid())?;
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
    pub(crate) fn configuration_binding(&self) -> Result<[u8; 32], Error> {
        use sha2::{Digest, Sha256};
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
                tenant: _,
                control,
                endpoint,
                ..
            } => serde_json::json!(["click_house", coordinate(control), endpoint]),
        };
        let identity = self.resource_id;
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
    pub(crate) fn tenant(&self) -> Result<Option<TenantId>, Error> {
        match &self.backend {
            Storage::TimescaleDedicated { tenant, .. } | Storage::ClickHouse { tenant, .. } => {
                Ok(Some(TenantId::parse(tenant).map_err(|_| invalid())?))
            }
            _ => Ok(None),
        }
    }
    pub(crate) fn database(&self) -> &Database {
        match &self.backend {
            Storage::Postgres { database }
            | Storage::TimescaleShared { database, .. }
            | Storage::TimescaleDedicated { database, .. } => database,
            Storage::ClickHouse { control, .. } => control,
        }
    }
    #[allow(
        clippy::cognitive_complexity,
        reason = "selected backend admission preserves each backend error without fallback"
    )]
    pub(crate) async fn open_backend(&self) -> Result<Backend, Error> {
        self.validate()?;
        let profile = self.profile()?;
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
                if !matches!(sqlx::query_scalar::<_,uuid::Uuid>("SELECT id FROM public.mdm_telemetry_installation").fetch_one(&runtime).await, Ok(id) if id==self.resource_id)
                {
                    runtime.close().await;
                    return Err(unavailable());
                }
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
                tenant: _,
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
                if !matches!(sqlx::query_scalar::<_,uuid::Uuid>("SELECT id FROM public.mdm_telemetry_installation").fetch_one(&runtime).await, Ok(id) if id==self.resource_id)
                {
                    runtime.close().await;
                    return Err(unavailable());
                }
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
                    self.tenant()?.ok_or_else(invalid)?,
                    runtime.clone(),
                    connections,
                    SystemClock,
                    limits,
                    rss_timeseries_clickhouse::CursorKey::new(key),
                    deadline,
                )
                .await
                {
                    Ok(store) => Backend::ClickHouse(Box::new(store)),
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
/// Open only explicitly installed physical resources. A failed optional resource stays unavailable;
/// tenant selection never falls back to another store or creates a pool.
pub(crate) async fn open(
    configurations: &[Config],
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    dependencies: rss_mdm_telemetry_service::PolicyDependencies,
    signing: Arc<rss_mdm_task_trust::Signing>,
    mut acquire: impl FnMut(Resource),
) -> Result<Arc<Service>, Error> {
    let default = configurations.first().ok_or_else(invalid)?;
    if !matches!(default.backend, Storage::Postgres { .. }) {
        return Err(invalid());
    }
    let mut resources = Vec::new();
    for (index, configuration) in configurations.iter().enumerate() {
        let binding = configuration.configuration_binding()?;
        let tenant = configuration.tenant()?;
        let backend = match configuration.open_backend().await {
            Ok(backend) => {
                let backend = Arc::new(backend);
                acquire(Resource(backend.clone()));
                Some(backend)
            }
            Err(error) if index == 0 => return Err(error),
            Err(error) => {
                eprintln!(
                    "optional telemetry resource {} unavailable: {error}",
                    configuration.resource_id
                );
                None
            }
        };
        resources.push(rss_mdm_telemetry_service::backend::Resource {
            binding,
            tenant,
            backend,
        });
    }
    Service::new(
        probe,
        runtime,
        dependencies,
        resources,
        signing,
        default.ingress.clone(),
        default.maintenance,
        rss_mdm_telemetry_service::StorageBudget {
            points: default.limits.max_points,
            series: default.limits.max_series,
            bytes: default.limits.max_bytes,
        },
    )
    .map(Arc::new)
    .map_err(|_| invalid())
}
pub(crate) struct Resource(pub Arc<Backend>);
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
