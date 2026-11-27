//! Real provider installation and product service dependencies; no substitute query backend.
use crate::{authority_t2_support::Context, planning_t2_support as planning};
use anyhow::{Context as _, Result};
use rss_mdm_telemetry_service::{
    PolicyDependencies, Service,
    backend::{Backend, SystemClock},
};
use rss_timeseries as ts;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub(super) fn deadline() -> rss_request_context::Deadline {
    rss_request_context::Deadline::from_timeout(&SystemClock, Duration::from_secs(20)).unwrap()
}
pub(super) struct Fixture {
    pub config: crate::telemetry::Config,
    pub owner: crate::owner_storage::OwnerRuntime,
    resources: std::sync::Mutex<Vec<crate::telemetry::Resource>>,
    directory: tempfile::TempDir,
    database: String,
    roles: [String; 2],
}
impl Fixture {
    pub async fn open(c: &Context) -> Result<Self> {
        Self::open_with_limits(c, 128, 64).await
    }
    pub async fn open_with_limits(c: &Context, points: u32, series: u32) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        // The installer rejects symlink ancestors, including the macOS /var temp alias.
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
        for (name, data) in [
            ("password", Uuid::new_v4().to_string().into_bytes()),
            ("cursor", vec![7; 32]),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, data)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let database = format!("t2_telemetry_{}", Uuid::new_v4().simple());
        let roles = [
            format!("o_{}", Uuid::new_v4().simple()),
            format!("r_{}", Uuid::new_v4().simple()),
        ];
        let mut administrator = c.inputs.database("shared", "postgres");
        administrator.name = database.clone();
        let mut runtime = administrator.clone();
        runtime.user = roles[1].clone();
        runtime.password_file = directory.path().join("password");
        let config: crate::telemetry::Config = serde_json::from_value(serde_json::json!({
            "resource_id":Uuid::new_v4(),"backend":{"kind":"postgres","database":runtime,"prepare":crate::telemetry::PrepareCapacity::installation()},"connections":2,"cursor_key_file":directory.path().join("cursor"),
            "maintenance":{"authorization_bytes":65536,"rows":points.min(128),"buckets":series.min(16),"step_seconds":6},
            "ingress":{"requestBytes":1048576,"pendingBatches":64,"batchesPerMinute":120,"bytesPerMinute":8388608},
            "limits":{"max_points":points,"max_series":series,"max_bytes":1048576,"replay_micros":86400000000u64,"cursor_micros":60000000}
        }))?;
        let owner = planning::owner(c, "mdm_telemetry_runtime").await?;
        let fixture = Self {
            config,
            owner,
            resources: Default::default(),
            directory,
            database,
            roles,
        };
        let result = async {
            // Names are fixed prefixes plus UUID hex; no external SQL input.
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "CREATE DATABASE {}",
                fixture.database
            )))
            .execute(&c.operator)
            .await
            .with_context(|| format!("create telemetry database {}", fixture.database))?;
            let today = time::OffsetDateTime::now_utc()
                .unix_timestamp()
                .div_euclid(86400)
                * 86_400_000_000;
            crate::installation::providers::telemetry::prepare(
                crate::installation::providers::telemetry::Request {
                    operation_id: Uuid::new_v4(),
                    directory: fixture.directory.path().join("installation"),
                    configuration: fixture.config.clone(),
                    administrator,
                    owner: fixture.roles[0].clone(),
                    partitions: vec![
                        crate::installation::providers::telemetry::Partition {
                            start_micros: 0,
                            end_micros: 10_000_000,
                        },
                        crate::installation::providers::telemetry::Partition {
                            start_micros: today - 86_400_000_000,
                            end_micros: today + 172_800_000_000,
                        },
                    ],
                    clickhouse: None,
                },
            )
            .await
            .context("install telemetry provider")?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            return with_cleanup(Err(error), fixture.close(c).await);
        }
        Ok(fixture)
    }
    pub async fn provider_observer(&self, c: &Context) -> Result<sqlx::PgConnection> {
        use sqlx::Connection;
        let mut db = c.inputs.database("shared", "postgres");
        db.name = self.database.clone();
        Ok(sqlx::PgConnection::connect_with(&db.options()?).await?)
    }
    pub async fn store(&self) -> Result<Arc<rss_timeseries_postgres::PgStore<SystemClock>>> {
        match self.config.open_backend().await? {
            Backend::Postgres(store) => Ok(store),
            Backend::ClickHouse(_) => unreachable!(),
        }
    }
    pub async fn service(
        &self,
        c: &Context,
        configurations: &[crate::telemetry::Config],
    ) -> Result<Arc<Service>> {
        let objects = Arc::new(rss_mdm_device_service::planning::PlanningObjects);
        let dependencies = PolicyDependencies {
            protection: crate::device_material_support::protection(c)?,
            agent_facts: Arc::new(crate::assembly::agent_facts::AgentFacts),
            read_pool: c.inputs.pool("shared", "mdm_access").await?,
            clock: Arc::new(SystemClock),
            audit_store: self.owner.audit.clone(),
            policies: Arc::new(rss_mdm_policy_service::telemetry::Reader::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                self.owner.runtime.clone(),
                objects.clone(),
            )),
            objects,
        };
        let service = crate::telemetry::open(
            configurations,
            c.execution(),
            self.owner.runtime.clone(),
            dependencies,
            Arc::new(rss_mdm_task_trust::Signing::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                rss_mdm_task_trust::Use::AgentTask,
                crate::device_material_support::protection(c)?,
            )?),
            |resource| self.resources.lock().unwrap().push(resource),
        )
        .await?;
        service
            .admit_default(c.execution(), crate::authority_t2_support::deadline())
            .await?;
        Ok(service)
    }
    pub async fn close(self, c: &Context) -> Result<()> {
        let mut failures = Vec::new();
        for resource in self.resources.into_inner().unwrap() {
            if let Err(error) = resource.0.close(deadline()).await {
                failures.push(format!("close telemetry storage: {error}"));
            }
        }
        self.owner.runtime.close().await;
        if let Err(error) = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.database
        )))
        .execute(&c.operator)
        .await
        {
            failures.push(format!("database {}: {error}", self.database));
        }
        for role in self.roles.iter().rev() {
            if let Err(error) =
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {role}")))
                    .execute(&c.operator)
                    .await
            {
                failures.push(format!("role {role}: {error}"));
            }
        }
        anyhow::ensure!(
            failures.is_empty(),
            "telemetry cleanup: {}",
            failures.join("; ")
        );
        Ok(())
    }
}
/// Retain both failures when the scenario and its cleanup fail together.
pub(super) fn with_cleanup<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("cleanup also failed: {cleanup:#}")))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(cleanup)) => Err(cleanup),
    }
}
/// Explicit fixture operator authority, bound to this tenant's provider data only.
pub(super) struct SeedAuthority(pub rss_request_context::TenantId);
impl ts::Authority for SeedAuthority {
    fn authorize(&self, access: ts::Access<'_>) -> Result<(), ts::Error> {
        let scope = match access {
            ts::Access::Definition(ts::DefinitionMutation::Register { definition, .. }) => {
                &definition.spec().scope
            }
            ts::Access::Write(batch) => batch.stream().scope(),
            ts::Access::Maintain(request) => request.scope(),
            _ => return Err(ts::Error::Unauthorized),
        };
        if scope.tenant() == self.0 {
            Ok(())
        } else {
            Err(ts::Error::Unauthorized)
        }
    }
}

/// The query fixture starts from an explicit domain selection. The installation T2 owns its creation.
pub(super) async fn persist_selection(
    c: &Context,
    config: &crate::telemetry::Config,
) -> Result<()> {
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_telemetry.storage_binding(tenant_id,binding,expected_epoch,resource_id,revision,operation_id) VALUES($1::uuid,$2,$3,$4,1,$5)")
        .bind(c.tenant.to_string()).bind(config.configuration_binding()?.as_slice()).bind(c.execution().epoch().get())
        .bind(config.resource_id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
