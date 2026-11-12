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
    directory: tempfile::TempDir,
    database: String,
    roles: [String; 2],
}
impl Fixture {
    pub async fn open(c: &Context) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
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
            "backend":{"kind":"postgres","database":runtime},"connections":2,"cursor_key_file":directory.path().join("cursor"),
            "ingress":{"requestBytes":1048576,"pendingBatches":64,"batchesPerMinute":120,"bytesPerMinute":8388608},
            "limits":{"max_points":128,"max_series":64,"max_bytes":1048576,"replay_micros":86400000000u64,"cursor_micros":60000000}
        }))?;
        let owner = planning::owner(c, "mdm_telemetry_runtime").await?;
        let fixture = Self {
            config,
            owner,
            directory,
            database,
            roles,
        };
        // Names are generated solely from fixed prefixes and UUID hex; no external SQL input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {}",
            fixture.database
        )))
        .execute(&c.operator)
        .await?;
        let result = crate::installation::providers::telemetry::prepare(
            crate::installation::providers::telemetry::Request {
                operation_id: Uuid::new_v4(),
                directory: fixture.directory.path().join("installation"),
                tenant: c.tenant.to_string(),
                configuration: fixture.config.clone(),
                administrator,
                owner: fixture.roles[0].clone(),
                partitions: vec![crate::installation::providers::telemetry::Partition {
                    start_micros: 0,
                    end_micros: 10_000_000,
                }],
                clickhouse: None,
            },
        )
        .await
        .context("install telemetry provider");
        if let Err(error) = result {
            fixture.close(c).await?;
            return Err(error);
        }
        Ok(fixture)
    }
    pub async fn store(
        &self,
        c: &Context,
    ) -> Result<rss_timeseries_postgres::PgStore<SystemClock>> {
        match self.config.open_backend(c.tenant).await? {
            Backend::Postgres(store) => Ok(store),
            Backend::ClickHouse(_) => unreachable!(),
        }
    }
    pub async fn service(&self, c: &Context) -> Result<Arc<Service>> {
        let objects = Arc::new(rss_mdm_device_service::planning::PlanningObjects);
        let dependencies = PolicyDependencies {
            agent_facts: Arc::new(crate::assembly::agent_facts::AgentFacts),
            read_pool: c.inputs.pool("shared", "mdm_access").await?,
            clock: Arc::new(SystemClock),
            audit_store: self.owner.audit.clone(),
            policies: Arc::new(rss_mdm_policy_service::telemetry::Reader::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                self.owner.runtime.clone(),
                c.tenant,
                objects.clone(),
            )),
            objects,
        };
        Ok(Arc::new(Service::new(
            c.tenant,
            self.owner.runtime.clone(),
            dependencies,
            Backend::Postgres(self.store(c).await?),
            Arc::new(rss_mdm_task_trust::Signing::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                rss_mdm_task_trust::Use::AgentTask,
                c.tenant,
                None,
            )?),
            self.config.ingress.clone(),
            rss_mdm_telemetry_service::StorageBudget {
                points: self.config.limits.max_points,
                series: self.config.limits.max_series,
                bytes: self.config.limits.max_bytes,
            },
        )?))
    }
    pub async fn close(self, c: &Context) -> Result<()> {
        self.owner.runtime.close().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.database
        )))
        .execute(&c.operator)
        .await?;
        for role in self.roles.iter().rev() {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {role}")))
                .execute(&c.operator)
                .await?;
        }
        Ok(())
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
