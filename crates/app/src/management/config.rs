use super::*;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub database: crate::config::Database,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
    pub publication_database: crate::config::Database,
    pub sources: Vec<super::publications::SourceConfig>,
}
pub(crate) const SOURCE_STARTUP_SECONDS: u64 = 6;
impl Config {
    pub(crate) fn startup_budget(&self) -> Duration {
        Duration::from_secs(
            35 + if self.sources.is_empty() {
                0
            } else {
                5 + SOURCE_STARTUP_SECONDS * self.sources.len() as u64
            },
        )
    }

    pub(crate) fn validate(
        &self,
        database: &crate::config::Database,
    ) -> std::result::Result<(), Error> {
        if self.database.user != "mdm_management_runtime"
            || self.database.host != database.host
            || self.database.port != database.port
            || self.database.name != database.name
        {
            return Err(Error::Configuration(crate::ConfigIssue::Management));
        }
        if self.publication_database.user != "mdm_software_driver"
            || self.publication_database.host != database.host
            || self.publication_database.port != database.port
            || self.publication_database.name != database.name
            || self.sources.len() > 16
        {
            return Err(Error::Configuration(crate::ConfigIssue::Management));
        }
        Ok(())
    }
    pub(crate) async fn open(
        &self,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        mut acquire: impl FnMut(Resource),
    ) -> std::result::Result<Arc<Management>, Error> {
        let invalid = || Error::Configuration(crate::ConfigIssue::Management);
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.target, self.lineage).map_err(|_| invalid())?,
            vec![(tenant, Epoch::new(self.epoch).map_err(|_| invalid())?)],
        )
        .map_err(|_| invalid())?;
        let database = &self.database;
        let config = PgConfig::new(
            &database.host,
            database.port,
            &database.name,
            &database.user,
            PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
            PgPrivateCa::from_pem(
                crate::config::read(&database.ca_file, 1024 * 1024, false)?.to_vec(),
            )
            .map_err(|_| invalid())?,
        );
        let runtime = Arc::new(
            PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::ManagementConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Management,
        });
        match Management::new(runtime.clone(), tenant, clock).await {
            Ok(mut service) => {
                if !self.sources.is_empty() {
                    let setup = self
                        .open_publications(tenant, &mut service, &mut acquire)
                        .await;
                    if let Err(error) = setup {
                        if let Some(p) = &service.publication_runtime {
                            p.close().await;
                        }
                        runtime.close().await;
                        return Err(error);
                    }
                }
                Ok(Arc::new(service))
            }
            Err(error) => {
                runtime.close().await;
                Err(error)
            }
        }
    }
    async fn open_publications(
        &self,
        tenant: TenantId,
        management: &mut Management,
        acquire: &mut impl FnMut(Resource),
    ) -> std::result::Result<(), Error> {
        use crate::software_publication as p;
        let invalid = || Error::Configuration(crate::ConfigIssue::Management);
        let db = &self.publication_database;
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.target, self.lineage).map_err(|_| invalid())?,
            vec![(tenant, Epoch::new(self.epoch).map_err(|_| invalid())?)],
        )
        .map_err(|_| invalid())?;
        let config = PgConfig::new(
            &db.host,
            db.port,
            &db.name,
            &db.user,
            PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
            PgPrivateCa::from_pem(crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec())
                .map_err(|_| invalid())?,
        );
        let runtime = Arc::new(
            PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::ManagementConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Publication,
        });
        management.publication_runtime = Some(runtime.clone());
        for source in &self.sources {
            let artifacts = p::ArtifactReader::new(
                source.artifacts.clone(),
                source.max_artifact_bytes,
                Duration::from_secs(5),
            )
            .map_err(|_| invalid())?;
            let service = p::PublicationService::connect(
                runtime.clone(),
                tenant,
                source.name.clone(),
                source.rings.clone(),
                artifacts,
                p::ServiceIdentity {
                    backend: rss_mdm_software_release::ActorId::new(tenant, "mdm-software-backend")
                        .map_err(|_| invalid())?,
                },
                Deadline::from_timeout(
                    &crate::lifecycle::RuntimeTimer,
                    Duration::from_secs(SOURCE_STARTUP_SECONDS),
                )
                .map_err(|_| invalid())?,
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::ManagementSource))?;
            if management
                .publications
                .insert(source.name.clone(), service)
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Role {
    Management,
    Publication,
}
pub(crate) struct Resource {
    runtime: Arc<PgRuntime>,
    role: Role,
}
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        match self.role {
            Role::Management => "management-runtime-postgres",
            Role::Publication => "software-driver-postgres",
        }
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.runtime.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn slow_sources_fit_declared_startup_budget_and_remain_bounded() {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))
                .unwrap();
        let source = serde_json::json!({"name":"fixture","rings":{"test":{"Brew":{"tap":"a/test","repository":"/tmp/test"}},"pilot":{"Brew":{"tap":"a/pilot","repository":"/tmp/pilot"}},"production":{"Brew":{"tap":"a/production","repository":"/tmp/production"}}},"artifacts":[],"max_artifact_bytes":1});
        config["management"]["sources"] =
            serde_json::json!([source.clone(), source.clone(), source]);
        let c: crate::config::Config = serde_json::from_value(config).unwrap();
        let result = tokio::time::timeout(c.management.startup_budget(), async {
            tokio::time::sleep(Duration::from_secs(7)).await;
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "individually bounded sources exhausted the host budget"
        );
        assert!(
            tokio::time::timeout(c.management.startup_budget(), std::future::pending::<()>())
                .await
                .is_err()
        );
    }
}
