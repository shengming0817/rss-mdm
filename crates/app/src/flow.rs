use crate::planning::Planning;
use crate::{Error, Failure};
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{sync::Arc, time::Duration};

use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub storage: StorageBinding,
    pub publication: crate::software_publication::http::Config,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageBinding {
    pub database: crate::config::Database,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
}
pub(crate) const SOURCE_STARTUP_SECONDS: u64 = 6;
impl Config {
    pub(crate) fn startup_budget(&self) -> Duration {
        Duration::from_secs(
            45 + if self.publication.sources.is_empty() {
                0
            } else {
                5 + SOURCE_STARTUP_SECONDS * self.publication.sources.len() as u64
            },
        )
    }

    pub(crate) fn validate(
        &self,
        database: &crate::config::Database,
    ) -> std::result::Result<(), Error> {
        if self.storage.database.user != "mdm_flow_runtime"
            || self.storage.database.host != database.host
            || self.storage.database.port != database.port
            || self.storage.database.name != database.name
        {
            return Err(Error::Configuration(crate::ConfigIssue::Flow));
        }
        if self.publication.database.user != "mdm_software_driver"
            || self.publication.database.host != database.host
            || self.publication.database.port != database.port
            || self.publication.database.name != database.name
            || self.publication.sources.len() > 16
        {
            return Err(Error::Configuration(crate::ConfigIssue::Publication));
        }
        Ok(())
    }
    pub(crate) async fn open(
        &self,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        mut acquire: impl FnMut(Resource),
    ) -> std::result::Result<Arc<Flow>, Error> {
        let invalid = || Error::Configuration(crate::ConfigIssue::Flow);
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.storage.target, self.storage.lineage)
                .map_err(|_| invalid())?,
            vec![(
                tenant,
                Epoch::new(self.storage.epoch).map_err(|_| invalid())?,
            )],
        )
        .map_err(|_| invalid())?;
        let database = &self.storage.database;
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
                .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Storage,
        });
        if let Err(error) =
            crate::database::admit_audit_runtime(&runtime, &audit_store, tenant).await
        {
            runtime.close().await;
            return Err(error);
        }
        storage::admit(&runtime, tenant).await?;
        let key = storage::cursor_key(&runtime, tenant).await?;
        let catalog = catalog(audit_store.clone(), runtime.clone(), tenant, clock.clone()).await?;
        match Planning::new(
            audit_store.clone(),
            runtime.clone(),
            tenant,
            clock.clone(),
            catalog.clone(),
            &key,
        )
        .await
        {
            Ok(service) => {
                let assets = Arc::new(crate::assets::AssetService::new(
                    audit_store.clone(),
                    runtime.clone(),
                    tenant,
                    clock.clone(),
                    &key,
                ));
                let mut service = Flow {
                    runtime: runtime.clone(),
                    planning: Arc::new(service),
                    catalog,
                    assets,
                    publications: Arc::new(
                        crate::software_publication::http::PublicationDirectory {
                            services: Default::default(),
                            tenant,
                            runtime: runtime.clone(),
                            audit_store,
                            clock,
                        },
                    ),
                    publication_runtime: None,
                };
                if !self.publication.sources.is_empty() {
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
        planning: &mut Flow,
        acquire: &mut impl FnMut(Resource),
    ) -> std::result::Result<(), Error> {
        use rss_mdm_software_service::publication as p;
        let invalid = || Error::Configuration(crate::ConfigIssue::Publication);
        let db = &self.publication.database;
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.storage.target, self.storage.lineage)
                .map_err(|_| invalid())?,
            vec![(
                tenant,
                Epoch::new(self.storage.epoch).map_err(|_| invalid())?,
            )],
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
                .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Publication,
        });
        planning.publication_runtime = Some(runtime.clone());
        crate::database::admit_audit_runtime(&runtime, &planning.publications.audit_store, tenant)
            .await?;
        for source in &self.publication.sources {
            let artifacts = p::ArtifactReader::new(
                source.artifacts.clone(),
                source.max_artifact_bytes,
                Duration::from_secs(5),
            )
            .map_err(|_| invalid())?;
            let service = p::PublicationService::connect(
                rss_mdm_software_service::Host {
                    runtime: runtime.clone(),
                    audit: Arc::new(crate::software_publication::host::Audit(
                        planning.publications.audit_store.clone(),
                    )),
                    credentials: Arc::new(
                        crate::software_publication::host::SourceCredentials::load(
                            tenant,
                            &source.name,
                            &source.credentials,
                        )?,
                    ),
                },
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
            .map_err(|_| Error::Unavailable(Failure::FlowSource))?;
            if Arc::get_mut(&mut planning.publications)
                .expect("unshared startup directory")
                .services
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
    Storage,
    Publication,
}
pub(crate) struct Resource {
    runtime: Arc<PgRuntime>,
    role: Role,
}
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        match self.role {
            Role::Storage => "flow-runtime-postgres",
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
            serde_json::from_str(include_str!("../../../fixtures/mdm-config.example.json"))
                .unwrap();
        let source = serde_json::json!({"name":"fixture","credentials":{},"rings":{"test":{"Brew":{"tap":"a/test","repository":"/tmp/test"}},"pilot":{"Brew":{"tap":"a/pilot","repository":"/tmp/pilot"}},"production":{"Brew":{"tap":"a/production","repository":"/tmp/production"}}},"artifacts":[],"max_artifact_bytes":1});
        config["flow"]["publication"]["sources"] =
            serde_json::json!([source.clone(), source.clone(), source]);
        let c: crate::config::Config = serde_json::from_value(config).unwrap();
        let result = tokio::time::timeout(c.flow.startup_budget(), async {
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
            tokio::time::timeout(c.flow.startup_budget(), std::future::pending::<()>())
                .await
                .is_err()
        );
    }
}

pub(crate) struct Flow {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) catalog: Arc<crate::resource_catalog::ResourceCatalog>,
    pub(crate) planning: Arc<Planning>,
    pub(crate) assets: Arc<crate::assets::AssetService>,
    pub(crate) publications: Arc<crate::software_publication::http::PublicationDirectory>,
    publication_runtime: Option<Arc<PgRuntime>>,
}

pub(crate) async fn catalog(
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
) -> std::result::Result<Arc<crate::resource_catalog::ResourceCatalog>, Error> {
    Ok(Arc::new(
        crate::resource_catalog::ResourceCatalog::new(
            audit,
            runtime,
            tenant,
            clock,
            Arc::new(crate::planning::configuration::FirewallAuthor),
            Arc::new(ResourceReferences),
        )
        .await?,
    ))
}
struct ResourceReferences;
impl crate::resource_catalog::References for ResourceReferences {
    fn count_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::transaction::Result<u64>> + Send + 'a>,
    > {
        Box::pin(async move {
            let plans = crate::planning::references::count_in(tx, resource, version).await?;
            let publications =
                rss_mdm_software_service::publication::references::count_in(tx, resource, version)
                    .await?;
            let tenant = tx.tenant_id().to_string();
            let resource = resource.to_owned();
            let version = version.to_owned();
            let approvals:i64=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT count(*) FROM mdm_software.approvals WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3").bind(tenant).bind(resource).bind(version).fetch_one(c).await})).await?;
            plans
                .checked_add(approvals as u64)
                .and_then(|n| n.checked_add(publications))
                .ok_or_else(|| Error::Unavailable(Failure::FlowStorage).into())
        })
    }
}

pub(crate) mod execution;

pub(crate) mod actions;

pub(crate) mod storage;

pub(crate) mod actions_http;
