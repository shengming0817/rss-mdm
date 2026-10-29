use crate::{Error, Failure};
use rss_mdm_policy_service::application::Application;
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{sync::Arc, time::Duration};

use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub storage: StorageBinding,
    pub publication: crate::publication_config::Config,
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
        storage: &Storage,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        content: Option<Arc<rss_mdm_content_service::Store>>,
        mut acquire: impl FnMut(Resource),
    ) -> std::result::Result<Arc<Flow>, Error> {
        let invalid = || Error::Configuration(crate::ConfigIssue::Flow);
        let runtime = storage.runtime.clone();
        let audit_store = storage.audit_store.clone();
        let key = storage.key.clone();
        let software_resources = Arc::new(
            rss_mdm_resource_postgres::ResourceStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_flow_service::transaction::deadline(),
            )
            .await
            .map_err(|_| invalid())?,
        );
        let policy_store = Arc::new(
            rss_mdm_policy_postgres::PolicyStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_flow_service::transaction::deadline(),
            )
            .await
            .map_err(|_| invalid())?,
        );
        match Application::new(
            audit_store.clone(),
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::PolicyClock(clock.clone())),
            &key,
            Arc::new(rss_mdm_device_service::planning::PlanningObjects),
        )
        .await
        {
            Ok(service) => {
                let groups = Arc::new(
                    rss_mdm_inventory_service::groups::Groups::new(
                        rss_mdm_inventory_service::groups::Dependencies {
                            reconcile_messaging: service.reconcile_messaging.clone(),
                            objects: service.objects.clone(),
                            tenant,
                            groups: Arc::new(
                                rss_mdm_group_postgres::GroupStore::new(
                                    runtime.clone(),
                                    tenant,
                                    rss_mdm_policy_service::transaction::deadline(),
                                )
                                .await
                                .map_err(|_| invalid())?,
                            ),
                            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
                            audit_store: audit_store.clone(),
                            runtime: runtime.clone(),
                            clock: Arc::new(crate::clock::InventoryClock(clock.clone())),
                        },
                    )
                    .await?,
                );
                let mut service = Flow { groups, scope_group_health: Arc::default(),
                    audit_store: audit_store.clone(),
                    cursor_key: key.clone(),
                    runtime: runtime.clone(),
                    planning: Arc::new(service),
                    policy_store,

                    software_resources,
                    publications: Arc::new(
                        rss_mdm_software_service::management::publication::service::PublicationDirectory {
                            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key)),
                            services: Default::default(),
                            tenant,
                            runtime: runtime.clone(),
                            audit_store,
                            clock: Arc::new(crate::clock::FlowClock(clock)),
                        },
                    ),
                    publication_runtime: None,
                };
                let setup = self
                    .open_publications(
                        tenant,
                        Arc::get_mut(&mut service.publications)
                            .expect("unshared startup directory"),
                        content,
                        &mut acquire,
                    )
                    .await;
                match setup {
                    Ok(publication_runtime) => service.publication_runtime = publication_runtime,
                    Err(error) => {
                        return Err(error);
                    }
                }
                Ok(Arc::new(service))
            }
            Err(error) => Err(error.into()),
        }
    }
    pub(crate) async fn open_publications(
        &self,
        tenant: TenantId,
        directory: &mut rss_mdm_software_service::management::publication::service::PublicationDirectory,
        content: Option<Arc<rss_mdm_content_service::Store>>,
        acquire: &mut impl FnMut(Resource),
    ) -> std::result::Result<Option<Arc<PgRuntime>>, Error> {
        if self.publication.sources.is_empty() {
            return Ok(None);
        }
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
        )
        .with_pool_limits(0, crate::background::AUXILIARY_CONNECTIONS);
        let runtime = Arc::new(
            PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Publication,
        });

        let audit_budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let publication_audit = Arc::new(
            directory
                .audit_store
                .on_runtime(runtime.clone(), tenant, &audit_budget.control())
                .await?,
        );
        for source in &self.publication.sources {
            let service = p::PublicationService::connect(
                rss_mdm_software_service::Host {
                    content: content.clone().ok_or_else(invalid)?,
                    runtime: runtime.clone(),
                    audit: publication_audit.clone(),
                    credentials: Arc::new(crate::source_credentials::SourceCredentials::load(
                        tenant,
                        &source.name,
                        &source.credentials,
                    )?),
                },
                tenant,
                source.name.clone(),
                source.target.clone(),
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
            if directory
                .services
                .insert(source.name.clone(), Arc::new(service))
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Some(runtime))
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

pub(crate) struct Flow {
    pub(crate) scope_group_health: Arc<crate::scope_group_changes::Health>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) cursor_key: Vec<u8>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) software_resources: Arc<rss_mdm_resource_postgres::ResourceStore>,
    pub(crate) planning: Arc<Application>,
    pub(crate) policy_store: Arc<rss_mdm_policy_postgres::PolicyStore>,
    pub(crate) groups: Arc<rss_mdm_inventory_service::groups::Groups>,
    pub(crate) publications:
        Arc<rss_mdm_software_service::management::publication::service::PublicationDirectory>,
    publication_runtime: Option<Arc<PgRuntime>>,
}

use rss_mdm_flow_service::transaction::deadline;
use rss_transactional_messaging_postgres::PgTransaction;
pub(crate) async fn admit_storage(
    runtime: &PgRuntime,
    tenant: TenantId,
) -> std::result::Result<(), Error> {
    runtime
        .local_tx(tenant, deadline(), |tx| {
            Box::pin(async move {
                admit_storage_in(tx).await.map_err(|error| {
                    #[cfg(feature = "integration")]
                    eprintln!("host storage admission: {error:?}");
                    let _ = error;
                    sqlx::Error::Protocol("host storage admission".into()).into()
                })
            })
        })
        .await
        .fold(
            |_| Ok(()),
            |_| Err(Error::Unavailable(Failure::FlowAdmission)),
            |_| Err(Error::Unavailable(Failure::FlowAdmission)),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::FlowAdmission)),
        )
}
async fn admit_storage_in(
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
    let tenant = tx.tenant_id();
    tx.with_connection(|c| {
        Box::pin(async move {
            rss_mdm_policy_postgres::verify_authority(c).await?;
            rss_mdm_scope_postgres::verify_authority(c).await?;
            rss_mdm_authorization_service::verify_authority(c).await?;
            rss_mdm_registration_service::verify_authority(c).await?;
            rss_mdm_device_service::verify_authority(c).await?;
            rss_mdm_execution_service::verify_authority(c).await
        })
    })
    .await?;

    // Policy expressions are evaluated under a fixed namespace.
    let original_path: String = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT current_setting('search_path')")
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    tx.with_connection(|c| {
        Box::pin(async move {
            sqlx::query("SELECT set_config('search_path','pg_catalog',true)")
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    tx.with_connection(move |c| {
        Box::pin(async move { rss_mdm_inventory_service::admit_storage_in(c, tenant).await })
    })
    .await?;
    let valid = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, bool>(include_str!("flow/admission.sql"))
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol("host capability admission".into()).into());
    }
    let contracts = [
        ("telemetry", rss_mdm_telemetry_service::ADMISSION_SQL),
        ("software", rss_mdm_software_service::catalog::ADMISSION_SQL),
        (
            "software snapshots",
            rss_mdm_software_service::source_snapshots::ADMISSION_SQL,
        ),
        ("content", rss_mdm_content_service::ADMISSION_SQL),
        (
            "execution handoff",
            include_str!("flow/handoff-admission.sql"),
        ),
        ("policy", rss_mdm_policy_service::ADMISSION_SQL),
        ("assets", rss_mdm_inventory_service::assets::ADMISSION_SQL),
        ("resource_catalog", rss_mdm_resource_service::ADMISSION_SQL),
        ("flow", include_str!("flow/admission.sql")),
        (
            "publication",
            rss_mdm_software_service::management::publication::HTTP_ADMISSION_SQL,
        ),
    ];
    for (owner, admission) in contracts {
        let valid = tx
            .with_connection(move |c| {
                Box::pin(async move { sqlx::query_scalar::<_, bool>(admission).fetch_one(c).await })
            })
            .await?;
        if !valid {
            eprintln!("capability authority rejected: {owner}");
            return Err(sqlx::Error::Protocol("host capability admission".into()).into());
        }
    }
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT set_config('search_path',$1,true)")
                .bind(original_path)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}

pub(crate) struct Storage {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) key: Vec<u8>,
}
impl Config {
    pub(crate) async fn open_storage(
        &self,
        connections: u32,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: TenantId,
        mut acquire: impl FnMut(Resource),
    ) -> Result<Storage, Error> {
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
        )
        .with_pool_limits(0, connections);
        let runtime = Arc::new(
            PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Storage,
        });
        let audit_budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit_store = Arc::new(
            audit_store
                .on_runtime(runtime.clone(), tenant, &audit_budget.control())
                .await?,
        );
        admit_storage(&runtime, tenant).await?;
        let key = crate::cursor_keys::load(&runtime, tenant).await?;
        Ok(Storage {
            runtime,
            audit_store,
            key,
        })
    }
}
