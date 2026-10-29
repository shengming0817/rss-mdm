//! Software publication assembly; only the Software owner interprets publication work.
use crate::owner_storage::{OwnerRuntime, Resource, StorageBinding};
use crate::{Error, Failure};
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{sync::Arc, time::Duration};
const SOURCE_STARTUP_SECONDS: u64 = 6;
pub(crate) fn startup_budget(config: &crate::publication_config::Config) -> Duration {
    Duration::from_secs(
        45 + if config.sources.is_empty() {
            0
        } else {
            5 + SOURCE_STARTUP_SECONDS * config.sources.len() as u64
        },
    )
}
pub(crate) async fn open(
    config: &crate::publication_config::Config,
    binding: &StorageBinding,
    owner: &OwnerRuntime,
    tenant: TenantId,
    key: &[u8],
    clock: Arc<dyn crate::clock::Clock>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
    mut acquire: impl FnMut(Resource),
) -> Result<
    Arc<rss_mdm_software_service::management::publication::service::PublicationDirectory>,
    Error,
> {
    owner
        .runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::management::publication::HTTP_ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "owner storage admission rejected".into(),
                            ));
                        }
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
        .fold(
            Ok,
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Database)),
        )?;
    let mut directory =
        rss_mdm_software_service::management::publication::service::PublicationDirectory {
            cursor: rss_mdm_query::cursor::CursorCodec::new(key).map_err(|_| Error::Malformed)?,
            services: Default::default(),
            tenant,
            runtime: owner.runtime.clone(),
            audit_store: owner.audit.clone(),
            clock: Arc::new(crate::clock::ContentClock(clock)),
        };
    open_sources(
        config,
        binding,
        tenant,
        &mut directory,
        content,
        &mut acquire,
    )
    .await?;
    Ok(Arc::new(directory))
}
pub(crate) async fn open_sources(
    config: &crate::publication_config::Config,
    binding: &crate::owner_storage::StorageBinding,
    tenant: TenantId,
    directory: &mut rss_mdm_software_service::management::publication::service::PublicationDirectory,
    content: Option<Arc<rss_mdm_content_service::Store>>,
    acquire: &mut impl FnMut(Resource),
) -> std::result::Result<Option<Arc<PgRuntime>>, Error> {
    if config.sources.is_empty() {
        return Ok(None);
    }
    use rss_mdm_software_service::publication as p;
    let invalid = || Error::Configuration(crate::ConfigIssue::Publication);
    let db = &config.database;
    let binding = ExecutionBinding::new(
        StorageIdentity::new(binding.target, binding.lineage).map_err(|_| invalid())?,
        vec![(tenant, Epoch::new(binding.epoch).map_err(|_| invalid())?)],
    )
    .map_err(|_| invalid())?;
    let pg = PgConfig::new(
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
        PgRuntime::connect_producer(pg, crate::lifecycle::RuntimeTimer, binding)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?,
    );
    acquire(Resource::new(runtime.clone(), "software-driver-postgres"));

    let audit_budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let publication_audit = Arc::new(
        directory
            .audit_store
            .on_runtime(runtime.clone(), tenant, &audit_budget.control())
            .await?,
    );
    for source in &config.sources {
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
        .map_err(|_| Error::Unavailable(Failure::Database))?;
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
