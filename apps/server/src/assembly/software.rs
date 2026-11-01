//! Software owner assembly; participants bind to the caller's runtime.
use rss_mdm_software_service::deployment as owner;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgOutboxStore, PgRuntime};
use std::{sync::Arc, time::Duration};
#[derive(Clone)]
pub(crate) struct Assembly {
    pub service: Arc<owner::SoftwareService>,
    pub transactions: Arc<owner::Transactions>,
    pub queries: Arc<owner::queries::Queries>,
    pub materials: Arc<owner::Materials>,
    pub authority: Arc<owner::managed_registration::AuthorityReader>,
}
#[expect(clippy::too_many_arguments, reason = "explicit host capabilities")]
pub(crate) async fn assemble(
    config: &crate::config::Config,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    source: Arc<super::software_sources::Source>,
    inventory: Arc<super::software_sources::Inventory>,
    lifecycle: Arc<super::software_sources::Lifecycle>,
    software: Arc<rss_mdm_software_service::preparation::Preparation>,
    authority: Arc<owner::managed_registration::AuthorityReader>,
    registration: Arc<rss_mdm_registration_service::installation::Materials>,
    channels: Arc<crate::channel_status::Channels>,
    signed: bool,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    read_pool: sqlx::PgPool,
    reconcile: rss_reconcile_postgres::PgStore,
    budget: Arc<tokio::sync::Semaphore>,
) -> Result<Assembly, crate::Error> {
    let input_materials = Arc::new(owner::InputMaterials {
        software_distribution: config.software_distribution,
        product_origin: config.product_origin.clone(),
        protection: protection.clone(),
        software,
        bootstrap_configured: registration.endpoints.is_some(),
        signing_enabled: signed,
        agent_installation: channels,
    });
    let inputs = Arc::new(owner::Inputs::bind(
        runtime.clone(),
        tenant,
        input_materials.clone(),
    ));
    let agent = Arc::new(super::software_agent_facts::AgentFacts);
    let windows = Arc::new(super::software_windows_facts::WindowsResults(
        rss_mdm_windows_channel::results::Results {
            protection: protection.clone(),
        },
    ));
    let apple = Arc::new(super::software_apple_facts::AppleFacts(
        rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        },
    ));
    let materials = Arc::new(owner::Materials {
        registration,
        capacity: Arc::new(super::capacity::Capacity),
        inputs: input_materials,
        source: source.clone(),
        inventory: inventory.clone(),
        lifecycle: lifecycle.clone(),
        protection: protection.clone(),
        agent_store: agent.clone(),
        windows_results: windows.clone(),
        apple_profiles: apple.clone(),
        apple_results: apple.clone(),
        instance: config.identity.instance_id.clone(),
        command_clock: rss_device_command_postgres::CommandClock::Postgres,
    });
    let queries = Arc::new(owner::queries::Queries::new(
        Arc::new(crate::lifecycle::RuntimeTimer),
        owner::queries::Dependencies {
            read_pool,
            source,
            inventory,
            lifecycle,
            protection,
            agent_store: agent,
            windows_results: windows,
            apple_results: apple,
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                rss_mdm_install_support::StorageProfile::Mdm,
                runtime.clone(),
                tenant,
            ),
            runtime: runtime.clone(),
            tenant,
            inputs,
            signed,
            content_available: config.content.is_some(),
        },
    ));
    let transactions = Arc::new(
        owner::Transactions::bind(runtime.clone(), tenant, audit, materials.clone())
            .await
            .map_err(super::owner_errors::software)?,
    );
    let delivery = rss_transactional_messaging::policy::DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(6),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .map_err(|_| crate::Error::Malformed)?;
    let outbox = Arc::new(
        PgOutboxStore::new(runtime, owner::messaging_domain(), delivery)
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandStorage))?,
    );
    let service = Arc::new(owner::SoftwareService::new(
        transactions.clone(),
        sessions,
        outbox,
        reconcile,
        budget,
        config.background.device_concurrency,
    ));
    service
        .initialize_recovery()
        .await
        .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
    Ok(Assembly {
        service,
        transactions,
        queries,
        materials,
        authority,
    })
}

pub(crate) struct Downloads {
    pub software: Arc<owner::SoftwareService>,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
}
impl rss_mdm_management_http::software_content::Packages for Downloads {
    fn download<'a>(
        &'a self,
        id: uuid::Uuid,
        token: &'a str,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> std::pin::Pin<
        Box<
            dyn Future<
                    Output = Result<
                        rss_mdm_content_service::Verified,
                        rss_mdm_management_http::Error,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let store = self
                .content
                .as_ref()
                .ok_or(rss_mdm_management_http::Error::Unsupported)?;
            let artifact = self
                .software
                .software_installation_artifact(id, token, audit)
                .await
                .map_err(super::owner_errors::software_http)?;
            let verified = store.verify(&artifact).await?;
            self.software
                .revalidate_software_download(id, token, &artifact, audit)
                .await
                .map_err(super::owner_errors::software_http)?;
            Ok(verified)
        })
    }
}

use crate::{Error, Failure, owner_storage::OwnerRuntime};
pub(crate) async fn catalog(
    owner: &OwnerRuntime,
    tenant: TenantId,
    key: &[u8],
    clock: Arc<dyn crate::clock::Clock>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
) -> Result<
    Arc<
        rss_mdm_software_service::management::catalog::Access<
            rss_mdm_content_service::software::SoftwareContent,
        >,
    >,
    Error,
> {
    owner
        .runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::catalog::ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "owner storage admission rejected".into(),
                            ));
                        }
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::agent_packages::ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "Agent package storage admission rejected".into(),
                            ));
                        }
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::source_snapshots::ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "Software source snapshot admission rejected".into(),
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
    let resources = Arc::new(
        rss_mdm_resource_postgres::ResourceStore::new(
            owner.runtime.clone(),
            tenant,
            rss_mdm_resource_service::transaction::deadline(),
        )
        .await
        .map_err(|_| {
            Error::Resource(rss_mdm_resource_service::Error::Unavailable(
                rss_mdm_resource_service::Failure::ResourceAdmission,
            ))
        })?,
    );

    Ok(Arc::new(
        rss_mdm_software_service::management::catalog::Access {
            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                key,
            )),
            resources: resources.clone(),
            resource_writer: std::sync::Arc::new(crate::assembly::resource::SoftwareResources(
                rss_mdm_resource_service::software::SoftwareWriter::new(resources.clone()),
            )),
            clock: Arc::new(crate::clock::ContentClock(clock.clone())),
            runtime: owner.runtime.clone(),
            audit: owner.audit.clone(),
            tenant,
            catalog: rss_mdm_software_service::catalog::Catalog::new(
                owner.runtime.clone(),
                tenant,
                owner.audit.clone(),
            ),
            content: content.as_ref().map(|store| {
                Arc::new(rss_mdm_content_service::software::SoftwareContent::new(
                    store.clone(),
                    Arc::new(crate::clock::ContentClock(clock.clone())),
                ))
            }),
            imports: rss_mdm_software_service::management::catalog::ImportConfig {
                sources: content
                    .as_ref()
                    .map(|s| s.config.imports.clone())
                    .unwrap_or_default(),
                transfer_seconds: content.as_ref().map_or(0, |s| s.config.transfer_seconds),
            },
        },
    ))
}
