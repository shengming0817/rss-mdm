//! Product route and service assembly.
pub(crate) mod agent_facts;
pub(crate) mod agent_tasks;
pub(crate) mod apple_business;
mod apple_facts;
mod capacity;
pub(crate) mod device_access;
pub(crate) mod self_service;
mod task_ownership;
pub(crate) mod task_relay;
pub(crate) mod windows_business;
mod windows_results;
use crate::clock::Clock;
use crate::{ConfigIssue, Database};
use crate::{
    Error, authorization::identity_management::IdentityManagementPolicy,
    enrollment::credentials::Credentials, identity::Identity,
};
use std::sync::Arc;

pub(crate) mod collection;
pub(crate) mod content;
pub(crate) mod device_control;
pub(crate) mod host_storage;
pub(crate) mod http;
pub(crate) mod inventory;
mod native_ownership;
pub(crate) mod policy;
mod policy_ports;
pub(crate) mod publication;
pub(crate) mod resource;
pub(crate) mod script;
pub(crate) mod software;
pub(crate) mod task_trust;
pub(crate) mod webhooks;
pub(crate) struct Assembly {
    pub(crate) da: Option<Arc<device_access::Assembly>>,
    pub(crate) script_work: Arc<rss_mdm_script_service::worker::Worker>,
    pub(crate) collection_work:
        Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    pub(crate) operation_reads: Arc<operation_reads::Operations>,
    pub(crate) software: software::Assembly,
    pub(crate) registration: registration::Assembly,
    pub(crate) configuration_preview: Arc<rss_mdm_policy_service::configuration::preview::Previews>,
    pub(crate) configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
    pub(crate) events: Arc<rss_mdm_policy_service::events::Events>,
    pub(crate) resources: Arc<rss_mdm_resource_service::ResourceCatalog>,
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub(crate) runtime_observation: crate::installation::host::Observation,
    pub(crate) apple_material_roots: Arc<Vec<Vec<u8>>>,
    pub(crate) webhooks: Arc<rss_mdm_webhook_service::management::Service>,
    pub(crate) pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub(crate) agent_enrollment: Option<Arc<rss_mdm_registration_service::agent::Service>>,
    pub(crate) agent_pki: Option<Arc<crate::agent_pki::AgentPki>>,
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) associations: Arc<rss_mdm_device_service::Associations>,
    pub(crate) content_writer: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: Arc<rss_mdm_device_service::control::Service>,
    pub(crate) access_execution: access_execution::Assembly,
    pub(crate) credential_execution: Option<credential_execution::Assembly>,
    pub(crate) agent_tasks: Arc<agent_tasks::AgentTasks>,
    pub(crate) windows_delivery: Arc<rss_mdm_windows_channel::management::exchange::Delivery>,
    pub(crate) apple_delivery: Arc<rss_mdm_apple_channel::delivery::Delivery>,
    pub(crate) agent_delivery: Arc<rss_mdm_agent_channel::delivery::Delivery>,
    pub(crate) task_trust: Arc<rss_mdm_task_trust::Service>,
    pub(crate) task_reads: Arc<task_reads::Reads>,
    pub(crate) queries: Arc<rss_mdm_device_service::control::queries::Queries>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) groups: Arc<rss_mdm_group_service::Groups>,
    pub(crate) policy_application: Arc<rss_mdm_policy_service::application::Application>,
    pub(crate) policies: Arc<rss_mdm_policy_service::management::Policies>,
    pub(crate) publications:
        Arc<rss_mdm_software_service::management::publication::service::PublicationDirectory>,
    pub(crate) software_catalog: Arc<
        rss_mdm_software_service::management::catalog::Access<
            rss_mdm_content_service::software::SoftwareContent,
        >,
    >,
    pub(crate) content_access: Option<Arc<rss_mdm_content_service::service::Access>>,
    pub(crate) cursor_key: Vec<u8>,
    pub(crate) scope_group_health: Arc<crate::scope_group_changes::Health>,

    pub(crate) scopes: Arc<rss_mdm_scope_service::Scopes>,
    pub(crate) assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub(crate) compliance: Arc<rss_mdm_compliance_service::Compliance>,
    pub(crate) identity: Arc<Identity>,
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) identity_management: Arc<IdentityManagementPolicy>,
    pub(crate) inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) apple: Option<Arc<crate::apple::Apple>>,
    pub(crate) platform_configuration:
        Option<rss_mdm_device_access::deployment::PlatformConfiguration>,
    pub(crate) windows: Option<Arc<crate::windows::Windows>>,
    pub(crate) access: Arc<Database>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

pub(crate) struct AssemblyDependencies {
    pub(crate) da: Option<Arc<device_access::Assembly>>,
    pub(crate) script_work: Arc<rss_mdm_script_service::worker::Worker>,
    pub(crate) collection_work:
        Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    pub(crate) telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) associations: Arc<rss_mdm_device_service::Associations>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) access_execution: access_execution::Assembly,
    pub(crate) credential_execution: Option<credential_execution::Assembly>,
    pub(crate) credential_receipts:
        Option<Arc<rss_mdm_recovery_credentials::native_receipts::NativeReceipts>>,
    pub(crate) software: software::Assembly,
    pub(crate) registration: registration::Assembly,
    pub(crate) read_pool: sqlx::PgPool,
    pub(crate) configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
    pub(crate) signing: Arc<rss_mdm_task_trust::Signing>,
    pub(crate) task_trust: Arc<rss_mdm_task_trust::Service>,
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub(crate) bootstrap:
        Option<Arc<rss_mdm_registration_service::agent::bootstrap::Configuration>>,
    pub(crate) control: Arc<rss_mdm_device_service::control::Service>,
    pub(crate) self_service: Arc<self_service::Requests>,
    pub(crate) scripts: Arc<rss_mdm_script_service::ScriptService>,
    pub(crate) collections:
        Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
    pub(crate) task_reads: Arc<task_reads::Reads>,
    pub(crate) queries: Arc<rss_mdm_device_service::control::queries::Queries>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) protocol_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) monotonic: Arc<dyn rss_observation::Clock>,
    pub(crate) access: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) groups: Arc<rss_mdm_group_service::Groups>,
    pub(crate) policy_application: Arc<rss_mdm_policy_service::application::Application>,
    pub(crate) policies: Arc<rss_mdm_policy_service::management::Policies>,
    pub(crate) publications:
        Arc<rss_mdm_software_service::management::publication::service::PublicationDirectory>,
    pub(crate) software_catalog: Arc<
        rss_mdm_software_service::management::catalog::Access<
            rss_mdm_content_service::software::SoftwareContent,
        >,
    >,
    pub(crate) content_access: Option<Arc<rss_mdm_content_service::service::Access>>,
    pub(crate) cursor_key: Vec<u8>,
    pub(crate) scope_group_health: Arc<crate::scope_group_changes::Health>,

    pub(crate) scopes: Arc<rss_mdm_scope_service::Scopes>,
    pub(crate) assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub(crate) compliance: Arc<rss_mdm_compliance_service::Compliance>,
    pub(crate) identity: Identity,
    pub(crate) resources: Arc<rss_mdm_resource_service::ResourceCatalog>,
    pub(crate) events: Arc<rss_mdm_policy_service::events::Events>,
}
pub(crate) async fn from_compiled(
    compiled: crate::config::Compiled,
    dependencies: AssemblyDependencies,
) -> Result<crate::native::Routers, Error> {
    let crate::config::Compiled {
        config,
        identity_management,
    } = compiled;
    let AssemblyDependencies {
        da,
        script_work,
        collection_work,
        telemetry,
        certificate_archive,
        timeline,
        associations,
        audit_store,
        access_execution,
        credential_execution,
        credential_receipts,
        software,
        registration,
        read_pool,
        configuration,
        signing,
        task_trust,
        channels,
        providers,
        bootstrap,
        control: execution,
        self_service,
        scripts,
        collections,
        task_reads,
        queries,
        protection,
        content: content_writer,
        protocol_runtime,
        clock,
        monotonic,
        access,
        runtime,
        groups,
        policy_application,
        policies,
        publications,
        software_catalog,
        content_access,
        cursor_key,
        scope_group_health,
        resources,
        events,
        scopes,
        assets,
        compliance,
        identity,
    } = dependencies;
    let configuration_preview =
        Arc::new(rss_mdm_policy_service::configuration::preview::Previews {
            publications: Arc::new(
                rss_mdm_policy_service::configuration::publication::Publications {
                    runtime: policy_application.runtime.clone(),
                    tenant: policy_application.tenant,
                    content: content_writer.clone(),
                    protection: protection.clone(),
                },
            ),
            source: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
            )),
            read_pool,
            clock: Arc::new(crate::lifecycle::RuntimeTimer),
        });
    let devices = Arc::new(crate::device::DeviceService::new(
        access.registration(),
        config.identity.tenant_id.clone(),
        audit_store.clone(),
    ));
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration(ConfigIssue::ProductOrigin))?
        .to_owned();
    use crate::channel_status::{ChannelName, ChannelState, Reason};
    let windows_push =
        match load_windows_push(&config, identity.tenant, &protection, monotonic.clone()).await {
            Ok(push) => {
                if push.is_some() {
                    channels.set(ChannelName::WindowsPush, ChannelState::Ready, None)?;
                }
                push
            }
            Err(Error::Windows(rss_mdm_windows_channel::Error::Conflict)) => {
                channels.set(
                    ChannelName::WindowsPush,
                    ChannelState::Waiting,
                    Some(Reason::MaterialNotSelected),
                )?;
                None
            }
            Err(error) => return Err(error),
        };
    let mut windows = channels
        .material(
            ChannelName::Windows,
            config
                .native_protocols
                .windows
                .map(|config| {
                    let entra = config
                        .entra
                        .clone()
                        .map(|binding| {
                            let verifier =
                                rss_identity_oidc::entra::HttpEntra::new().map_err(|_| {
                                    Error::Configuration(ConfigIssue::IdentityConfiguration)
                                })?;
                            let provider = rss_identity_core::federation::ProviderId::parse(
                                &binding.provider_id.to_string(),
                            )
                            .map_err(|_| {
                                Error::Configuration(ConfigIssue::IdentityConfiguration)
                            })?;
                            let authority = rss_identity_postgres::EntraAuthority::new(
                                identity.authority.clone(),
                                Arc::new(verifier),
                                identity.tenant,
                                provider,
                                binding.token.clone(),
                            )
                            .map_err(crate::identity::failure)?;
                            rss_mdm_windows_channel::entra::Entra::new(
                                authority,
                                identity.tenant,
                                binding,
                            )
                            .map(Arc::new)
                            .map_err(Error::from)
                        })
                        .transpose()?;
                    let mut windows = crate::windows::Windows::load(
                        config,
                        clock.unix_seconds()?,
                        providers.clone(),
                        windows_push,
                    )?;
                    Arc::get_mut(&mut windows.channel)
                        .ok_or(Error::Conflict)?
                        .entra = entra;
                    Ok::<_, Error>(Arc::new(windows))
                })
                .transpose(),
        )?
        .flatten();
    let roots = channels.material(
        ChannelName::Apple,
        config
            .apple_material_roots
            .iter()
            .map(|path| crate::config::read(path, 128 * 1024, false).map(|bytes| bytes.to_vec()))
            .collect::<Result<Vec<_>, _>>(),
    )?;
    let roots_available = roots.is_some();
    let apple_material_roots = Arc::new(roots.unwrap_or_default());
    let mut apple = if let Some(config) = config.native_protocols.apple {
        if !roots_available {
            None
        } else {
            match rss_mdm_apple_channel::runtime_materials::runtime::load(
                &access.apple_store(),
                identity.tenant,
                &protection,
                &apple_material_roots,
                &config.materials,
                clock.unix_seconds()?,
            )
            .await
            {
                Ok(materials) => channels
                    .material(
                        ChannelName::Apple,
                        crate::apple::Apple::load(
                            protection.clone(),
                            config,
                            materials,
                            clock.unix_seconds()?,
                            providers.clone(),
                            credential_receipts.clone(),
                        ),
                    )?
                    .map(Arc::new),
                Err(rss_mdm_apple_channel::runtime_materials::runtime::LoadError::Blocked(
                    reason,
                )) => {
                    use rss_mdm_apple_channel::runtime_materials::runtime::MaterialFailure as M;
                    let (state, reason) = match reason {
                        M::NotSelected | M::Missing => {
                            (ChannelState::Waiting, Reason::MaterialNotSelected)
                        }
                        M::Revoked => (ChannelState::Degraded, Reason::MaterialRevoked),
                        M::Expired => (ChannelState::Degraded, Reason::CertificateExpired),
                        M::VersionMismatch => {
                            (ChannelState::Degraded, Reason::MaterialVersionMismatch)
                        }
                        M::Invalid => (ChannelState::Degraded, Reason::MaterialInvalid),
                    };
                    channels.set(ChannelName::Apple, state, Some(reason))?;
                    None
                }
                Err(rss_mdm_apple_channel::runtime_materials::runtime::LoadError::Fatal(error)) => {
                    return Err(error.into());
                }
            }
        }
    } else {
        None
    };
    let mut agent_pki = channels
        .material(
            ChannelName::Agent,
            config.agent_pki.load(
                &config.identity.instance_id,
                audit_store.clone(),
                clock.clone(),
                providers.clone(),
                bootstrap,
            ),
        )?
        .flatten();
    let trusts = native_trusts(&windows, &apple, &agent_pki);
    let admission = rss_mdm_pki_service::registry::Registry::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        access.archive_pool(),
        audit_store.clone(),
        trusts,
        providers.clone(),
    );
    admit_native(
        &mut windows,
        &mut apple,
        &mut agent_pki,
        &channels,
        &admission,
        identity.tenant,
        clock.unix_seconds()?,
    )
    .await?;
    loaded_native_materials(&windows, &apple, &channels)?;
    let trusts = native_trusts(&windows, &apple, &agent_pki);
    let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        access.archive_pool(),
        audit_store.clone(),
        trusts,
        providers,
    ));
    observe_native_trust(&pki, &agent_pki, &channels)?;

    for (_, name) in [
        (
            windows.is_some(),
            crate::channel_status::ChannelName::Windows,
        ),
        (apple.is_some(), crate::channel_status::ChannelName::Apple),
        (
            agent_pki.is_some(),
            crate::channel_status::ChannelName::Agent,
        ),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    {
        channels.mounted(name)?;
    }
    let agent_enrollment = agent_pki
        .as_ref()
        .map(|pki| {
            rss_mdm_registration_service::agent::Service::new(
                rss_mdm_registration_service::agent::Assembly {
                    cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                        ring::hmac::HMAC_SHA256,
                        &cursor_key,
                    )),
                    tenant: identity.tenant,
                    store: access.registration(),
                    audit: audit_store.clone(),
                    issuer: pki.issuer.clone(),
                    clock: pki.pki_clock.clone(),
                    binding: Arc::new(rss_mdm_agent_channel::Bindings::new(
                        rss_mdm_install_support::StorageProfile::Mdm,
                    )),
                    native: Some(software.authority.clone()),
                    bootstrap: pki.bootstrap.clone(),
                    protection: protection.clone(),
                    installations: Some(Arc::new(crate::agent_configurations::Installations)),
                },
            )
            .map(Arc::new)
            .map_err(Error::from)
        })
        .transpose()?;
    let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
        rss_transactional_messaging::fence::StorageIdentity::new(
            config.storage_binding.target,
            config.storage_binding.lineage,
        )
        .map_err(|_| Error::Malformed)?,
        vec![(
            identity.tenant,
            rss_transactional_messaging::fence::Epoch::new(config.storage_binding.epoch)
                .map_err(|_| Error::Malformed)?,
        )],
    )
    .map_err(|_| Error::Malformed)?;
    let webhooks = crate::assembly::webhooks::open(
        config.webhooks,
        protocol_runtime.clone(),
        identity.tenant,
        audit_store.clone(),
        clock.clone(),
        protection.clone(),
        binding,
        rss_mdm_query::cursor::CursorCodec::new(&cursor_key).map_err(|_| Error::Malformed)?,
    )
    .await?;
    let platform_configuration = da
        .as_ref()
        .and_then(|d| d.runtime.platform.platform_sso.as_ref())
        .map(|runtime| runtime.qualification_configuration())
        .transpose()
        .map_err(|_| Error::Configuration(crate::ConfigIssue::DeviceAccess))?;
    let protocol_audit = Arc::new(
        audit_store
            .on_runtime(
                protocol_runtime.clone(),
                identity.tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(
                    std::time::Duration::from_secs(6),
                )
                .control(),
            )
            .await?,
    );
    let windows_delivery = Arc::new(rss_mdm_windows_channel::management::exchange::Delivery {
        runtime: protocol_runtime.clone(),
        tenant: identity.tenant,
        audit: protocol_audit.clone(),
        protection: protection.clone(),
        business: Arc::new(windows_business::WindowsBusiness(
            execution.clone(),
            configuration.clone(),
            collections.clone(),
            software.service.clone(),
            registration.native.clone(),
        )),
    });
    let apple_delivery = Arc::new(rss_mdm_apple_channel::delivery::Delivery {
        runtime: protocol_runtime.clone(),
        tenant: identity.tenant,
        audit: protocol_audit.clone(),
        business: Arc::new(apple_business::AppleBusiness(
            execution.clone(),
            configuration.clone(),
            collections.clone(),
            software.service.clone(),
            registration.native.clone(),
            credential_execution.as_ref().map(|v| v.native.clone()),
        )),
        facts: Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        }),
    });
    let agent_tasks = Arc::new(agent_tasks::AgentTasks {
        access: access_execution.service.clone(),
        credentials: credential_execution
            .as_ref()
            .map(|v| v.tasks.clone())
            .unwrap_or_default(),
        requests: self_service,
        software: software.service.clone(),
        registration: registration.enrollment.clone(),
        content: content_writer.clone(),
        execution: execution.clone(),
        scripts,
        collections,
    });
    let agent_delivery = Arc::new(rss_mdm_agent_channel::delivery::Delivery {
        runtime: protocol_runtime,
        tenant: identity.tenant,
        audit: protocol_audit,
        signing,
        tasks: agent_tasks.clone(),
        content: content_writer.clone(),
    });
    let operation_reads = Arc::new(operation_reads::Operations {
        apple: Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        }),
        recovery: credential_execution.as_ref().map(|v| v.native.clone()),
        tasks: task_reads.clone(),
        registration: registration.native.clone(),
        execution: execution.clone(),
    });
    let state = Arc::new(Assembly {
        da,
        script_work,
        collection_work,
        access_execution,
        credential_execution,
        operation_reads,
        software,
        registration,
        agent_tasks,
        agent_delivery,
        apple_delivery,
        windows_delivery,
        task_trust,
        events,
        resources,
        channels,
        telemetry,
        runtime_observation: crate::installation::host::Observation::new(
            &config.runtime_binding,
            identity.tenant.to_string(),
            identity.instance.to_string(),
        ),
        apple_material_roots,
        webhooks,
        pki,
        agent_enrollment,
        agent_pki,
        certificate_archive,
        timeline,
        associations,
        content_writer,
        configuration_preview,
        configuration,
        queries,
        task_reads,
        protection,
        audit_store,
        apple,
        platform_configuration,
        execution,
        groups,
        policy_application,
        policies,
        publications,
        software_catalog,
        content_access,
        cursor_key,
        scope_group_health,
        scopes,
        assets,
        compliance,
        windows,
        access: access.clone(),
        identity: Arc::new(identity),
        credentials: Arc::new(Credentials::new(monotonic.clone(), 10000)),
        clock,
        identity_management,
        inventory: runtime.clone(),
        devices,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    let routers = http::from_state(state, host, monotonic);
    Ok(routers)
}

async fn load_windows_push(
    config: &crate::config::Config,
    tenant: rss_request_context::TenantId,
    protection: &rss_mdm_native_protection::Protector,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> Result<Option<rss_mdm_windows_channel::push::Push>, Error> {
    Ok(
        if let Some(push) = config
            .native_protocols
            .windows
            .as_ref()
            .and_then(|w| w.push.as_ref())
        {
            use sqlx::Connection;
            let mut c = sqlx::PgConnection::connect_with(&config.access_database.options()?)
                .await
                .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
            let mut tx = c
                .begin()
                .await
                .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
            let value = rss_mdm_windows_channel::wns_materials::load(
                &mut tx,
                &tenant.to_string(),
                push.revision,
                protection,
                monotonic.clone(),
                true,
            )
            .await;
            tx.rollback()
                .await
                .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
            c.close()
                .await
                .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
            Some(value?)
        } else {
            None
        },
    )
}

/// Locally owned sockets are dropped together if any bind in this channel fails.
fn observe_native_trust(
    pki: &Arc<rss_mdm_pki_service::registry::Registry>,
    agent: &Option<Arc<crate::agent_pki::AgentPki>>,
    channels: &crate::channel_status::Channels,
) -> Result<(), Error> {
    use crate::channel_status::ChannelName;
    use rss_mdm_agent_wire::pki::Purpose;
    for binding in pki.bindings() {
        let trust = binding
            .public()
            .map_err(|_| Error::Unavailable(crate::Failure::CommandInvariant))?;
        let name = match trust.purpose {
            Purpose::Windows => ChannelName::Windows,
            Purpose::Apple => ChannelName::Apple,
            Purpose::Agent => ChannelName::Agent,
            Purpose::AgentBootstrap => ChannelName::AgentBootstrap,
            Purpose::DaDevice => return Err(Error::Forbidden),
        };
        channels.loaded(
            name,
            crate::channel_status::LoadedMaterials {
                trust: Some(i64::try_from(trust.revision).map_err(|_| Error::Conflict)?),
                ..Default::default()
            },
        )?;
    }
    if let Some(agent) = agent {
        channels.installation(agent.clone(), pki.clone())?;
    }
    Ok(())
}

fn native_trusts(
    windows: &Option<Arc<crate::windows::Windows>>,
    apple: &Option<Arc<crate::apple::Apple>>,
    agent_pki: &Option<Arc<crate::agent_pki::AgentPki>>,
) -> Vec<rss_mdm_device_trust::DeviceTrust> {
    let mut trusts = Vec::new();
    if let Some(w) = windows {
        trusts.push(w.channel.ca.trust.clone());
    }
    if let Some(a) = apple {
        trusts.push(a.channel.device_trust().clone());
    }
    if let Some(a) = agent_pki {
        trusts.push(a.issuer.trust().trust.clone());
        if let Some(bootstrap) = &a.bootstrap {
            trusts.push(bootstrap.trust.clone());
        }
    }
    trusts
}
async fn admit_native(
    windows: &mut Option<Arc<crate::windows::Windows>>,
    apple: &mut Option<Arc<crate::apple::Apple>>,
    agent_pki: &mut Option<Arc<crate::agent_pki::AgentPki>>,
    channels: &crate::channel_status::Channels,
    admission: &rss_mdm_pki_service::registry::Registry,
    tenant: rss_request_context::TenantId,
    now: i64,
) -> Result<(), Error> {
    use crate::channel_status::{ChannelName, ChannelState, Reason};
    use rss_mdm_agent_wire::pki::Purpose;
    for (purpose, name) in [
        (Purpose::Windows, ChannelName::Windows),
        (Purpose::Apple, ChannelName::Apple),
        (Purpose::Agent, ChannelName::Agent),
        (Purpose::AgentBootstrap, ChannelName::AgentBootstrap),
    ] {
        match admission.admit_purpose(tenant, now, purpose).await {
            Ok(()) => (),
            Err(error) => {
                use rss_mdm_pki_service::Error as P;
                let reason = match error {
                    P::Configuration => Reason::MaterialInvalid,
                    P::Conflict => Reason::TrustConflict,
                    P::NotFound | P::ReadConflict | P::CursorInvalidated => {
                        return Err(Error::Unavailable(crate::Failure::Database));
                    }
                    P::Request => Reason::DependencyUnavailable,
                    P::Audit(error) => return Err(error.into()),
                    P::Storage => return Err(Error::Unavailable(crate::Failure::Database)),
                    P::Unknown { .. } => return Err(Error::CommitUnknown),
                    P::Forbidden => return Err(Error::Forbidden),
                };
                channels.set(name, ChannelState::Degraded, Some(reason))?;
                match purpose {
                    Purpose::DaDevice => return Err(Error::Forbidden),
                    Purpose::Windows => *windows = None,
                    Purpose::Apple => *apple = None,
                    Purpose::Agent => *agent_pki = None,
                    Purpose::AgentBootstrap => {
                        if let Some(pki) = agent_pki.as_mut() {
                            let pki = Arc::get_mut(pki).ok_or(Error::Conflict)?;
                            pki.remove_bootstrap()?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
fn loaded_native_materials(
    windows: &Option<Arc<crate::windows::Windows>>,
    apple: &Option<Arc<crate::apple::Apple>>,
    channels: &crate::channel_status::Channels,
) -> Result<(), Error> {
    use crate::channel_status::ChannelName;
    if let Some(a) = apple {
        channels.loaded(
            ChannelName::Apple,
            crate::channel_status::LoadedMaterials {
                apns: a.config.materials.apns,
                profile: a.config.materials.profile,
                ..Default::default()
            },
        )?;
    }
    if let Some(w) = windows
        && w.channel.push.is_some()
    {
        channels.loaded(
            ChannelName::WindowsPush,
            crate::channel_status::LoadedMaterials {
                wns: w.config.push.as_ref().map(|p| p.revision),
                ..Default::default()
            },
        )?;
    }
    Ok(())
}

mod configuration_channels;

mod configuration_cleanup;

pub(crate) mod timeline_associations;

mod collection_ports;

pub(crate) mod task_reads;

#[cfg(test)]
#[path = "../../tests/execution_owners/mod.rs"]
mod execution_owners_t2;

mod task_cleanup;

mod registration_sources;
pub(crate) mod software_sources;

mod registration_agent_facts;
mod registration_apple_facts;
mod registration_windows_facts;
mod software_agent_facts;
mod software_apple_facts;
mod software_windows_facts;

mod owner_errors;
pub(crate) mod registration;

mod device_reads;
mod operation_reads;

#[cfg(test)]
#[path = "../../tests/registration/directory.rs"]
mod registration_directory_t2;
#[cfg(test)]
#[path = "../../tests/registration/mod.rs"]
mod registration_installation_t2;
#[cfg(test)]
#[path = "../../tests/software/mod.rs"]
mod software_t2;

pub(crate) mod access_execution;
mod credential_apple_facts;
pub(crate) mod credential_execution;

#[cfg(test)]
#[path = "../../tests/credential_owners/mod.rs"]
mod credential_owners_t2;

mod device_materials;

#[cfg(test)]
#[path = "../../tests/device/mod.rs"]
mod device_t2;

#[cfg(test)]
#[path = "../../tests/owner_boundaries/mod.rs"]
mod owner_boundaries_t2;

#[cfg(test)]
#[path = "../../tests/reference_blockers/mod.rs"]
mod reference_blockers_t2;

mod operation_diagnostics;

#[cfg(test)]
#[path = "../../tests/operation_diagnostics.rs"]
mod operation_diagnostics_t2;
#[cfg(test)]
#[path = "../../tests/software_assets/mod.rs"]
mod software_assets_t2;
