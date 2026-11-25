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
    pub(crate) providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub(crate) credential_receipts:
        Option<Arc<rss_mdm_recovery_credentials::native_receipts::NativeReceipts>>,
    pub(crate) request_timeout: std::time::Duration,
    pub(crate) request_budget: rss_axum::RequestBudget,
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
    pub(crate) scope_group_health: Arc<crate::local_delivery::Health>,
    pub(crate) asset_input_health: Arc<crate::local_delivery::Health>,

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
    pub(crate) buffered_bytes: Arc<tokio::sync::Semaphore>,
}

pub(crate) struct AssemblyDependencies {
    pub(crate) baseline_wake: Arc<tokio::sync::Notify>,
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
    pub(crate) bootstrap: Option<Arc<rss_mdm_pki_service::scep::Verifier>>,
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
    pub(crate) scope_group_health: Arc<crate::local_delivery::Health>,
    pub(crate) asset_input_health: Arc<crate::local_delivery::Health>,

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
        identity: identity_policy,
        inventory_runtime: _,
        config,
        background: _,
        http,
        audit_query: _,
        identity_management,
    } = compiled;
    let identity_runtime_policy = config.identity.runtime.clone();
    let AssemblyDependencies {
        baseline_wake,
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
        asset_input_health,
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
                    content: content_writer.clone(),
                    protection: protection.clone(),
                },
            ),
            source: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
            )),
            read_pool: read_pool.clone(),
            clock: Arc::new(crate::lifecycle::RuntimeTimer),
        });
    let devices = Arc::new(crate::device::DeviceService::new(
        access.registration(),
        audit_store.clone(),
    ));
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration(ConfigIssue::ProductOrigin))?
        .to_owned();
    use crate::channel_status::ChannelName;
    let windows = config
        .native_protocols
        .windows
        .map(|config| {
            let verifier = rss_identity_oidc::entra::HttpEntra::new(
                identity_policy.transport,
                identity_runtime_policy.jwks.max_token_bytes,
                identity_policy.jwks,
            )
            .map_err(|_| Error::Configuration(ConfigIssue::IdentityConfiguration))?;
            crate::windows::Windows::load(
                config,
                identity.authority.clone(),
                Arc::new(verifier),
                monotonic.clone(),
            )
            .map(Arc::new)
        })
        .transpose()?;
    let roots = channels.material(
        ChannelName::Apple,
        config
            .apple_material_roots
            .iter()
            .map(|path| crate::config::read(path, 128 * 1024, false).map(|bytes| bytes.to_vec()))
            .collect::<Result<Vec<_>, _>>(),
    )?;
    let apple_material_roots = Arc::new(roots.unwrap_or_default());
    let apple = config
        .native_protocols
        .apple
        .map(crate::apple::Apple::load)
        .transpose()?
        .map(Arc::new);
    let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        access.archive_pool(),
        audit_store.clone(),
        identity
            .storage
            .execution(identity.management_binding.tenant())?,
        providers.clone(),
    ));
    let agent_pki = channels
        .material(
            ChannelName::Agent,
            config.agent_pki.load(
                &config.identity.instance_id,
                audit_store.clone(),
                clock.clone(),
                providers.clone(),
                pki.clone(),
                bootstrap,
            ),
        )?
        .flatten();

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
    if let Some(agent) = &agent_pki {
        channels.installation(agent.clone())?;
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
                    probe: identity
                        .storage
                        .execution(identity.management_binding.tenant())?,
                    store: access.registration(),
                    audit: audit_store.clone(),
                    origins: pki.origins.clone(),
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
    let binding = identity.management_binding;
    let webhooks = crate::assembly::webhooks::open(
        config.webhooks,
        protocol_runtime.clone(),
        access.archive_pool(),
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
                identity.management_binding,
                &rss_mdm_audit_integration::budget::AuditBudget::new(
                    std::time::Duration::from_secs(6),
                )
                .control(),
            )
            .await?,
    );
    let windows_delivery = Arc::new(rss_mdm_windows_channel::management::exchange::Delivery {
        runtime: protocol_runtime.clone(),
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
        audit: protocol_audit,
        signing,
        tasks: agent_tasks.clone(),
        content: content_writer.clone(),
    });
    let operation_reads = Arc::new(operation_reads::Operations {
        budgets: Default::default(),
        apple: Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        }),
        recovery: credential_execution.as_ref().map(|v| v.native.clone()),
        tasks: task_reads.clone(),
        registration: registration.native.clone(),
        execution: execution.clone(),
    });
    let state = Arc::new(Assembly {
        request_timeout: std::time::Duration::from_secs(config.http.request_seconds),
        request_budget: http.request,
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
        runtime_observation: crate::installation::host::Observation::new(
            &config.runtime_binding,
            identity.instance.to_string(),
            config
                .telemetry
                .iter()
                .filter_map(|r| {
                    (!telemetry
                        .as_ref()
                        .is_some_and(|s| s.admits_installation(r.resource_id)))
                    .then_some(r.resource_id)
                })
                .collect(),
        ),
        telemetry,
        apple_material_roots,
        webhooks,
        pki,
        providers,
        credential_receipts,
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
        asset_input_health,
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
        buffered_bytes: Arc::new(tokio::sync::Semaphore::new(http.buffered_body_bytes)),
    });
    let routers = http::from_state(state, host, monotonic, baseline_wake);
    Ok(routers)
}

/// Locally owned sockets are dropped together if any bind in this channel fails.
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

#[cfg(test)]
#[path = "../../tests/directory_queries/mod.rs"]
mod directory_queries_t2;

#[cfg(test)]
pub(crate) use software_t2::support::software as seed_software;

#[cfg(test)]
#[path = "../../tests/telemetry/mod.rs"]
mod telemetry_queries_t2;

#[cfg(test)]
#[path = "../../tests/webhook_relay.rs"]
mod webhook_relay_t2;
