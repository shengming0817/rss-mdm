//! Product route and service assembly.
use crate::clock::Clock;
use crate::{ConfigIssue, Database};
use crate::{
    Error, authorization::identity_management::IdentityManagementPolicy,
    enrollment::credentials::Credentials, identity::Identity,
};
use std::sync::Arc;

pub(crate) mod content;
pub(crate) mod execution;
pub(crate) mod inventory;
pub(crate) mod policy;
pub(crate) mod publication;
pub(crate) mod resource;
pub(crate) mod software;
pub(crate) mod http;
pub(crate) struct Assembly {
    pub(crate) events: Arc<rss_mdm_policy_service::events::Events>,
    pub(crate) resources: Arc<rss_mdm_resource_service::ResourceCatalog>,
    pub(crate) access_audit: Option<Arc<rss_mdm_audit_integration::AuditStore>>,
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub(crate) runtime_observation: crate::installation::host::Observation,
    pub(crate) apple_material_roots: Arc<Vec<Vec<u8>>>,
    pub(crate) webhooks: Arc<crate::webhooks::Backend>,
    pub(crate) pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub(crate) agent_enrollment: Option<Arc<rss_mdm_registration_service::agent::Service>>,
    pub(crate) agent_pki: Option<Arc<crate::agent_pki::AgentPki>>,
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) associations: Arc<rss_mdm_device_service::Associations>,
    pub(crate) content_writer: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) groups: Arc<rss_mdm_inventory_service::groups::Groups>,
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
    pub(crate) compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    pub(crate) identity: Arc<Identity>,
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) identity_management: Arc<IdentityManagementPolicy>,
    pub(crate) inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) apple: Option<Arc<crate::apple::Apple>>,
    pub(crate) platform_configuration:
        Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
    pub(crate) windows: Option<Arc<crate::windows::Windows>>,
    pub(crate) access: Arc<Database>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
pub(crate) async fn application_fixture(
    config: crate::config::Config,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    access: Arc<Database>,
    identity: Option<Identity>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
) -> Result<
    (
        crate::native::Routers,
        crate::assembly::execution::Assembly,
        Arc<rss_transactional_messaging_postgres::PgRuntime>,
        Arc<crate::planning::test_support::OwnerFixture>,
        crate::test_support::runtime::Resources,
    ),
    Error,
> {
    let mut resources = crate::test_support::runtime::Resources::default();
    resources.resource(crate::lifecycle::AccessResource(access.clone()));
    let result = async {
        access.claim_tenant_use(&config).await?;
        let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
            config.runtime_database.options()?,
            access.inventory(),
            rss_request_context::TenantId::parse(&config.identity.tenant_id)
                .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?,
            monotonic.clone(),
            access
                .audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        resources.resource(crate::test_support::runtime::InventoryFixtureResource(
            runtime.clone(),
        ));
        let protection = config.native_protector()?;
        let content = crate::assembly::execution::open_content(&config, protection.clone()).await?;
        if let Some(content) = &content {
            resources.resource(crate::assembly::execution::ContentResource(content.clone()));
        }
        let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)
            .map_err(|_| Error::Malformed)?;
        let cursor_key = crate::cursor_keys::load(
            access
                .fixture_source_runtime
                .get()
                .ok_or(Error::Unavailable(crate::Failure::Database))?,
            tenant,
        )
        .await?;
        let inventory_owner = crate::owner_storage::OwnerRuntime::open(
            &config.business_databases.inventory,
            &config.storage_binding,
            tenant,
            config.background.inventory_connections(),
            audit_store.clone(),
            "inventory-runtime-postgres",
            |resource| {
                resources.resource(resource);
            },
        )
        .await?;
        let scope_owner = crate::owner_storage::OwnerRuntime::open(
            &config.business_databases.scope,
            &config.storage_binding,
            tenant,
            config.background.scope_connections(),
            audit_store.clone(),
            "scope-runtime-postgres",
            |resource| {
                resources.resource(resource);
            },
        )
        .await?;
        let policy_owner = crate::owner_storage::OwnerRuntime::open(
            &config.business_databases.policy,
            &config.storage_binding,
            tenant,
            config.background.policy_connections(),
            audit_store.clone(),
            "policy-runtime-postgres",
            |resource| {
                resources.resource(resource);
            },
        )
        .await?;
        let resource_owner = crate::owner_storage::OwnerRuntime::open(
            &config.business_databases.resource,
            &config.storage_binding,
            tenant,
            2,
            audit_store.clone(),
            "resource-runtime-postgres",
            |resource| {
                resources.resource(resource);
            },
        )
        .await?;
        let software_owner = crate::owner_storage::OwnerRuntime::open(
            &config.business_databases.software,
            &config.storage_binding,
            tenant,
            2,
            audit_store.clone(),
            "software-runtime-postgres",
            |resource| {
                resources.resource(resource);
            },
        )
        .await?;
        let inventory_services = crate::assembly::inventory::Services::new(
            runtime.clone(),
            inventory_owner.runtime.clone(),
            inventory_owner.audit.clone(),
            tenant,
            &cursor_key,
            clock.clone(),
        )
        .await?;
        let policy_application =
            crate::assembly::policy::application(&policy_owner, tenant, &cursor_key, clock.clone())
                .await?;
        let publications = crate::assembly::publication::open(
            &config.publication,
            &config.storage_binding,
            &software_owner,
            tenant,
            &cursor_key,
            clock.clone(),
            content.clone(),
            |resource| {
                resources.resource(resource);
            },
        )
        .await?;
        let resource_catalog = crate::assembly::resource::catalog(
            resource_owner.audit.clone(),
            resource_owner.runtime.clone(),
            tenant,
            clock.clone(),
            cursor_key.clone(),
        )
        .await?;
        let software_catalog = crate::assembly::software::catalog(
            &software_owner,
            tenant,
            &cursor_key,
            clock.clone(),
            content.clone(),
        )
        .await?;
        let scope_group_health = Arc::new(crate::scope_group_changes::Health::default());
        let compiled = config.compile()?;
        access
            .authorization_store()
            .require_management_initializer()
            .await?;
        let identity = match identity {
            Some(identity) => identity,
            None => {
                Identity::connect(
                    &compiled.config,
                    compiled.identity_management.clone(),
                    Some(crate::apple::identity_platform(&compiled.config).await?),
                    |resource| resources.acquire(resource),
                )
                .await?
            }
        };
        let content_access = if let Some(content) = &content {
            let content_owner = crate::owner_storage::OwnerRuntime::open(
                &compiled.config.business_databases.content,
                &compiled.config.storage_binding,
                tenant,
                2,
                audit_store.clone(),
                "content-runtime-postgres",
                |resource| {
                    resources.resource(resource);
                },
            )
            .await?;
            Some(
                crate::assembly::content::access(
                    &content_owner,
                    &identity,
                    access.authorization_store(),
                    content.clone(),
                    clock.clone(),
                )
                .await?,
            )
        } else {
            None
        };
        let execution = crate::assembly::execution::open(
            &compiled.config,
            protection,
            audit_store.clone(),
            content.clone(),
            publications.services.clone(),
            rss_device_command_postgres::CommandClock::Postgres,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    identity.authority.clone(),
                    identity.tenant,
                ),
            ),
            cursor_key.clone(),
        )
        .await?;
        resources.resource(rss_mdm_execution_service::Resource(
            execution.service.clone(),
        ));
        let policy_inputs = Arc::new(rss_mdm_execution_service::Inputs::bind(
            policy_owner.runtime.clone(),
            policy_application.tenant,
            execution.materials.inputs.clone(),
        ));
        let policies =
            crate::assembly::policy::management(&policy_application, policy_inputs, &cursor_key)
                .await?;
        let events =
            crate::assembly::policy::events(policy_application.clone(), execution.materials.clone())
                .await?;
        let associations = Arc::new(
            rss_mdm_device_service::Associations::new(
                audit_store.clone(),
                identity.tenant,
                &cursor_key,
            )
            .map_err(|_| Error::Unavailable(crate::Failure::Database))?,
        );
        let timeline = access.timeline(audit_store.clone(), identity.tenant, &cursor_key)?;
        let telemetry = match &compiled.config.telemetry {
            Some(config) => {
                let telemetry_owner = crate::owner_storage::OwnerRuntime::open(
                    &compiled.config.business_databases.telemetry,
                    &compiled.config.storage_binding,
                    tenant,
                    compiled.config.background.telemetry_control_connections(),
                    audit_store.clone(),
                    "telemetry-runtime-postgres",
                    |resource| {
                        resources.resource(resource);
                    },
                )
                .await?;
                let dependencies = rss_mdm_telemetry_service::PolicyDependencies {
                    audit_store: telemetry_owner.audit.clone(),
                    policies: Arc::new(rss_mdm_policy_service::telemetry::Reader::new(
                        telemetry_owner.runtime.clone(),
                        tenant,
                        Arc::new(rss_mdm_device_service::planning::PlanningObjects),
                    )),
                    objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
                };
                let service = config
                    .open(
                        tenant,
                        telemetry_owner.runtime,
                        dependencies,
                        execution.service.clone(),
                    )
                    .await?;
                resources.resource(crate::telemetry::Resource(service.clone()));
                resources.resource(crate::telemetry::fixture_task(
                    service.clone(),
                    execution.runtime.clone(),
                    runtime.clone(),
                    compiled.config.access_options()?,
                    policy_application.tenant,
                )?);
                Some(service)
            }
            None => None,
        };
        let scopes = crate::scopes::open(
            scope_owner.runtime.clone(),
            identity.tenant,
            clock.clone(),
            scope_owner.audit.clone(),
            cursor_key.clone(),
        )
        .await?;
        let plan_runtime = policy_owner.runtime.clone();
        let fixture_planning = Arc::new(crate::planning::test_support::OwnerFixture::from_owners(
            policy_application.clone(),
            inventory_owner,
            scope_owner,
            resource_owner,
            software_owner,
            cursor_key.clone(),
        ));
        let execution_service = execution.clone();
        let mut fixture_routers = from_compiled(
            compiled,
            AssemblyDependencies {
                mount_channels: false,
                telemetry,
                certificate_archive: crate::certificate_archive::assemble(
                    &access,
                    audit_store.clone(),
                    clock.clone(),
                ),
                timeline,
                associations,
                audit_store,
                execution,
                clock,
                monotonic,
                access: access.clone(),
                runtime,
                groups: inventory_services.groups.clone(),
                policy_application: policy_application.clone(),
                policies: policies.clone(),
                publications: publications.clone(),
                software_catalog: software_catalog.clone(),
                content_access: content_access.clone(),
                cursor_key: cursor_key.clone(),
                scope_group_health: scope_group_health.clone(),
                resources: resource_catalog.clone(),
                events: events.clone(),
                scopes,
                assets: inventory_services.assets,
                compliance: inventory_services.compliance,
                identity,
            },
        )
        .await?;
        resources.resource(crate::webhooks::Resource(fixture_routers.webhooks.clone()));
        crate::test_support::pki::seed_trust(
            &access.archive_pool(),
            fixture_routers.pki.bindings(),
        )
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
        // Test carrier projects real, completed TLS evidence; the production browser router stays separate.
        for (kind, tls) in fixture_routers.listeners.drain(..) {
            if kind == crate::native::ChannelKind::Agent {
                fixture_routers.browser = crate::test_support::gateway::browser_agent(
                    fixture_routers.browser,
                    tls.router,
                    "mdm.example.test",
                )
            }
        }
        let requests = crate::test_support::runtime::NativeRequests::new();
        resources.resource(requests.clone());
        fixture_routers.browser = requests.wrap(fixture_routers.browser);
        for (_, channel) in &mut fixture_routers.listeners {
            channel.router = requests.wrap(std::mem::take(&mut channel.router));
        }
        Ok((
            fixture_routers,
            execution_service,
            plan_runtime,
            fixture_planning,
        ))
    }
    .await;
    match result {
        Ok((router, execution, runtime, planning)) => {
            Ok((router, execution, runtime, planning, resources))
        }
        Err(error) => {
            let cleanup = resources.finish(async { Ok(()) }).await;
            if let Err(cleanup_error) = cleanup {
                eprintln!("application fixture cleanup also failed: {cleanup_error:#}");
            }
            Err(error)
        }
    }
}
pub(crate) struct AssemblyDependencies {
    #[cfg(test)]
    pub(crate) mount_channels: bool,
    pub(crate) telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) associations: Arc<rss_mdm_device_service::Associations>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: crate::assembly::execution::Assembly,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) monotonic: Arc<dyn rss_observation::Clock>,
    pub(crate) access: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) groups: Arc<rss_mdm_inventory_service::groups::Groups>,
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
    pub(crate) compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    pub(crate) identity: Identity,
    pub(crate) resources: Arc<rss_mdm_resource_service::ResourceCatalog>,
    pub(crate) events: Arc<rss_mdm_policy_service::events::Events>,
}
async fn device_access_audit(
    identity: &Identity,
    audit_store: &rss_mdm_audit_integration::AuditStore,
    enabled: bool,
) -> Result<Option<Arc<rss_mdm_audit_integration::AuditStore>>, Error> {
    if !enabled {
        return Ok(None);
    }
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    Ok(Some(Arc::new(
        audit_store
            .on_runtime(identity.runtime.clone(), identity.tenant, &budget.control())
            .await?,
    )))
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
        #[cfg(test)]
        mount_channels,
        telemetry,
        certificate_archive,
        timeline,
        associations,
        audit_store,
        execution,
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
    let crate::assembly::execution::Assembly {
        materials: _,
        channels,
        providers,
        bootstrap,
        service: execution,
        queries,
        protection,
        content: content_writer,
        runtime: _execution_runtime,
    } = execution;
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
    let platform_origin = config.product_origin.clone();
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
                            (&platform_origin, identity.tenant),
                            providers.clone(),
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
        access.archive_pool(),
        audit_store.clone(),
        trusts,
        providers.clone(),
    );
    #[cfg(not(test))]
    let mount_channels = true;
    if mount_channels {
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
    }
    loaded_native_materials(&windows, &apple, &channels)?;
    let trusts = native_trusts(&windows, &apple, &agent_pki);
    let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        access.archive_pool(),
        audit_store.clone(),
        trusts,
        providers,
    ));
    observe_native_trust(&pki, &agent_pki, &channels)?;
    // Handler fixtures own their transport outside this assembly.
    #[cfg(test)]
    if !mount_channels {
        fixture_native_mounted(&windows, &apple, &agent_pki, &channels)?;
    }
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
    let access_audit = device_access_audit(&identity, &audit_store, agent_pki.is_some()).await?;
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
                    access_audit: access_audit.clone().ok_or(Error::Malformed)?,
                    issuer: pki.issuer.clone(),
                    clock: pki.pki_clock.clone(),
                    binding: Arc::new(rss_mdm_agent_channel::Bindings),
                    native: execution.clone(),
                    bootstrap: pki.bootstrap.clone(),
                    protection: protection.clone(),
                    installations: Arc::new(crate::agent_configurations::Installations),
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
    let webhooks = crate::webhooks::Backend::open(
        config.webhooks,
        _execution_runtime.clone(),
        identity.tenant,
        audit_store.clone(),
        clock.clone(),
        protection.clone(),
        binding,
        rss_mdm_query::cursor::CursorCodec::new(&cursor_key).map_err(|_| Error::Malformed)?,
    )
    .await?;
    let platform_configuration = apple
        .as_ref()
        .and_then(|apple| apple.platform_sso.as_ref())
        .map(|runtime| runtime.qualification_configuration())
        .transpose()?;
    let state = Arc::new(Assembly {
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
        access_audit,
        agent_enrollment,
        agent_pki,
        certificate_archive,
        timeline,
        associations,
        content_writer,
        queries,
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
#[cfg(test)]
fn fixture_native_mounted(
    windows: &Option<Arc<crate::windows::Windows>>,
    apple: &Option<Arc<crate::apple::Apple>>,
    agent_pki: &Option<Arc<crate::agent_pki::AgentPki>>,
    channels: &crate::channel_status::Channels,
) -> Result<(), Error> {
    use crate::channel_status::ChannelName;
    for (name, present) in [
        (ChannelName::Windows, windows.is_some()),
        (ChannelName::Apple, apple.is_some()),
        (ChannelName::Agent, agent_pki.is_some()),
    ] {
        if present {
            channels.mounted(name)?;
        }
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

/// Final prefixes are shared by the serving listener and offline contract projection.
