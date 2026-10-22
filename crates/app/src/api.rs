//! Product route and service assembly.
use crate::clock::Clock;
use crate::{ConfigIssue, Database};
use crate::{
    Error, authorization::identity_management::IdentityManagementPolicy,
    enrollment::credentials::Credentials, identity::Identity,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    middleware::{self},
    response::{IntoResponse, Response},
    routing::get,
};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
pub(crate) struct Assembly {
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub(crate) runtime_observation: crate::setup::host::Observation,
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
    pub(crate) inputs: Arc<rss_mdm_execution_service::Inputs>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    #[cfg(test)]
    pub(crate) execution_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) flow: Arc<crate::flow::Flow>,
    pub(crate) identity: Arc<Identity>,
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) identity_management: Arc<IdentityManagementPolicy>,
    pub(crate) inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) apple: Option<Arc<crate::apple::Apple>>,
    pub(crate) windows: Option<Arc<crate::windows::Windows>>,
    pub(crate) access: Arc<Database>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
impl Assembly {
    pub(crate) fn apple(&self) -> Result<&Arc<crate::apple::Apple>, Error> {
        self.apple.as_ref().ok_or(Error::Unsupported)
    }
    pub(crate) fn windows(&self) -> Result<&Arc<crate::windows::Windows>, Error> {
        self.windows.as_ref().ok_or(Error::Unsupported)
    }
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
        Router,
        crate::execution_assembly::Assembly,
        Arc<rss_transactional_messaging_postgres::PgRuntime>,
        Arc<rss_mdm_flow_service::planning::Planning>,
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
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        resources.resource(crate::test_support::runtime::InventoryFixtureResource(
            runtime.clone(),
        ));
        let protection = config.native_protector()?;
        let content = crate::execution_assembly::open_content(&config, protection.clone()).await?;
        if let Some(content) = &content {
            resources.resource(crate::execution_assembly::ContentResource(content.clone()));
        }
        let planning = config
            .flow
            .open(
                runtime.clone(),
                audit_store.clone(),
                rss_request_context::TenantId::parse(&config.identity.tenant_id)
                    .map_err(|_| Error::Malformed)?,
                clock.clone(),
                content.clone(),
                |resource| resources.resource(resource),
            )
            .await?;
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
                    |resource| resources.acquire(resource),
                )
                .await?
            }
        };
        let execution = crate::execution_assembly::open(
            &compiled.config,
            protection,
            audit_store.clone(),
            content,
            planning.publications.services.clone(),
            rss_device_command_postgres::CommandClock::Postgres,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    identity.authority.clone(),
                    identity.tenant,
                ),
            ),
        )
        .await?;
        resources.resource(rss_mdm_execution_service::Resource(
            execution.service.clone(),
        ));
        let associations = Arc::new(
            rss_mdm_device_service::Associations::new(
                audit_store.clone(),
                identity.tenant,
                &planning.cursor_key,
            )
            .map_err(|_| Error::Unavailable(crate::Failure::Database))?,
        );
        let timeline =
            access.timeline(audit_store.clone(), identity.tenant, &planning.cursor_key)?;
        timeline
            .initialize()
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
        let telemetry = match &compiled.config.telemetry {
            Some(config) => {
                let service = config.open(&planning, execution.service.clone()).await?;
                resources.resource(crate::telemetry::Resource(service.clone()));
                resources.resource(crate::telemetry::fixture_task(
                    service.clone(),
                    execution.runtime.clone(),
                    runtime.clone(),
                    compiled.config.access_options()?,
                    planning.planning.tenant,
                )?);
                Some(service)
            }
            None => None,
        };
        let plan_runtime = planning.runtime.clone();
        let fixture_planning = planning.planning.clone();
        let execution_service = execution.clone();
        let mut fixture_routers = from_compiled(
            compiled,
            AssemblyDependencies {
                bind_listeners: false,
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
                flow: planning,
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
        for (kind, tls) in fixture_routers.listeners {
            if kind == crate::native::NativeListenerKind::Agent {
                fixture_routers.browser = fixture_routers.browser.merge(tls.router)
            }
        }
        Ok((
            fixture_routers.browser,
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
    pub(crate) bind_listeners: bool,
    pub(crate) telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) associations: Arc<rss_mdm_device_service::Associations>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: crate::execution_assembly::Assembly,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) monotonic: Arc<dyn rss_observation::Clock>,
    pub(crate) access: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) flow: Arc<crate::flow::Flow>,
    pub(crate) identity: Identity,
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
        bind_listeners,
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
        flow: planning,
        identity,
    } = dependencies;
    let crate::execution_assembly::Assembly {
        channels,
        providers,
        bootstrap,
        configuration_signer,
        service: execution,
        inputs,
        queries,
        protection,
        content: content_writer,
        runtime: _execution_runtime,
        #[cfg(test)]
            webhooks: fixture_webhooks,
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
    use rss_mdm_management_http::runtime_diagnostics::{ChannelName, ChannelState, Reason};
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
                audit_store.clone(),
                clock.clone(),
                providers.clone(),
                bootstrap,
            ),
        )?
        .flatten();
    let mut trusts = Vec::new();
    if let Some(w) = &windows {
        trusts.push(w.channel.ca.trust.clone());
    }
    if let Some(a) = &apple {
        trusts.push(a.channel.device_trust().clone());
    }
    if let Some(a) = &agent_pki {
        trusts.push(a.issuer.trust().trust.clone());
        if let Some(bootstrap) = &a.bootstrap {
            trusts.push(bootstrap.trust.clone());
        }
    }
    let admission = rss_mdm_pki_service::registry::Registry::new(
        access.archive_pool(),
        audit_store.clone(),
        trusts,
        providers.clone(),
    );
    use rss_mdm_agent_wire::pki::Purpose;
    for (purpose, name) in [
        (Purpose::Windows, ChannelName::Windows),
        (Purpose::Apple, ChannelName::Apple),
        (Purpose::Agent, ChannelName::Agent),
        (Purpose::AgentBootstrap, ChannelName::AgentBootstrap),
    ] {
        match admission
            .admit_purpose(identity.tenant, clock.unix_seconds()?, purpose)
            .await
        {
            Ok(()) => (),
            Err(error) => {
                use rss_mdm_pki_service::Error as P;
                let reason = match error {
                    P::Configuration | P::Conflict => Reason::MaterialInvalid,
                    P::Request => Reason::DependencyUnavailable,
                    P::Audit(error) => return Err(error.into()),
                    P::Storage => return Err(Error::Unavailable(crate::Failure::Database)),
                    P::Unknown { .. } => return Err(Error::CommitUnknown),
                    P::Forbidden => return Err(Error::Forbidden),
                };
                channels.set(name, ChannelState::Degraded, Some(reason))?;
                match purpose {
                    Purpose::Windows => windows = None,
                    Purpose::Apple => apple = None,
                    Purpose::Agent => agent_pki = None,
                    Purpose::AgentBootstrap => {
                        if let (Some(pki), crate::agent_pki::Config::StepCa { endpoint, .. }) =
                            (&mut agent_pki, &config.agent_pki)
                        {
                            let pki = Arc::get_mut(pki).ok_or(Error::Conflict)?;
                            pki.remove_bootstrap(endpoint)?;
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(test))]
    let bind_listeners = true;
    if let Some(a) = &apple {
        channels.loaded(
            ChannelName::Apple,
            a.config
                .materials
                .apns
                .map(|v| ("apns".into(), v))
                .into_iter()
                .chain(a.config.materials.profile.map(|v| ("profile".into(), v))),
        )?;
    }
    if let Some(w) = &windows {
        if w.channel.push.is_some() {
            channels.loaded(
                ChannelName::WindowsPush,
                w.config.push.as_ref().map(|p| ("wns".into(), p.revision)),
            )?;
        }
    }
    let mut bound = Vec::new();
    if bind_listeners {
        if let Some(w) = &windows {
            let mut endpoints = vec![
                (
                    crate::native::NativeListenerKind::WindowsEnrollment,
                    w.config.enrollment.listen,
                ),
                (
                    crate::native::NativeListenerKind::WindowsManagement,
                    w.config.management.listen,
                ),
            ];
            endpoints.extend(w.config.additional_management.iter().map(|e| {
                (
                    crate::native::NativeListenerKind::WindowsManagement,
                    e.listen,
                )
            }));
            match bind_native(&endpoints).await {
                Ok(listeners) => {
                    bound.extend(listeners);
                    channels.listening(ChannelName::Windows)?;
                }
                Err(_) => {
                    channels.set(
                        ChannelName::Windows,
                        ChannelState::Degraded,
                        Some(Reason::ListenerUnavailable),
                    )?;
                    windows = None;
                }
            }
        }
        if let Some(a) = &apple {
            match bind_native(&[(
                crate::native::NativeListenerKind::AppleManagement,
                a.config.management.listen,
            )])
            .await
            {
                Ok(listeners) => {
                    bound.extend(listeners);
                    channels.listening(ChannelName::Apple)?;
                }
                Err(_) => {
                    channels.set(
                        ChannelName::Apple,
                        ChannelState::Degraded,
                        Some(Reason::ListenerUnavailable),
                    )?;
                    apple = None;
                }
            }
        }
        if let Some(a) = &agent_pki {
            match bind_native(&[(crate::native::NativeListenerKind::Agent, a.listen)]).await {
                Ok(listeners) => {
                    bound.extend(listeners);
                    channels.listening(ChannelName::Agent)?;
                }
                Err(_) => {
                    channels.set(
                        ChannelName::Agent,
                        ChannelState::Degraded,
                        Some(Reason::ListenerUnavailable),
                    )?;
                    agent_pki = None;
                }
            }
        }
    }
    let mut trusts = Vec::new();
    if let Some(w) = &windows {
        trusts.push(w.channel.ca.trust.clone());
    }
    if let Some(a) = &apple {
        trusts.push(a.channel.device_trust().clone());
    }
    if let Some(a) = &agent_pki {
        trusts.push(a.issuer.trust().trust.clone());
        if let Some(bootstrap) = &a.bootstrap {
            trusts.push(bootstrap.trust.clone());
        }
    }
    let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        access.archive_pool(),
        audit_store.clone(),
        trusts,
        providers,
    ));
    let agent_enrollment = agent_pki
        .as_ref()
        .map(|pki| {
            rss_mdm_registration_service::agent::Service::new(
                rss_mdm_registration_service::agent::Assembly {
                    tenant: identity.tenant,
                    store: access.registration(),
                    audit: audit_store.clone(),
                    issuer: pki.issuer.clone(),
                    clock: pki.pki_clock.clone(),
                    binding: Arc::new(rss_mdm_agent_channel::Bindings),
                    native: execution.clone(),
                    bootstrap: pki.bootstrap.clone(),
                    origin: pki.origin.clone(),
                    configuration_signer: configuration_signer.clone(),
                    installations: Arc::new(crate::agent_configurations::Installations),
                },
            )
            .map(Arc::new)
            .map_err(Error::from)
        })
        .transpose()?;
    let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
        rss_transactional_messaging::fence::StorageIdentity::new(
            config.flow.storage.target,
            config.flow.storage.lineage,
        )
        .map_err(|_| Error::Malformed)?,
        vec![(
            identity.tenant,
            rss_transactional_messaging::fence::Epoch::new(config.flow.storage.epoch)
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
    )
    .await?;
    #[cfg(test)]
    fixture_webhooks
        .set(webhooks.clone())
        .map_err(|_| Error::Conflict)?;
    let state = Arc::new(Assembly {
        channels,
        telemetry,
        runtime_observation: crate::setup::host::Observation::new(
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
        inputs,
        queries,
        protection,
        #[cfg(test)]
        execution_runtime: _execution_runtime,
        audit_store,
        apple,
        execution,
        flow: planning,
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
    // Existing durable intent only: normal fixtures and non-initialized tenants are never seeded.
    // A failed attempt remains visible and resumes under the same identities after restart.
    #[cfg(test)]
    match tokio::time::timeout(
        std::time::Duration::from_secs(120),
        crate::baseline::resume(&state),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("baseline initialization blocked: {error}"),
        Err(_) => eprintln!(
            "baseline initialization outcome unknown; resume original intent after restart"
        ),
    }
    let mut routers = from_state(state, host, monotonic);
    routers.bound = bound;
    Ok(routers)
}

pub(crate) fn from_state(
    state: Arc<Assembly>,
    host: String,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> crate::native::Routers {
    let apple_state = Arc::new(rss_mdm_apple_channel::HttpState {
        material_roots: state.apple_material_roots.clone(),
        account_authority: rss_mdm_apple_channel::account_enrollment::authority(),
        authentication: rss_mdm_apple_channel::account_enrollment::Authentication {
            authority: state.identity.authority.clone(),
            http: state.identity.browser().http.clone(),
            origin: format!("https://{host}"),
        },
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::MdmApple,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: state.audit_store.clone(),
        access: state.access.apple_store(),
        apple: state.apple.as_ref().map(|a| a.channel.clone()),
        clock: Arc::new(crate::clock::InventoryClock(state.clock.clone())),
        execution: state.execution.clone(),
        protection: state.protection.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                state.identity.authority.clone(),
                state.identity.tenant,
            ),
        ),
        requests: state.requests.clone(),
    });
    let windows_state = Arc::new(rss_mdm_windows_channel::HttpState {
        protection: state.protection.clone(),
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::MdmWindows,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: state.audit_store.clone(),
        access: state.access.windows_store(),
        clock: Arc::new(crate::clock::InventoryClock(state.clock.clone())),
        execution: state.execution.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                state.identity.authority.clone(),
                state.identity.tenant,
            ),
        ),
        requests: state.requests.clone(),
        windows: state.windows.as_ref().map(|w| w.channel.clone()),
    });
    let diagnostics = Arc::new(crate::runtime_diagnostics::RuntimeDiagnostics {
        channels: state.channels.clone(),
        apple_store: state.access.apple_store(),
        access: state.access.archive_pool(),
        telemetry: state.telemetry.clone(),
        execution: state.execution.clone(),
        inventory: state.inventory.clone(),
        identity_audit: state.identity.audit_readiness.clone(),
        apple: state.apple.clone(),
        clock: state.clock.clone(),
        planning: state.flow.planning.clone(),
        tenant: state.identity.tenant,
        instance: state.identity.instance.to_string(),
    });
    let bearer = state
        .identity
        .bearer_routes()
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::new(rss_mdm_management_http::api_access::BearerAdmission {
                access: state.access.authorization_store(),
                tenant: state.identity.tenant.to_string(),
            }),
            rss_mdm_management_http::api_access::admit_bearer,
        ));
    let authentication = state.identity.routes().merge(bearer);
    let admission = Arc::new(tokio::sync::Semaphore::new(32));
    let management_boundary = rss_mdm_management_http::boundary::Envelope {
        admission: admission.clone(),
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let apple_boundary = rss_mdm_apple_channel::boundary::Envelope {
        admission: admission.clone(),
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let windows_browser_boundary = rss_mdm_windows_channel::boundary::Envelope {
        admission: admission.clone(),
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let agent_boundary = rss_mdm_agent_channel::boundary::Envelope {
        admission,
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let authentication =
        rss_mdm_management_http::authentication_routes(authentication, management_boundary.clone());
    let directory = crate::settings::Directory {
        state: state.clone(),
        apple: apple_state.clone(),
    };
    let settings: Arc<dyn rss_mdm_management_http::settings::Source> = Arc::new(directory.clone());
    let channels: Arc<dyn rss_mdm_management_http::enrollment::channels::Source> =
        Arc::new(crate::registration_channels::Channels {
            preparation: state.channels.clone(),
            windows: state.windows.clone(),
            agent: state.agent_pki.clone(),
            apple: state.apple.clone(),
            pki: state.pki.clone(),
            clock: state.clock.clone(),
        });
    let first_use = Arc::new(crate::first_use::FirstUse {
        directory,
        channels: channels.clone(),
    });
    let tenant_administration = rss_mdm_management_http::tenant_administration::router(
        Arc::new(
            rss_mdm_management_http::authorization::http::AuthenticationState {
                identity: state.identity.management_browser(),
                access: state.access.authorization_store(),
                requests: state.requests.clone(),
            },
        ),
        crate::tenant_registry::http::routes(state.identity.tenant_administration.clone()),
        settings.clone(),
        state.identity_management.clone(),
        rss_mdm_management_http::boundary::Envelope {
            tenant: state.identity.management_tenant.to_string(),
            ..management_boundary.clone()
        },
    );
    let apple_management = rss_mdm_management_http::boundary::wrap(
        rss_mdm_apple_channel::management_routes(apple_state.clone())
            .route_layer(middleware::from_fn(apple_management_settlement))
            .route_layer(middleware::from_fn_with_state(
                Arc::new(
                    rss_mdm_management_http::authorization::http::AuthenticationState {
                        identity: state.identity.browser(),
                        access: state.access.authorization_store(),
                        requests: state.requests.clone(),
                    },
                ),
                rss_mdm_management_http::authorization::http::protect,
            )),
        management_boundary.clone(),
    );
    let wns_management = rss_mdm_management_http::boundary::wrap(
        rss_mdm_windows_channel::wns_materials::routes(windows_state.clone()).route_layer(
            middleware::from_fn_with_state(
                Arc::new(
                    rss_mdm_management_http::authorization::http::AuthenticationState {
                        identity: state.identity.browser(),
                        access: state.access.authorization_store(),
                        requests: state.requests.clone(),
                    },
                ),
                rss_mdm_management_http::authorization::http::protect,
            ),
        ),
        management_boundary.clone(),
    );
    let management = rss_mdm_management_http::router(
        rss_mdm_management_http::Services {
            first_use,
            user_profiles: Arc::new(crate::user_profiles::Backend {
                identity: state.identity.authority.clone(),
                tenant: state.identity.tenant,
                instance: state.identity.instance,
                audit: state.audit_store.clone(),
            }),
            mail: Arc::new(rss_mdm_mail_service::authority::Authority {
                tenant: state.identity.tenant,
                protection: state.protection.clone(),
                audit: state.audit_store.clone(),
            }),
            settings,
            webhooks: state.webhooks.clone(),
            telemetry: state.telemetry.clone(),
            registration_channels: channels,
            windows_entra: state
                .windows
                .as_ref()
                .and_then(|w| w.channel.entra.as_ref())
                .map(|_| {
                    Arc::new(
                        rss_mdm_registration_service::windows_entra::Management::new(
                            state.access.registration(),
                            state.audit_store.clone(),
                            state.identity.tenant,
                        ),
                    )
                }),
            agent_enrollment: state.agent_enrollment.clone(),
            pki: state.pki.clone(),
            pki_clock: Arc::new(crate::agent_pki::PkiClock(state.clock.clone())),
            recovery_credentials: state.execution.recovery_credentials().map(|p| {
                Arc::new(rss_mdm_recovery_credentials::Credentials::new(
                    state.access.archive_pool(),
                    state.audit_store.clone(),
                    p.keys.clone(),
                ))
            }),
            certificate_archive: state.certificate_archive.clone(),
            timeline: state.timeline.clone(),
            associations: state.associations.clone(),
            diagnostics: diagnostics.clone(),
            identity: state.identity.browser(),
            authorization: state.access.authorization_store(),
            identity_management: state.identity_management.clone(),
            requests: state.requests.clone(),
            audit_store: state.audit_store.clone(),
            planning: state.flow.planning.clone(),
            groups: state.flow.groups.clone(),
            compliance: state.flow.compliance.clone(),
            execution: state.execution.clone(),
            queries: state.queries.clone(),
            policies: Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(
                &state.flow.cursor_key,
                state.flow.runtime.clone(),
                state.audit_store.clone(),
                state.identity.tenant,
                state.flow.planning.policy_store.clone(),
                state.inputs.clone(),
            )),
            assets: state.flow.assets.clone(),
            catalog: state.flow.catalog.clone(),
            publications: state.flow.publications.clone(),
            software_catalog: software_access(&state),
            storage_connections: Arc::new(
                rss_mdm_content_service::connections::authority::Authority {
                    tenant: state.identity.tenant,
                    protection: state.protection.clone(),
                    audit: state.audit_store.clone(),
                },
            ),
            content: Arc::new(rss_mdm_content_service::service::Access {
                sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
                    state.identity.authority.clone(),
                    state.identity.tenant,
                ),
                authorization: state.access.authorization_store(),
                catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(
                    state.identity.tenant,
                )),
                runtime: state.flow.runtime.clone(),
                audit_store: state.audit_store.clone(),
                tenant: state.identity.tenant,
                content: state.content_writer.clone(),
                clock: Arc::new(crate::clock::ContentClock(state.clock.clone())),
            }),
            enrollment_progress: Arc::new(crate::enrollment_progress::EnrollmentProgress {
                sessions: apple_state.identity.clone(),
                windows: state.windows.as_ref().map(|w| w.channel.clone()),
                apple: state.apple.as_ref().map(|a| a.channel.clone()),
            }),
            enrollment: Arc::new(
                rss_mdm_registration_service::enrollment::EnrollmentService::new(
                    state.access.registration(),
                    state.credentials.clone(),
                    state.audit_store.clone(),
                ),
            ),
            devices: state.devices.clone(),
            windows: state.windows.is_some(),
            apple: state.apple.is_some(),
        },
        management_boundary,
    );
    let mut listeners = Vec::new();
    if let Some((enrollment, planning)) = crate::windows::routers(
        state.windows.as_deref(),
        windows_state.clone(),
        monotonic.clone(),
    ) {
        listeners.push((
            crate::native::NativeListenerKind::WindowsEnrollment,
            enrollment,
        ));
        listeners.extend(
            planning
                .into_iter()
                .map(|router| (crate::native::NativeListenerKind::WindowsManagement, router)),
        );
    }
    if let Some(apple) = crate::apple::router(
        state.apple.as_deref(),
        apple_state.clone(),
        monotonic.clone(),
    ) {
        listeners.push((crate::native::NativeListenerKind::AppleManagement, apple));
    }
    if let (Some(pki), Some(service)) = (&state.agent_pki, &state.agent_enrollment) {
        let mut envelope = agent_boundary;
        envelope.host = pki.origin.trim_start_matches("https://").to_string();
        let runtime = rss_mdm_agent_channel::router(
            Arc::new(crate::agent::HttpState {
                content: state.content_writer.clone(),
                enrollment: service.clone(),
                audit_store: state.audit_store.clone(),
                access: Arc::new(state.access.agent_store()),
                inventory: state.inventory.clone(),
                telemetry: state.telemetry.clone(),
            }),
            envelope.clone(),
        )
        .merge(rss_mdm_agent_channel::task_router(
            Arc::new(crate::agent::TaskState {
                identity: Arc::new(
                    rss_mdm_authorization_service::session::SessionAuthority::new(
                        state.identity.authority.clone(),
                        state.identity.tenant,
                    ),
                ),
                authorization: state.access.authorization_store(),
                enrollment: service.clone(),
                access: Arc::new(state.access.agent_store()),
                execution: state.execution.clone(),
            }),
            envelope.clone(),
        ));
        let router = Router::new().nest("/api/v1/agent/runtime", runtime).nest(
            "/api/v1/agent/enroll",
            rss_mdm_agent_channel::enroll::router(service.clone(), envelope.clone())
                .merge(rss_mdm_agent_channel::installation_router(
                    state.execution.clone(),
                    envelope.clone(),
                ))
                .merge(rss_mdm_agent_channel::boundary::wrap_enroll(
                    rss_mdm_management_http::software_catalog::agent_packages_public(
                        software_access(&state),
                    ),
                    envelope,
                )),
        );
        listeners.push((
            crate::native::NativeListenerKind::Agent,
            crate::native::TlsRouter {
                listen: pki.listen,
                tls: pki.tls.clone(),
                router,
                admission: crate::native::admission::Admission::new(
                    monotonic.clone(),
                    state.requests.clone(),
                    "agent-tls",
                ),
            },
        ));
    }
    let apple = state.apple.clone();
    let host_routes = Router::new()
        .route("/livez", get(|| async { Json(json!({"alive":true})) }))
        .route(
            "/readyz",
            get(ready).with_state((
                diagnostics,
                monotonic.clone(),
                state.runtime_observation.clone(),
            )),
        )
        .fallback(|| async { axum::http::StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(
            host,
            crate::http_host::guard,
        ));
    let browser = Router::new()
        .merge(tenant_administration)
        .merge(management)
        .merge(wns_management)
        .merge(apple_management)
        .merge(rss_mdm_apple_channel::browser_routes(
            apple_state.clone(),
            apple_boundary,
        ))
        .merge(rss_mdm_windows_channel::entra::browser_routes(
            windows_state,
            windows_browser_boundary,
        ))
        .merge(authentication)
        .merge(host_routes)
        .merge(
            rss_mdm_management_http::software_native::routes().with_state(Arc::new(
                rss_mdm_management_http::software_native::StateData {
                    directory: state.flow.publications.clone(),
                    content: state.content_writer.clone(),
                    requests: state.requests.clone(),
                },
            )),
        )
        .layer(DefaultBodyLimit::max(16384));
    crate::native::Routers {
        baseline: crate::baseline::registration(state.clone()),
        telemetry: state.telemetry.clone(),
        webhooks: state.webhooks.clone(),
        apple_control: apple_state,
        pki: state.pki.clone(),
        agent_pki: state.agent_pki.clone(),
        windows: state.windows.clone(),
        apple,
        browser,
        listeners,
        bound: Vec::new(),
    }
}

async fn ready(
    State((diagnostics, clock, observation)): State<(
        Arc<crate::runtime_diagnostics::RuntimeDiagnostics>,
        Arc<dyn rss_observation::Clock>,
        crate::setup::host::Observation,
    )>,
) -> Response {
    let result = diagnostics
        .collect(clock.now() + std::time::Duration::from_secs(8), false)
        .await;
    let status = if result.ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({"ready":result.ready,"observation":observation})),
    )
        .into_response()
}

#[cfg(test)]
#[path = "../tests/api/mod.rs"]
pub(crate) mod t2;

pub(crate) fn software_access(
    state: &Assembly,
) -> Arc<
    rss_mdm_software_service::management::catalog::Access<
        rss_mdm_content_service::software::SoftwareContent,
    >,
> {
    Arc::new(rss_mdm_software_service::management::catalog::Access {
        resources: state.flow.software_resources.clone(),
        clock: Arc::new(crate::clock::ContentClock(state.clock.clone())),
        runtime: state.flow.runtime.clone(),
        audit: state.audit_store.clone(),
        tenant: state.identity.tenant,
        catalog: rss_mdm_software_service::catalog::Catalog::new(
            state.flow.runtime.clone(),
            state.identity.tenant,
            state.audit_store.clone(),
        ),
        content: state.content_writer.as_ref().map(|store| {
            Arc::new(rss_mdm_content_service::software::SoftwareContent::new(
                store.clone(),
                Arc::new(crate::clock::ContentClock(state.clock.clone())),
            ))
        }),
        imports: rss_mdm_software_service::management::catalog::ImportConfig {
            sources: state
                .content_writer
                .as_ref()
                .map(|s| s.config.imports.clone())
                .unwrap_or_default(),
            transfer_seconds: state
                .content_writer
                .as_ref()
                .map_or(0, |s| s.config.transfer_seconds),
        },
    })
}

/// Compose the Apple business owner's settlement class with the common HTTP boundary.
async fn apple_management_settlement(
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    use rss_mdm_apple_channel::{Error as AppleError, Failure as AppleFailure};
    use rss_mdm_audit_integration::completion::ResponseFailure;
    let mut response = next.run(request).await;
    let failure = match response.extensions().get::<AppleError>() {
        Some(AppleError::CommitUnknown) => Some(ResponseFailure::CommitUnknown),
        Some(AppleError::RollbackFailed) => Some(ResponseFailure::RollbackFailed),
        Some(AppleError::Unauthorized | AppleError::Forbidden) => Some(ResponseFailure::Denied),
        Some(AppleError::Unavailable(AppleFailure::RequestDeadline)) => {
            Some(ResponseFailure::Deadline)
        }
        Some(AppleError::Unavailable(AppleFailure::AuditIntegrity)) => {
            Some(ResponseFailure::AuditIntegrity)
        }
        Some(AppleError::Unavailable(
            AppleFailure::AuditContract
            | AppleFailure::AuditIsolation
            | AppleFailure::AuditAdmission,
        )) => Some(ResponseFailure::AuditContract),
        Some(AppleError::Unavailable(AppleFailure::Audit)) => {
            Some(ResponseFailure::AuditUnavailable)
        }
        _ => None,
    };
    if let Some(failure) = failure {
        response.extensions_mut().insert(failure);
    }
    response
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

#[cfg(test)]
#[path = "../tests/api/diagnostics.rs"]
mod tests;

/// Locally owned sockets are dropped together if any bind in this channel fails.
async fn bind_native(
    endpoints: &[(crate::native::NativeListenerKind, std::net::SocketAddr)],
) -> std::io::Result<Vec<(crate::native::NativeListenerKind, tokio::net::TcpListener)>> {
    let mut listeners = Vec::new();
    for (kind, address) in endpoints {
        listeners.push((*kind, tokio::net::TcpListener::bind(address).await?));
    }
    Ok(listeners)
}

#[cfg(test)]
mod binding_tests {
    #[tokio::test]
    async fn partial_channel_binding_releases_every_acquired_listener() {
        use crate::native::NativeListenerKind as K;
        let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = free.local_addr().unwrap();
        drop(free);
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(
            super::bind_native(&[
                (K::WindowsEnrollment, first),
                (K::WindowsManagement, occupied.local_addr().unwrap())
            ])
            .await
            .is_err()
        );
        assert!(tokio::net::TcpListener::bind(first).await.is_ok());
    }
}
