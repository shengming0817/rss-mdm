//! Real settings read owners, without Flow, Inventory, content or command execution.
use super::{runtime::*, *};

pub(crate) async fn directory(f: &mut authority::Authority) -> Result<crate::settings::Directory> {
    let config: Config = serde_json::from_value(f.base.clone())?;
    let tenant = f.identity.tenant;
    let clock = Arc::new(crate::clock::SystemClock);
    let protection = config.native_protector()?;
    let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_flow_runtime").await;
    f.resources.resource(SourceResource(runtime.clone()));
    let webhook_runtime =
        crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    f.resources
        .resource(SourceResource(webhook_runtime.clone()));
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    let binding = ExecutionBinding::new(
        StorageIdentity::new(config.flow.storage.target, config.flow.storage.lineage)?,
        vec![(tenant, Epoch::new(config.flow.storage.epoch)?)],
    )?;
    let webhooks = crate::webhooks::Backend::open(
        config.webhooks,
        webhook_runtime,
        tenant,
        f.audit.clone(),
        clock.clone(),
        protection.clone(),
        binding,
        rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?,
    )
    .await?;
    f.resources
        .resource(crate::webhooks::Resource(webhooks.clone()));
    let signing_key = match config.task_signing.as_ref() {
        Some(selection) => Some(
            crate::task_signing::open(selection, &config.access_database, tenant, &protection)
                .await?
                .task
                .key_id()
                .to_owned(),
        ),
        None => None,
    };
    Ok(crate::settings::Directory {
        tenant,
        management_tenant: f.identity.management_tenant,
        identity: f.identity.authority.clone(),
        federation: f.identity.federation.clone(),
        tenant_administration: f.identity.tenant_administration.clone(),
        user_profiles: Arc::new(crate::user_profiles::Backend {
            cursor: rss_mdm_query::cursor::CursorCodec::new(&[29; 32])?,
            identity: f.identity.authority.clone(),
            tenant,
            instance: f.identity.instance,
            audit: f.audit.clone(),
        }),
        audit: f.audit.clone(),
        clock,
        protection,
        pki: Arc::new(rss_mdm_pki_service::registry::Registry::new(
            f.pool.clone(),
            f.audit.clone(),
            vec![],
            crate::device_pki::providers(&[])?,
        )),
        software_runtime: runtime,
        registration: None,
        webhooks,
        windows: Arc::new(rss_mdm_windows_channel::Store::from_pool(
            f.pool.clone(),
            f.registration.clone(),
            f.authorization.clone(),
        )),
        windows_loaded: false,
        windows_push_revision: None,
        apple_materials: None,
        content: None,
        signing_key,
        recovery: None,
        apple_store: Arc::new(rss_mdm_apple_channel::Store::from_pool(
            f.pool.clone(),
            f.registration.clone(),
            f.authorization.clone(),
        )),
        apple: None,
    })
}

pub(crate) fn catalog(
    f: &authority::Authority,
    directory: crate::settings::Directory,
) -> Result<Router> {
    let source: Arc<dyn rss_mdm_management_http::settings::Source> = Arc::new(directory);
    let catalog = rss_mdm_management_http::settings::routes(source.clone());
    let management = rss_mdm_management_http::tenant_administration::router(
        Arc::new(crate::authorization::http::AuthenticationState {
            identity: f.identity.management_browser(),
            access: f.authorization.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(32)),
        }),
        crate::tenant_registry::http::mount_registry(None, false),
        source,
        Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?,
        ),
        rss_mdm_management_http::boundary::Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            requests: Arc::new(tokio::sync::Semaphore::new(32)),
            host: "mdm.example.test".into(),
            clock: monotonic(),
            audit_store: f.audit.clone(),
            tenant: f.identity.management_tenant.to_string(),
        },
        rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?,
    )
    .into_axum();
    Ok((f.router({
 rss_mdm_http_contract::route_module! { struct CatalogModule1 for [Browser] { api_v1 at "/api/v1" } }
 CatalogModule1 { api_v1: catalog }.assemble()
})?).merge(management))
}
