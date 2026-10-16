//! Successful command preparation; behavioral assertions live in their owning module.
use crate::test_support::Browser;
use anyhow::ensure;
use axum::{
    Router,
    http::{Method, StatusCode},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_execution_service::{deadline, messaging_domain};
use rss_transactional_messaging_postgres::PgOutboxStore;
use serde_json::{Value, json};
pub(crate) use std::{sync::Arc, time::Duration};
pub(crate) use uuid::Uuid;
#[path = "support/configuration.rs"]
pub(crate) mod configuration;
#[path = "support/native.rs"]
pub(crate) mod native;
pub(crate) fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
pub(crate) fn case_device() -> &'static str {
    crate::test_support::case::name("tls-device")
}
pub(crate) struct Client {
    pub(crate) browser: Browser,
    pub(crate) router: Router,
    pub(crate) app: Arc<crate::api::Assembly>,
    pub(crate) operation: Uuid,
    rule: Uuid,
    rule_revision: u64,
}
impl Client {
    pub(crate) async fn start(
        router: Router,
        app: Arc<crate::api::Assembly>,
    ) -> anyhow::Result<Self> {
        let secret = crate::test_support::identity::credential_for(case_tenant(), "admin")?;
        Ok(Self::with_browser(
            router,
            app,
            Browser {
                cookies: std::collections::BTreeMap::from([(
                    "__Host-identity-session".into(),
                    secret.expose().into(),
                )]),
                csrf: Some(secret.csrf()),
                ..Browser::default()
            },
        ))
    }

    pub(crate) fn with_browser(
        router: Router,
        app: Arc<crate::api::Assembly>,
        browser: Browser,
    ) -> Self {
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse().expect("fixture address"),
        )));
        Self {
            browser,
            router,
            app,
            operation: Uuid::new_v4(),
            rule: Uuid::new_v4(),
            rule_revision: 0,
        }
    }
    pub(crate) async fn call(
        &mut self,
        method: Method,
        suffix: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        self.browser
            .call(
                &self.router,
                method,
                &format!(
                    "/api/v1/devices/{DEVICE}/operations{suffix}",
                    DEVICE = case_device()
                ),
                body,
            )
            .await
    }
    pub(crate) async fn set_authorized(&mut self, enabled: bool) -> anyhow::Result<()> {
        let mut permissions = vec!["operation_read", "operation_cancel"];
        if enabled {
            permissions.push("device_control");
        }
        let grants: Vec<_> = permissions
            .iter()
            .map(|p| json!({"operation":p,"scope":{"kind":"device","id":case_device()}}))
            .collect();
        let value = json!({"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants});
        let response=self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",self.rule),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":self.rule_revision,"value":value}))).await?;
        ensure!(response.0 == StatusCode::OK, "grant update {:?}", response);
        self.rule_revision += 1;
        Ok(())
    }
    pub(crate) async fn publish_operation(&self, id: Uuid) -> anyhow::Result<()> {
        for _ in 0..16 {
            self.app.execution.relay_once().await?;
        }
        let audit = RequestAudit::new(case_tenant().into(), "management_read");
        let service = self.app.execution.as_ref();
        let result = service.recover_operation(id, &audit).await;
        audit.finalize(None);
        result?;
        Ok(())
    }
    pub(crate) async fn known_windows_capability(&self, device: &str) -> anyhow::Result<()> {
        use sqlx::Connection;
        let mut c =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("INSERT INTO mdm_commands.capabilities(tenant_id,registration,generation,os_version,edition,session,observed_at) SELECT tenant_id,id,generation,'10.0.22621.0',48,1,floor(extract(epoch FROM clock_timestamp()))::bigint FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND purpose='primary' AND channel='mdm' AND state='active' ON CONFLICT(tenant_id,registration) DO NOTHING")
            .bind(case_tenant()).bind(device).execute(&mut c).await?;
        c.close().await?;
        Ok(())
    }
    pub(crate) async fn accept_approved(&mut self) -> anyhow::Result<()> {
        self.set_authorized(true).await?;
        let request = json!({"operationId":self.operation,"action":{"kind":"restart"},"deadline":self.app.clock.unix_seconds()?+300});
        ensure!(self.call(Method::POST, "", Some(request)).await?.0 == StatusCode::ACCEPTED);
        ensure!(
            self.call(
                Method::POST,
                &format!("/{}/approve", self.operation),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::OK
        );
        Ok(())
    }
}
impl Client {
    pub(crate) fn command_worker(
        &self,
        signals: Arc<crate::worker_wake::Signals>,
    ) -> anyhow::Result<rss_runtime::ShutdownStack> {
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = owner.startup()?.commit();
        launch.stage_deferred_task_with_token(
            self.app
                .execution
                .clone()
                .registration(signals.execution())
                .critical(),
        );
        launch.finish();
        Ok(owner)
    }
}
pub(crate) async fn ordinary(
    command_clock: rss_device_command_postgres::CommandClock,
) -> anyhow::Result<(crate::windows::test_support::Host, Client)> {
    let host = crate::windows::test_support::Host::with_agent(None, command_clock).await?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let credential =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 91);
    crate::device::test_support::bind(&host.app.devices, &proof, &credential, case_device(), 0)
        .await?;
    let client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client.known_windows_capability(case_device()).await?;
    Ok((host, client))
}
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "subprocess killed by command T2 after confirmed PG acceptance"]
async fn relay_crash_child() -> anyhow::Result<()> {
    use rss_transactional_messaging::{outbox::OutboxRelayStore, policy::DeliveryBudget};
    let config = crate::test_support::identity::config(case_tenant())?;
    let authority = crate::test_support::authority::Authority::open().await?;
    let service = Box::pin(crate::execution_assembly::open(
        &config,
        config.native_protector()?,
        authority.audit.clone(),
        crate::execution_assembly::open_content(&config, config.native_protector()?).await?,
        std::collections::BTreeMap::new(),
        rss_device_command_postgres::CommandClock::Postgres,
        Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                authority.identity.authority.clone(),
                authority.identity.tenant,
            ),
        ),
    ))
    .await?;
    let relay = PgOutboxStore::<()>::new(
        service.runtime.clone(),
        messaging_domain(),
        DeliveryBudget::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?;
    let claims = relay
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await?;
    ensure!(claims.len() == 1);
    for claim in claims {
        let message = PgOutboxStore::<()>::message(&claim);
        let id = Uuid::parse_str(
            message
                .message_id()
                .as_str()
                .strip_prefix("dispatch.")
                .unwrap(),
        )?;
        ensure!(
            id.to_string() == std::env::var("MDM_CRASH_OPERATION")?,
            "child claimed another operation"
        );
        let digest = message.fingerprint().as_bytes().to_vec();
        service.service.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitAcknowledgedPending,
        );
        service.service.accept_dispatch(id, digest).await?;
    }
    anyhow::bail!("parent must kill before completion")
}
