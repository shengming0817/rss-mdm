//! Successful command preparation; behavioral assertions live in their owning module.
use super::*;
use crate::test_support::Browser;
use anyhow::ensure;
use axum::{
    Router,
    http::{Method, StatusCode},
};
use serde_json::{Value, json};
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
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
        let mut browser = Browser::default();
        let login = browser
            .call(
                &router,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/login", TENANT = case_tenant()),
                Some(json!({"login":crate::test_support::case::login("admin"),"password":crate::test_support::identity::PASSWORD})),
            )
            .await?;
        ensure!(
            login.0 == StatusCode::OK,
            "real planning login: {:?}",
            login
        );
        Ok(Self {
            browser,
            router,
            app,
            operation: Uuid::new_v4(),
            rule: Uuid::new_v4(),
            rule_revision: 0,
        })
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
                    "/api/v2/devices/{DEVICE}/operations{suffix}",
                    DEVICE = case_device()
                ),
                body,
            )
            .await
    }
    pub(crate) async fn set_authorized(&mut self, enabled: bool) -> anyhow::Result<()> {
        let mut permissions = vec!["operation_read", "operation_cancel"];
        if enabled {
            permissions.push("state_verify");
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
        let result = rss_mdm_flow_service::transaction::run(
            &service.audit_store,
            &service.runtime,
            service.tenant,
            &audit,
            (service, id),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, id) = *ctx;
                    let operation = storage::load(tx, id).await?;
                    let _page = service
                        .store
                        .recover(tx, operation.scope, dc::BatchLimit::new(64).unwrap(), None)
                        .await?;
                    Ok(())
                })
            },
            rss_mdm_flow_service::transaction::TransactionOwner::Execution,
        )
        .await;
        audit.finalize(None);
        result?;
        Ok(())
    }
    pub(crate) async fn accept_approved(&mut self) -> anyhow::Result<()> {
        self.set_authorized(true).await?;
        let request = json!({"operationId":self.operation,"task":{"kind":"state_verify","field":"model","expectedValue":"Final-Model"},"deadline":self.app.clock.unix_seconds()?+300});
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
pub(crate) async fn ordinary() -> anyhow::Result<(crate::windows::test_support::Host, Client)> {
    let host = crate::windows::test_support::Host::open().await?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let credential =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 91);
    crate::device::test_support::bind(&host.app.devices, &proof, &credential, case_device(), 0)
        .await?;
    let client = Client::start(host.browser.clone(), host.app.clone()).await?;
    Ok((host, client))
}
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "subprocess killed by command T2 after confirmed PG acceptance"]
async fn relay_crash_child() -> anyhow::Result<()> {
    use rss_transactional_messaging::{outbox::OutboxRelayStore, policy::DeliveryBudget};
    let config = crate::test_support::identity::config(case_tenant())?;
    let service = Box::pin(crate::flow::execution::open(
        &config,
        crate::test_support::identity::audit_store(&config).await?,
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
        let digest = message.fingerprint().as_bytes().to_vec();
        service.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitAcknowledgedPending,
        );
        service.accept_dispatch(id, digest).await?;
    }
    anyhow::bail!("parent must kill before completion")
}
