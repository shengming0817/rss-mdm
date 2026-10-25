//! Current-user HTTP needs real sessions and device credentials, not software or task trust.
use super::{
    agent_execution::{case_credential, case_device_id},
    http::*,
    runtime::*,
    *,
};
pub(crate) struct Fixture {
    pub(crate) authority: authority::Authority,
    pub(crate) resources: Resources,
    pub(crate) router: Router,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) author: Browser,
    pub(crate) author_id: String,
    pub(crate) grants: Vec<crate::authorization::Grant>,
    pub(crate) enrollment: Arc<rss_mdm_registration_service::agent::Service>,
}
impl Fixture {
    pub(crate) async fn new() -> Result<Self> {
        let base = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        Self::from_config(base).await
    }
    pub(crate) async fn from_config(base: Value) -> Result<Self> {
        let (resources, mut fixture) = Resources::build(move |resources| {
            Box::pin(async move {
                let mut authority = authority::Authority::from_config(base).await?;
                resources.extend(std::mem::take(&mut authority.resources));
                let config: Config = serde_json::from_value(authority.base.clone())?;
                let execution = super::agent_runtime::Execution::open(
                    &mut authority,
                    &config,
                    None,
                    BTreeMap::new(),
                    None,
                    None,
                    resources,
                )
                .await?;
                let enrollment = super::agent_runtime::enrollment(
                    &mut authority,
                    &config,
                    execution.service.clone(),
                )
                .await?;
                let public = super::agent_runtime::routes(
                    &authority,
                    enrollment.clone(),
                    execution.service.clone(),
                );
                let router = resources
                    .native_router(authority.router_with_public(authority.enrollment(), public)?);
                let author = authority.browser("other")?;
                let author_id = prepared_subject(&author)?;
                let grants = super::identity::device_grants(
                    Some(case_device_id()),
                    &["enrollment", "inventory_read"],
                )?;
                super::identity::seed_grants(case_tenant(), &author_id, grants.clone()).await?;
                Ok(Self {
                    authority,
                    resources: Resources::default(),
                    router,
                    author,
                    author_id,
                    grants,
                    enrollment,
                    execution: execution.service,
                })
            })
        })
        .await?;
        fixture.resources = resources;
        Ok(fixture)
    }
    pub(crate) async fn register_profile(&mut self, capabilities: Value) -> Result<Value> {
        let previous = case_device_id();
        let registration = super::agent::seed_unacknowledged(&self.enrollment, case_credential(), previous,
            json!({"capabilities":capabilities,"platform":"macos","architecture":"aarch64",
                "executionContext":super::software_execution::context(super::software_execution::Platform::MacOs)})).await?;
        for grant in &mut self.grants {
            if let crate::authorization::Scope::Device { id } = &mut grant.scope
                && id == previous
            {
                *id = registration["deviceId"].as_str().unwrap().into();
            }
        }
        super::identity::seed_grants(case_tenant(), &self.author_id, self.grants.clone()).await?;
        Ok(registration)
    }
}
