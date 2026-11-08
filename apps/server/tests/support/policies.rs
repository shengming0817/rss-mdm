//! Real production Policy assembly for composed Scope management tests.
use crate::policy_configuration_t2::fixture;
use crate::{authority_t2_support::Context, planning_t2_support as planning};
use anyhow::Result;
use rss_mdm_policy_service::{
    management::{Change, Policies, View},
    operation::Operation,
};
use std::sync::Arc;
use uuid::Uuid;
pub struct Fixture {
    resources: fixture::Fixture,
    owner: crate::owner_storage::OwnerRuntime,
    pub policies: Arc<Policies>,
}
impl Fixture {
    pub async fn open(c: &Context) -> Result<Self> {
        let resources = fixture::Fixture::open(c, true).await?;
        let owner = planning::owner(c, "mdm_policy_runtime").await?;
        let config = &resources.resources.config;
        let protection = resources.resources.protection.clone();
        let app = crate::assembly::policy::application(
            &owner,
            c.tenant,
            &[7; 32],
            Arc::new(crate::clock::SystemClock),
            protection.clone(),
            None,
        )
        .await?;
        let editor = crate::scopes::editor(
            owner.runtime.clone(),
            c.tenant,
            Arc::new(crate::clock::SystemClock),
            owner.audit.clone(),
            vec![7; 32],
            c.inputs.pool("shared", "mdm_access").await?,
        )
        .await?;
        let policies = crate::assembly::policy::management(
            editor,
            &app,
            Arc::new(rss_mdm_software_service::deployment::Inputs::bind(
                owner.runtime.clone(),
                c.tenant,
                resources.software.materials.inputs.clone(),
            )),
            config.enrollment_entries.clone(),
            &[7; 32],
            None,
            protection,
            true,
            true,
            false,
        )
        .await?;
        Ok(Self {
            resources,
            owner,
            policies,
        })
    }
    pub async fn create(
        &self,
        c: &Context,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        definition: rss_mdm_scope::ScopeDefinition,
    ) -> Result<View> {
        let definition = serde_json::from_value(
            serde_json::json!({"scope":definition,"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}),
        )?;
        Ok(self
            .policies
            .change(
                p,
                Uuid::new_v4(),
                &Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 0,
                    input: Change::Put {
                        definition,
                        enabled: false,
                    },
                },
                &c.request(p)?,
            )
            .await?)
    }
    pub async fn close(self) -> Result<()> {
        drop(self.policies);
        self.owner.runtime.close().await;
        self.resources.close().await
    }
}
