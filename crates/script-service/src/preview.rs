//! Read-only draft preparation; preview never registers a collection or creates a Run.
use crate::{Error, Result};
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_policy::{Architecture, ExactResourceBinding, Platform};
use rss_mdm_resource as r;
pub struct Preview {
    definition: r::ScriptDefinition,
    platform: Platform,
    architecture: Architecture,
}
impl crate::inputs::Inputs {
    pub async fn preview_on(
        &self,
        c: &mut sqlx::PgConnection,
        binding: &ExactResourceBinding,
        parameters: crate::Parameters<'_>,
        verified: &rss_mdm_content_service::Verified,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
    ) -> Result<Preview> {
        if !self.signing_enabled {
            return Err(Error::Conflict.into());
        }
        grant.require_all_devices(proof, Permission::ScriptExecute)?;
        let identity = binding.identity();
        let (version, state) = rss_mdm_resource_postgres::version_facts_on(
            c,
            self.tenant,
            &[(identity.id().into(), identity.version().into())],
        )
        .await?
        .versions
        .pop()
        .flatten()
        .ok_or(Error::NotFound)?;
        if state != r::State::Active {
            return Err(Error::Conflict.into());
        }
        let selected = crate::inputs::select(&version, binding, parameters)?;
        if !verified.matches(selected.artifact()) {
            return Err(Error::Conflict.into());
        }
        rss_mdm_inventory_service::collection::resource_authoring::validate_variant_on(
            c,
            self.tenant,
            selected.variant(),
        )
        .await?;
        Ok(Preview {
            definition: selected.definition().clone(),
            platform: binding.platform,
            architecture: binding.architecture,
        })
    }
}
impl Preview {
    pub async fn eligibility_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        store: std::sync::Arc<dyn crate::agent_facts::Store>,
        target: &crate::Target,
    ) -> Result<crate::eligibility::Eligibility> {
        use crate::eligibility::{self, Eligibility};
        let profile = match self.definition.spec().profile {
            r::ScriptProfile::PowerShell7 => {
                rss_mdm_agent_wire::runtime::ExecutorProfile::PowerShell7
            }
            r::ScriptProfile::PosixSh => rss_mdm_agent_wire::runtime::ExecutorProfile::PosixSh,
            r::ScriptProfile::Bash => rss_mdm_agent_wire::runtime::ExecutorProfile::Bash,
            r::ScriptProfile::Osquery => rss_mdm_agent_wire::runtime::ExecutorProfile::Osquery,
        };
        let state = eligibility::check_on(
            c,
            tenant,
            store.clone(),
            target,
            self.platform,
            self.architecture,
            profile,
        )
        .await?;
        if state != Eligibility::Eligible {
            return Ok(state);
        }
        if let r::ScriptPurpose::Collection { applicability, .. } = &self.definition.spec().purpose
            && !eligibility::collection_requirements_on(
                store.clone(),
                c,
                tenant,
                target,
                applicability,
            )
            .await?
        {
            return Ok(Eligibility::Ineligible);
        }
        let Some(binding) = store
            .binding(c, tenant.to_string(), target.device.clone())
            .await?
        else {
            return Ok(Eligibility::Unknown);
        };
        let platform = match self.platform {
            Platform::Windows => rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
            Platform::Macos => rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
        };
        if rss_mdm_software_service::preparation::execution::identity_target(
            match self.definition.spec().run_as {
                r::RunAs::System => rss_mdm_agent_wire::runtime::ExecutionIdentity::System,
                r::RunAs::LoggedInUser => {
                    rss_mdm_agent_wire::runtime::ExecutionIdentity::LoggedInUser
                }
            },
            platform,
            &binding.execution_context,
        )
        .is_err()
        {
            return Ok(Eligibility::Ineligible);
        }
        Ok(Eligibility::Eligible)
    }
}
