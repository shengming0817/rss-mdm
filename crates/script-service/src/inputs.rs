//! Script publication uses exact Resource material and the initiating runtime.
use crate::{
    Error, Parameters, Result, checked_input,
    transaction::{checked, inspect},
};
use rss_mdm_content_service::{StorageClass, Store, Verified};
use rss_mdm_policy::{Architecture, ExactResourceBinding, Frequency, Platform, schedule::Schedule};
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;

pub struct Inputs {
    runtime: Arc<PgRuntime>,
    tenant: rss_request_context::TenantId,
    content: Option<Arc<Store>>,
    signing_enabled: bool,
}
pub struct Publication<'a> {
    pub binding: &'a ExactResourceBinding,
    pub parameters: Parameters<'a>,
    pub schedule: &'a Schedule,
    pub frequency: Frequency,
    pub lifetime: u32,
}
impl Inputs {
    pub fn bind(
        runtime: Arc<PgRuntime>,
        tenant: rss_request_context::TenantId,
        content: Option<Arc<Store>>,
        signing_enabled: bool,
    ) -> Self {
        Self {
            runtime,
            tenant,
            content,
            signing_enabled,
        }
    }
    fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        if !self.signing_enabled {
            return Err(Error::Conflict.into());
        }
        Ok(())
    }
    pub async fn prepare_resource(
        &self,
        binding: &ExactResourceBinding,
        parameters: Parameters<'_>,
    ) -> std::result::Result<Verified, Error> {
        let artifact = inspect(
            &self.runtime,
            self.tenant,
            (self, binding, parameters),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, binding, parameters) = *ctx;
                    let version = service.version_in(tx, binding).await?;
                    Ok(select(&version, binding, parameters)?.artifact().clone())
                })
            },
        )
        .await?;
        let content = self.content.as_ref().ok_or(Error::Unavailable)?;
        Ok(content
            .verify_class(
                &artifact,
                StorageClass::Artifact,
                content.upload_budget()?.operation_deadline(),
            )
            .await?)
    }
    async fn version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &ExactResourceBinding,
    ) -> Result<r::Version> {
        self.validate_in(tx)?;
        let identity = binding.identity();
        let (version, state) = checked(
            rss_mdm_resource_postgres::lock_reference_in(
                tx,
                &checked_input(r::Id::new(identity.id()))?,
                &checked_input(r::Id::new(identity.version()))?,
            )
            .await?,
        )?;
        if state != r::State::Active {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Publication<'_>,
        verified: &Verified,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        snapshot: &rss_mdm_authorization_service::Snapshot,
    ) -> Result<crate::policy::Published> {
        self.validate_in(tx)?;
        snapshot.require_all_devices(
            proof,
            rss_mdm_authorization_service::Permission::ScriptExecute,
        )?;
        let version = self.version_in(tx, input.binding).await?;
        let selected = select(&version, input.binding, input.parameters)?;
        if !verified.matches(selected.artifact()) {
            return Err(Error::Conflict.into());
        }
        Ok(crate::policy::Published {
            action: Box::new(
                crate::preparation::freeze_in(
                    tx,
                    self.tenant,
                    &selected,
                    input.parameters.checked(selected.definition())?,
                    input.schedule.clone(),
                    input.lifetime,
                )
                .await?,
            ),
            frequency: input.frequency,
        })
    }
}
pub fn select<'a>(
    version: &'a r::Version,
    binding: &ExactResourceBinding,
    parameters: Parameters<'_>,
) -> Result<r::SelectedScript<'a>> {
    let selected = checked_input(version.select_script(
        match binding.platform {
            Platform::Windows => r::Platform::Windows,
            Platform::Macos => r::Platform::MacOS,
        },
        match binding.architecture {
            Architecture::X86_64 => r::Architecture::X86_64,
            Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        &checked_input(r::Id::new(&binding.variant))?,
    ))?;
    parameters.checked(selected.definition())?;
    Ok(selected)
}
