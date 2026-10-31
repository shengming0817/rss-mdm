//! Draft collection validation reads Inventory's catalog and channel eligibility.
use crate::{Error, transaction::Result};
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::Channel;
use rss_mdm_resource as r;
pub enum Preview {
    Agent {
        definition: r::AgentCollectionDefinition,
        platform: rss_mdm_policy::Platform,
        architecture: rss_mdm_policy::Architecture,
    },
    Native(r::NativeCollectionDefinition),
}
impl super::inputs::Inputs {
    pub async fn preview_on(
        &self,
        c: &mut sqlx::PgConnection,
        binding: &rss_mdm_policy::ExactResourceBinding,
        channel: Channel,
        verified: &rss_mdm_content_service::Verified,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
    ) -> Result<Preview> {
        grant.require_all_devices(proof, Permission::InventoryCollect)?;
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
        let selected = super::inputs::select(&version, binding)?;
        if !verified.matches(super::inputs::artifact(selected, channel)?) {
            return Err(Error::Conflict.into());
        }
        crate::collection::resource_authoring::validate_variant_on(c, self.tenant, selected)
            .await?;
        match selected.declaration() {
            r::Declaration::AgentCollection { definition, .. } if channel == Channel::Agent => {
                grant.require_all_devices(proof, Permission::InventorySensitiveRead)?;
                if definition
                    .spec()
                    .mappings
                    .values()
                    .any(|m| m.counter_normalization.is_some())
                {
                    return Err(Error::Malformed.into());
                }
                Ok(Preview::Agent {
                    definition: definition.clone(),
                    platform: binding.platform,
                    architecture: binding.architecture,
                })
            }
            r::Declaration::NativeCollection { definition, .. } if channel == Channel::Mdm => {
                let permissions = self.native.permissions(definition)?;
                if permissions.contains(&Permission::Credentials) {
                    return Err(Error::Forbidden.into());
                }
                for permission in permissions {
                    grant.require_all_devices(proof, permission)?;
                }
                Ok(Preview::Native(definition.clone()))
            }
            _ => Err(Error::Malformed.into()),
        }
    }
    pub async fn eligible_on(
        &self,
        c: &mut sqlx::PgConnection,
        preview: &Preview,
        store: std::sync::Arc<dyn super::agent_facts::Store>,
        target: &super::model::Target,
    ) -> Result<bool> {
        match preview {
            Preview::Agent {
                definition,
                platform,
                architecture,
            } => {
                super::eligibility::check_on(
                    c,
                    self.tenant,
                    store,
                    target,
                    *platform,
                    *architecture,
                    definition,
                )
                .await
            }
            Preview::Native(definition) => {
                self.native
                    .eligible_on(c, self.tenant, target, definition)
                    .await
            }
        }
    }
}
