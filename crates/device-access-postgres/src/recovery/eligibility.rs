//! Current DA qualification adapter; Recovery owns material lifecycle and transaction settlement.
use crate::device_access as access;
use rss_mdm_recovery_credentials::{
    Binding, Error, Material, Subject,
    eligibility::{Eligibility, Pending, Retention},
};
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;

pub struct AccessEligibility {
    pub admission: Option<Arc<dyn access::Admission>>,
}
impl Eligibility for AccessEligibility {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile {
        rss_mdm_install_support::StorageProfile::Da
    }
    fn active<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        binding: &'a Binding,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let Subject::RssLogin {
                binding: id,
                binding_generation,
                sid,
            } = &binding.subject
            else {
                return Err(Error::Unsupported);
            };
            let b = access::storage::locked_in(c, tenant, *id)
                .await
                .map_err(super::custody_error)?;
            if b.generation != *binding_generation
                || b.state == rss_mdm_device_access::State::Revoked
                || b.device != binding.device
                || b.registration != binding.registration
                || b.registration_generation != binding.generation
                || !matches!(&b.account, Some(rss_mdm_agent_wire::runtime::AccessAccount::Windows { sid: current, .. }) if current == sid)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        })
    }
    fn disclose<'a>(
        &'a self,
        c: &'a mut PgConnection,
        principal: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
        binding: &'a Binding,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if principal.profile() != rss_mdm_install_support::StorageProfile::Da {
                return Err(Error::Forbidden);
            }
            let tenant = Uuid::parse_str(principal.tenant_id()).map_err(|_| Error::Malformed)?;
            self.active(c, tenant, binding).await?;
            let Subject::RssLogin {
                binding: id,
                binding_generation,
                ..
            } = binding.subject
            else {
                return Err(Error::Unsupported);
            };
            let current = access::storage::locked_in(c, tenant, id)
                .await
                .map_err(super::custody_error)?;
            let selection = self
                .admission
                .as_ref()
                .ok_or(Error::Unsupported)?
                .policy(c, tenant, &binding.device, current.policy)
                .await
                .map_err(super::custody_error)?;
            access::lifecycle::require_subject_on(c, tenant, &current.person)
                .await
                .map_err(super::custody_error)?;
            let subject = rss_identity_postgres::platform::PlatformBinding {
                instance: rss_identity_core::InstanceId::parse(
                    &current.person.instance.to_string(),
                )
                .map_err(|_| Error::Integrity)?,
                account: rss_identity_core::account::AccountKey {
                    tenant: rss_request_context::TenantId::parse(principal.tenant_id())
                        .map_err(|_| Error::Integrity)?,
                    principal: rss_identity_core::PrincipalId::parse(
                        &current.person.principal.to_string(),
                    )
                    .map_err(|_| Error::Integrity)?,
                },
                binding_id: current.id,
                binding_epoch: current.generation,
                source_id: current.id,
                source_version: current.generation,
                external_identity: None,
            };
            rss_identity_postgres::platform::admit_platform_subject_on(
                c,
                subject.instance,
                &subject,
                None,
            )
            .await
            .map_err(|e| match e {
                rss_identity_postgres::platform::PlatformSubjectAdmissionError::Rejected => {
                    Error::Forbidden
                }
                _ => Error::Storage,
            })?;
            if current.state == rss_mdm_device_access::State::Revoked
                || current.generation != binding_generation
                || !selection.configuration.enabled
                || selection.version != current.policy_version
            {
                return Err(Error::Forbidden);
            }
            Ok(())
        })
    }
}
impl Retention for AccessEligibility {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile {
        rss_mdm_install_support::StorageProfile::Da
    }
    fn releasable<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        material: &'a Material,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let Subject::RssLogin { binding, .. } = material.binding.subject else {
                return Err(Error::Unsupported);
            };
            let b = access::storage::locked_observation_in(c, tenant, binding)
                .await
                .map_err(super::custody_error)?;
            Ok(b.applied_revision == Some(b.revision)
                && matches!(
                    b.effect,
                    Some(rss_mdm_agent_wire::runtime::AccessEffect::Unbound { .. })
                ))
        })
    }
}
