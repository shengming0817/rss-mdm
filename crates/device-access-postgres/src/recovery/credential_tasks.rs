//! RSS credential task authority. Agent transport never supplies material identity.
use super::eligibility::AccessEligibility;
use rss_mdm_policy::CredentialOperation;
use rss_mdm_recovery_credentials::{
    Binding, Error, Subject,
    eligibility::Pending,
    tasks::{Target, product::Product},
};
use sqlx::PgConnection;
use uuid::Uuid;
impl Product for AccessEligibility {
    fn resolve<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        operation: &'a CredentialOperation,
        target: &'a Target,
    ) -> Pending<'a, Binding> {
        Box::pin(async move {
            let (b, anchor) = qualified(c, tenant, operation).await?;
            let delivery = crate::delivery::for_binding_on(c, &b)
                .await
                .map_err(super::custody_error)?
                .ok_or(Error::Forbidden)?;
            if delivery.device != target.device {
                return Err(Error::Forbidden);
            }
            Ok(anchor)
        })
    }
}

pub(super) async fn qualified(
    c: &mut PgConnection,
    tenant: Uuid,
    operation: &CredentialOperation,
) -> Result<(crate::device_access::Binding, Binding), Error> {
    let (CredentialOperation::RotateRssLogin {
        binding,
        binding_generation,
        sid,
    }
    | CredentialOperation::VerifyRssLogin {
        binding,
        binding_generation,
        sid,
    }) = operation
    else {
        return Err(Error::Unsupported);
    };
    let b = crate::device_access::storage::locked_in(c, tenant, *binding)
        .await
        .map_err(super::custody_error)?;
    if b.generation != *binding_generation
        || !matches!(
            &b.configuration.windows,
            rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor { .. }
        )
        || !matches!(&b.account,Some(rss_mdm_agent_wire::runtime::AccessAccount::Windows{sid:actual,..}) if actual==sid)
        || !crate::device_access::storage::accepts_login_in(c, &b)
            .await
            .map_err(super::custody_error)?
    {
        return Err(Error::Forbidden);
    }
    let selected = crate::device_access::execution::admission::policy_on(
        rss_request_context::TenantId::parse(&tenant.to_string()).map_err(|_| Error::Malformed)?,
        c,
        tenant,
        &b.device,
        b.policy,
    )
    .await
    .map_err(super::custody_error)?;
    if selected.version != b.policy_version || selected.configuration != b.configuration {
        return Err(Error::Forbidden);
    }
    let anchor = Binding {
        device: b.device,

        subject: Subject::RssLogin {
            binding: *binding,
            binding_generation: *binding_generation,
            sid: sid.clone(),
        },
    };

    Ok((b, anchor))
}
