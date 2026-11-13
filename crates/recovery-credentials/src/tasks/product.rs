//! Product-specific credential semantics, borrowed by the shared task mechanism.
use crate::{
    Binding, Error,
    eligibility::{Eligibility, Pending},
};
use sqlx::PgConnection;
use uuid::Uuid;
/// Resolves an immutable material anchor from a current product binding and exact Agent delivery.
/// The engine keeps this anchor in its run; wire/AAD coordinates remain the real Agent's.
pub trait Product: Eligibility {
    fn resolve<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        operation: &'a rss_mdm_policy::CredentialOperation,
        target: &'a super::Target,
    ) -> Pending<'a, Binding>;
}
pub fn rss(operation: &rss_mdm_policy::CredentialOperation) -> bool {
    matches!(
        operation,
        rss_mdm_policy::CredentialOperation::RotateRssLogin { .. }
            | rss_mdm_policy::CredentialOperation::VerifyRssLogin { .. }
    )
}
pub(crate) async fn anchor(
    service: &super::Transactions,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    operation: &rss_mdm_policy::CredentialOperation,
    target: &super::Target,
) -> super::Result<Option<Binding>> {
    if rss(operation) != (service.profile() == rss_mdm_install_support::StorageProfile::Da) {
        return Err(super::Error::Forbidden.into());
    }
    let Some(product) = service.product.clone() else {
        return Ok(None);
    };
    let operation = operation.clone();
    let target = target.clone();
    let tenant =
        Uuid::parse_str(&tx.tenant_id().to_string()).map_err(|_| super::Error::Invariant)?;
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(product.resolve(c, tenant, &operation, &target).await) })
    })
    .await?
    .map(Some)
    .map_err(super::Error::from)
    .map_err(Into::into)
}
pub(crate) fn custody(
    profile: rss_mdm_install_support::StorageProfile,
    product: Option<&dyn Product>,
) -> crate::Custody<'_> {
    crate::Custody::new(profile, product.map(|p| p as &dyn Eligibility))
}
/// Material subjects are compared before using the frozen authority; transport fields cannot override it.
pub(crate) fn material(
    anchor: Option<&Binding>,
    task: &super::Target,
    subject: crate::Subject,
) -> Result<Binding, Error> {
    if let Some(anchor) = anchor {
        if anchor.subject != subject {
            return Err(Error::Conflict);
        }
        return Ok(anchor.clone());
    }
    if matches!(subject, crate::Subject::RssLogin { .. }) {
        return Err(Error::Forbidden);
    }
    Ok(Binding {
        device: task.device,

        subject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rss_material_identity_is_the_frozen_da_anchor() {
        let transport = crate::tasks::Target {
            device: rss_mdm_agent_wire::DeviceId::parse("eade504c-4515-50ed-a3a7-ef0823e7a753")
                .unwrap(),
        };
        let subject = crate::Subject::RssLogin {
            binding: Uuid::new_v4(),
            binding_generation: 2,
            sid: "S-1-5-21-1-2-3-1001".into(),
        };
        let anchor = Binding {
            device: rss_mdm_agent_wire::DeviceId::parse("2393c3f3-4e8c-5c75-b7cf-f4978eb921df")
                .unwrap(),

            subject: subject.clone(),
        };
        let result = material(Some(&anchor), &transport, subject.clone()).unwrap();
        assert_eq!(result.device, anchor.device);
        assert!(material(None, &transport, subject).is_err());
        assert!(
            material(
                Some(&anchor),
                &transport,
                crate::Subject::LocalAdministrator {
                    sid: "S-1-5-21-1-2-3-1001".into()
                }
            )
            .is_err()
        );
    }
}
