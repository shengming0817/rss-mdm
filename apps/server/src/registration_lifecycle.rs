//! Cross-capability retirement keeps the original transaction and lock order.

pub(crate) struct Bridge;
impl rss_mdm_registration_service::Retirement for Bridge {
    fn retire<'a>(
        &'a self,
        tx: &'a mut sqlx::PgConnection,
        facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        registration: uuid::Uuid,
        state: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), rss_mdm_registration_service::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            rss_mdm_registration_service::device_access::storage::retire_in(
                tx,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_pki_service::certificates::revoke_registration_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                tx,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_device_service::control::retire_in(tx, facts, tenant, registration)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_software_service::deployment::retirement::retire_in(
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_registration_service::installation::retirement::retire_in(
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_registration_service::enrollment::tasks::retirement::retire_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_script_service::retirement::retire_in(tx, facts, tenant, registration)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_inventory_service::collection::execution::retirement::retire_in(
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_registration_service::device_access::execution::retirement::retire_in(
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_recovery_credentials::tasks::retirement::retire_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_recovery_credentials::native::retirement::retire_in(
                tx,
                facts,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_recovery_credentials::storage::retire_in(
                rss_mdm_recovery_credentials::Custody::new(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    None,
                ),
                tx,
                tenant,
                registration,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_windows_channel::retire_in(tx, tenant, registration)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            rss_mdm_apple_channel::retire_in(tx, tenant, registration)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Retirement)?;
            crate::collection::terminate(
                rss_mdm_install_support::StorageProfile::Mdm,
                tx,
                facts,
                tenant,
                &registration.to_string(),
                state,
            )
            .await
            .map_err(collection_failure)
        })
    }
}

fn collection_failure(
    error: rss_mdm_inventory_service::Error,
) -> rss_mdm_registration_service::Error {
    use rss_mdm_inventory_service::{Error as I, Failure as F};
    use rss_mdm_registration_service::Error as R;
    match error {
        I::Malformed => R::Malformed,
        I::Unauthorized => R::Unauthorized,
        I::Forbidden => R::Forbidden,
        I::Conflict => R::Conflict,
        I::NotFound => R::NotFound,
        I::CommitUnknown => R::CommitUnknown,
        I::RollbackFailed => R::RollbackFailed,
        I::Audit(e) => R::Audit(e),
        I::Unavailable(F::RequestDeadline) => R::Deadline,
        _ => R::Retirement,
    }
}
