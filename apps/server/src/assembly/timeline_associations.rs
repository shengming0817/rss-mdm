//! Static source-owner dispatch. UUID spelling and event hashes do not select an owner.
use rss_mdm_audit_integration::operation::{OperationLocator, OperationOwner as O};
use rss_mdm_timeline_service::{
    Error,
    associations::{Association, Associations},
};
use std::{future::Future, pin::Pin};
pub(crate) struct Producers;
impl Associations for Producers {
    fn association_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: &'a str,
        actor: &'a str,
        locator: &'a OperationLocator,
    ) -> Pin<Box<dyn Future<Output = Result<Association, Error>> + Send + 'a>> {
        Box::pin(async move {
            let id = locator.operation_id;
            use rss_mdm_device_service::control::timeline as device;
            use rss_mdm_recovery_credentials::native::timeline as recovery;
            use rss_mdm_registration_service::installation::timeline as installation;
            use rss_mdm_software_service::deployment::timeline as software;
            let result=match locator.owner {
                O::DeviceControl=>device::association_in(c,tenant,actor,device::Identity::Operation(id)).await?,
                O::DeviceAction=>device::association_in(c,tenant,actor,device::Identity::ActionRun(id)).await?,
                O::DeviceControlRequest=>device::association_in(c,tenant,actor,device::Identity::ChangeRequest(id)).await?,
                O::SoftwareDeployment=>software::association_in(c,tenant,actor,software::Identity::Operation(id)).await?,
                O::SoftwareAction=>software::association_in(c,tenant,actor,software::Identity::ActionRun(id)).await?,
                O::Installation=>installation::association_in(c,tenant,actor,installation::Identity::Operation(id)).await?,
                O::RecoveryCommand=>recovery::association_in(c,tenant,actor,recovery::Identity::Operation(id)).await?,
                O::Configuration=>rss_mdm_policy_service::configuration::storage::association_on(c,tenant,id).await?,
                O::Script=>rss_mdm_script_service::storage::association_on(c,tenant,id).await?,
                O::CollectionExecution=>rss_mdm_inventory_service::collection::execution::storage::association_on(c,tenant,id).await?,
                O::EnrollmentTask=>rss_mdm_registration_service::enrollment::tasks::storage::association_on(rss_mdm_install_support::StorageProfile::Mdm,c,tenant,id).await?,
                O::DeviceAccessTask=>rss_mdm_device_access_postgres::device_access::execution::storage::association_on(c,tenant,id).await?,
                O::CredentialTask=>rss_mdm_recovery_credentials::tasks::storage::association_on(locator.product,c,tenant,id).await?,
                _=>None,
            };
            Ok(result)
        })
    }
}
