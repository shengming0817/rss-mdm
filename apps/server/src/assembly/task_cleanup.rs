//! Static composition of exact registration retirement participants.
use rss_mdm_device_service::control::{
    Error, Failure,
    task_cleanup::*,
    transaction::{Fault, Result},
};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub(super) struct Cleanup(pub std::sync::Arc<rss_mdm_software_service::deployment::Transactions>);
impl TaskCleanup for Cleanup {
    fn installations_removed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
        target: &'a rss_mdm_device_service::control::Target,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .prior_agent_installations_removed_in(tx, retirement, &channel(target))
                .await
                .map_err(software)
        })
    }
    fn remove_software_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
        target: &'a rss_mdm_device_service::control::Target,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .cleanup_software_retirement_in(tx, retirement, &channel(target))
                .await
                .map_err(software)
        })
    }
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registrations: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Progress>> + Send + 'a>> {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            let registrations = registrations.to_vec();
            tx.with_connection(move |c| Box::pin(async move {
                Ok(async {
                    let mut progress=Progress::default();
                    for registration in &registrations {
                        rss_mdm_software_service::deployment::retirement::retire_in(c,&mut progress.facts,&tenant,registration.clone()).await.map_err(software_error)?;
                        rss_mdm_registration_service::installation::retirement::retire_in(c,&mut progress.facts,&tenant,registration.clone()).await.map_err(installation_error)?;
                        rss_mdm_registration_service::enrollment::tasks::retirement::retire_in(rss_mdm_install_support::StorageProfile::Mdm, c,&mut progress.facts,&tenant,registration.clone()).await.map_err(enrollment)?;
                        rss_mdm_device_access_postgres::device_access::execution::retirement::retire_in(c,&mut progress.facts,&tenant,registration.clone()).await.map_err(access)?;
                        rss_mdm_recovery_credentials::tasks::retirement::retire_in(rss_mdm_install_support::StorageProfile::Mdm, c,&mut progress.facts,&tenant,registration.clone()).await.map_err(credential)?;
                        rss_mdm_recovery_credentials::tasks::retirement::retire_in(rss_mdm_install_support::StorageProfile::Da, c,&mut progress.facts,&tenant,registration.clone()).await.map_err(credential)?;
                        rss_mdm_recovery_credentials::native::retirement::retire_in(c,&mut progress.facts,&tenant,registration.clone()).await.map_err(|e|recovery_native(e.into()))?;
                        rss_mdm_script_service::retirement::retire_in(c,&mut progress.facts,&tenant,registration.clone()).await.map_err(script)?;
                        rss_mdm_inventory_service::collection::execution::retirement::retire_in(c,&mut progress.facts,&tenant,registration.clone()).await.map_err(collection)?;
                    }
                    let script=rss_mdm_script_service::retirement::progress_on(c,&tenant,&registrations).await.map_err(script)?;
                    let collection=rss_mdm_inventory_service::collection::execution::retirement::progress_on(c,&tenant,&registrations).await.map_err(collection)?;
                    let enrollment=rss_mdm_registration_service::enrollment::tasks::retirement::progress_on(rss_mdm_install_support::StorageProfile::Mdm, c,&tenant,&registrations).await.map_err(enrollment)?;
                    let software=rss_mdm_software_service::deployment::retirement::progress_on(c,&tenant,&registrations).await.map_err(software)?;
                    let native=rss_mdm_registration_service::installation::retirement::progress_on(c,&tenant,&registrations).await.map_err(installation)?;
                    let access=rss_mdm_device_access_postgres::device_access::execution::retirement::progress_on(c,&tenant,&registrations).await.map_err(access)?;
                    let credential_progress=rss_mdm_recovery_credentials::tasks::retirement::progress_on(rss_mdm_install_support::StorageProfile::Mdm, c,&tenant,&registrations).await.map_err(credential)?;
                    let recovery_native=rss_mdm_recovery_credentials::native::retirement::progress_on(c,&tenant,&registrations).await.map_err(recovery_native)?;
                    let da_credential=rss_mdm_recovery_credentials::tasks::retirement::progress_on(rss_mdm_install_support::StorageProfile::Da,c,&tenant,&registrations).await.map_err(credential)?;
                    progress.pending=da_credential.0 || credential_progress.0 || recovery_native.0 || access.0 || script.0 || collection.0 || enrollment.0 || software.0 || native.0;
                    progress.unknown=script.1.into_iter().chain(recovery_native.1).chain(credential_progress.1).chain(da_credential.1).chain(access.1).chain(collection.1).chain(enrollment.1).chain(software.1).chain(native.1).min();
                    Ok(progress)
                }.await)
            })).await?
        })
    }
}
fn collection(error: rss_mdm_inventory_service::transaction::Fault) -> Fault {
    use rss_mdm_inventory_service::transaction::Fault as F;
    match error {
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
        F::Request(e) => Error::from(e).into(),
    }
}
fn script(error: rss_mdm_script_service::transaction::Fault) -> Fault {
    use rss_mdm_script_service::{Error as E, transaction::Fault as F};
    match error {
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
        F::Request(e) => match e {
            E::Unsupported => Error::Unsupported,
            E::Malformed => Error::Malformed,
            E::Conflict => Error::Conflict,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Inventory(e) => e.into(),
            E::Content(e) => match e {
                rss_mdm_content_service::Error::CommitUnknown => Error::CommitUnknown,
                rss_mdm_content_service::Error::Conflict => Error::Conflict,
                rss_mdm_content_service::Error::Malformed => Error::Malformed,
                _ => Error::Unavailable(Failure::ContentStorage),
            },
            E::Audit(_) => Error::Unavailable(Failure::Audit),
            E::Invariant => Error::Unavailable(Failure::CommandInvariant),
            E::Unavailable => Error::Unavailable(Failure::CommandStorage),
        }
        .into(),
    }
}

fn channel(
    t: &rss_mdm_device_service::control::Target,
) -> rss_mdm_software_service::deployment::retirement::Channel {
    rss_mdm_software_service::deployment::retirement::Channel {
        device: t.device.clone(),
    }
}
fn software_error(e: rss_mdm_software_service::deployment::Error) -> Fault {
    use rss_mdm_software_service::deployment::Error as E;
    match e {
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Malformed => Error::Malformed,
        E::Forbidden => Error::Forbidden,
        E::Unauthorized => Error::Unauthorized,
        E::Conflict => Error::Conflict,
        _ => Error::Unavailable(Failure::CommandStorage),
    }
    .into()
}
fn software(e: rss_mdm_software_service::deployment::transaction::Fault) -> Fault {
    use rss_mdm_software_service::deployment::transaction::Fault as F;
    match e {
        F::Request(e) => software_error(e),
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
    }
}
fn installation_error(e: rss_mdm_registration_service::installation::Error) -> Fault {
    use rss_mdm_registration_service::installation::Error as E;
    match e {
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Malformed => Error::Malformed,
        E::Forbidden => Error::Forbidden,
        E::Unauthorized => Error::Unauthorized,
        E::Conflict => Error::Conflict,
        _ => Error::Unavailable(Failure::CommandStorage),
    }
    .into()
}
fn installation(e: rss_mdm_registration_service::installation::transaction::Fault) -> Fault {
    use rss_mdm_registration_service::installation::transaction::Fault as F;
    match e {
        F::Request(e) => installation_error(e),
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
    }
}
fn enrollment_error(e: rss_mdm_registration_service::enrollment::tasks::Error) -> Fault {
    use rss_mdm_registration_service::enrollment::tasks::Error as E;
    match e {
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Malformed => Error::Malformed,
        E::Forbidden => Error::Forbidden,
        E::Unauthorized => Error::Unauthorized,
        E::Conflict => Error::Conflict,
        _ => Error::Unavailable(Failure::CommandStorage),
    }
    .into()
}
fn enrollment(e: rss_mdm_registration_service::enrollment::tasks::transaction::Fault) -> Fault {
    use rss_mdm_registration_service::enrollment::tasks::transaction::Fault as F;
    match e {
        F::Request(e) => enrollment_error(e),
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
    }
}

fn access(
    e: rss_mdm_device_access_postgres::device_access::execution::transaction::Fault,
) -> Fault {
    use rss_mdm_device_access_postgres::device_access::execution::{
        Error as E, transaction::Fault as F,
    };
    match e {
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
        F::Request(e) => match e {
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::Conflict => Error::Conflict,
            _ => Error::Unavailable(Failure::CommandStorage),
        }
        .into(),
    }
}

fn credential(e: rss_mdm_recovery_credentials::tasks::transaction::Fault) -> Fault {
    use rss_mdm_recovery_credentials::tasks::{Error as E, transaction::Fault as F};
    match e {
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
        F::Request(e) => match e {
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::Conflict => Error::Conflict,
            _ => Error::Unavailable(Failure::CommandStorage),
        }
        .into(),
    }
}

fn recovery_native(e: rss_mdm_recovery_credentials::native::transaction::Fault) -> Fault {
    use rss_mdm_recovery_credentials::native::{Error as E, transaction::Fault as F};
    match e {
        F::Sql(e) => Fault::Sql(e),
        F::Storage(e) => Fault::Storage(e),
        F::Request(e) => match e {
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::Conflict => Error::Conflict,
            _ => Error::Unavailable(Failure::CommandStorage),
        }
        .into(),
    }
}
