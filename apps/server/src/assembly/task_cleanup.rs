//! Static composition of exact registration retirement participants.
use rss_mdm_execution_service::{
    Error, Failure,
    task_cleanup::*,
    transaction::{Fault, Result},
};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub(super) struct Cleanup;
impl TaskCleanup for Cleanup {
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registrations: &'a [Uuid],
    ) -> Pin<Box<dyn Future<Output = Result<Progress>> + Send + 'a>> {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            let registrations = registrations.to_vec();
            tx.with_connection(move |c| Box::pin(async move {
                Ok(async {
                    let mut progress=Progress::default();
                    for registration in &registrations {
                        rss_mdm_script_service::retirement::retire_in(c,&mut progress.facts,&tenant,*registration).await.map_err(script)?;
                        rss_mdm_inventory_service::collection::execution::retirement::retire_in(c,&mut progress.facts,&tenant,*registration).await.map_err(collection)?;
                    }
                    let script=rss_mdm_script_service::retirement::progress_on(c,&tenant,&registrations).await.map_err(script)?;
                    let collection=rss_mdm_inventory_service::collection::execution::retirement::progress_on(c,&tenant,&registrations).await.map_err(collection)?;
                    progress.pending=script.0 || collection.0;
                    progress.unknown=script.1.into_iter().chain(collection.1).min();
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
            E::Malformed => Error::Malformed,
            E::Conflict => Error::Conflict,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Inventory(e) => e.into(),
            E::Content(e) => e.into(),
            E::Audit(_) => Error::Unavailable(Failure::Audit),
            E::Invariant => Error::Unavailable(Failure::CommandInvariant),
            E::Unavailable => Error::Unavailable(Failure::CommandStorage),
        }
        .into(),
    }
}
