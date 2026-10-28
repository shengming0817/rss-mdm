//! Resource lifecycle participant required by software imports and installers.
use crate::catalog::Result;
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
/// Software validates origin and materials; Resource owns its mutation sequence.
pub trait ResourceWriter: Send + Sync {
    fn partition(
        &self,
        resource: &str,
    ) -> Result<rss_transactional_messaging::message::PartitionIdentity>;
    fn import_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        operation: uuid::Uuid,
        expected: u64,
        version: &'a rss_mdm_resource::Version,
        at: rss_contract::Timepoint,
    ) -> Pending<'a, u64>;
    fn installer_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        operation: uuid::Uuid,
        version: &'a rss_mdm_resource::Version,
        filename: &'a str,
        at: rss_contract::Timepoint,
    ) -> Pending<'a, u64>;
}
