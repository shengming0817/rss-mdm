//! Each input-copy owner decides and scrubs its own persistent copies on the caller's transaction.
use crate::Error;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::PgConnection;
use uuid::Uuid;
pub type Pending<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyState {
    Purged,
    Retained,
}
pub trait InputCopies: Send + Sync {
    fn purge_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        operation: Uuid,
    ) -> Pending<'a, CopyState>;
}
pub trait ChannelCopies: Send + Sync {
    /// The command component's actual record proves delivery state; the channel also checks its own receipts.
    fn purge_in<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        operation: Uuid,
        command: &'a rss_device_command::Command,
    ) -> Pending<'a, CopyState>;
}
