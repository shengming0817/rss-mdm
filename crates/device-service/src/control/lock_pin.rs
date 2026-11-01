//! Lock PIN custody borrows the initiating control transaction.
use super::{Error, Target};
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub trait LockPins: Send + Sync {
    fn hold_in<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        target: &'a Target,
        operation: Uuid,
        pin: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
