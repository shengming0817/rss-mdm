//! Immutable producer associations resolved before any projection write.
use crate::Error;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identity {
    Operation(Uuid),
    ActionRun(Uuid),
    ChangeRequest(Uuid),
}
pub type Association = Option<(String, Option<Uuid>)>;
pub trait Associations: Send + Sync {
    fn association_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        actor: &'a str,
        identity: Identity,
    ) -> Pin<Box<dyn Future<Output = Result<Association, Error>> + Send + 'a>>;
}
