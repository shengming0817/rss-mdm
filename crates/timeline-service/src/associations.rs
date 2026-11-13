//! Immutable producer associations resolved before any projection write.
use crate::Error;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
pub type Association = Option<(rss_mdm_agent_wire::DeviceId, Option<uuid::Uuid>)>;
pub trait Associations: Send + Sync {
    fn association_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        actor: &'a str,
        identity: &'a rss_mdm_audit_integration::operation::OperationLocator,
    ) -> Pin<Box<dyn Future<Output = Result<Association, Error>> + Send + 'a>>;
}
