//! Device controls borrow this material capability in their initiating transaction.
use crate::{Binding, Error, Protection, Subject, storage};
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub struct LockPins {
    protection: Arc<Protection>,
}
impl LockPins {
    pub fn new(protection: Arc<Protection>) -> Self {
        Self { protection }
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "the complete device and operation identity is required for material custody"
    )]
    pub async fn hold_in(
        &self,
        c: &mut PgConnection,
        tenant: Uuid,
        device: &str,
        registration: Uuid,
        generation: i64,
        operation: Uuid,
        pin: &str,
    ) -> Result<(), Error> {
        let binding = Binding {
            device: device.into(),
            registration,
            generation,
            subject: Subject::LockPin { operation },
        };
        let coordinates = storage::reserve_in(c, tenant, &binding, operation, 0).await?;
        storage::ingest_in(
            c,
            &self.protection.keys,
            &coordinates,
            operation,
            pin.as_bytes(),
        )
        .await?;
        storage::link_native_in(
            c,
            tenant,
            operation,
            &binding,
            &storage::NativeAction {
                reconciles: None,
                action: "lock_pin".into(),
                coordinates: Some(coordinates),
                recipient: self.protection.active_recipient().id().into(),
            },
        )
        .await
    }
}
