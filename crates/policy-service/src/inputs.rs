//! Validation of locked Policy publication material.
//! These are facts inside the initiating transaction, not independent service requests.
use rss_mdm_resource::Version;
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};

/// One operation borrowing its initiating transaction.
pub type Pending<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Closed failures from validation of exact profile material.
#[derive(Clone, Copy, Debug)]
pub enum ProfileValidationError {
    Invalid,
    Conflict,
    Unavailable,
}
/// Validates a locked template using Inventory facts and Telemetry rules.
pub trait ProfileValidator: Send + Sync {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        template: &'a Version,
        profile: &'a rss_mdm_resource::TelemetryProfile,
    ) -> Pending<'a, Vec<rss_mdm_inventory::FieldDefinition>, ProfileValidationError>;
}

use crate::transaction::Fault;
/// Durable changes in remaining Execution work, borrowing the original Policy transaction.
pub trait ExecutionChanges: Send + Sync {
    fn policy_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: &'a rss_mdm_policy::Policy,
        previous: Option<&'a rss_mdm_policy::Policy>,
    ) -> Pending<'a, (), Fault>;
    fn assignment_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: uuid::Uuid,
        target: &'a rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
        available: bool,
    ) -> Pending<'a, (), Fault>;
    fn configuration_progressed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        devices: &'a [rss_mdm_agent_wire::DeviceId],
    ) -> Pending<'a, (), Fault>;
    fn retirement_accepted_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: uuid::Uuid,
    ) -> Pending<'a, (), Fault>;
}
