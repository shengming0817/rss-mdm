//! Narrow cyclic-boundary ports; App maps concrete Scope and channel capabilities.
use super::model::Target;
use crate::{objects::DeviceObject, transaction::Result};
use rss_mdm_inventory::Channel;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Eligible { entry: i64 },
    Pending,
    Excluded,
}
pub trait TargetAdmission: Send + Sync {
    fn admission_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Admission>;
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Vec<DeviceObject>>;
    fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: Channel,
        device: &'a rss_mdm_agent_wire::DeviceId,
        evidence: &'a [DeviceObject],
    ) -> Pending<'a, bool>;
}
pub trait NativeDelivery: Send + Sync {
    fn permissions(
        &self,
        template: &rss_mdm_resource::NativeCollectionDefinition,
    ) -> std::result::Result<Vec<rss_mdm_authorization_service::Permission>, crate::Error>;
    fn eligible_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        target: &'a Target,
        template: &'a rss_mdm_resource::NativeCollectionDefinition,
    ) -> Pending<'a, bool>;
    fn prepare_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        platform: rss_mdm_policy::Platform,
    ) -> Pending<'a, Vec<rss_mdm_audit_integration::Fact>>;
}
pub trait DeviceCapacity: Send + Sync {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a rss_mdm_agent_wire::DeviceId,
        now: i64,
    ) -> Pending<'a, bool>;
}
