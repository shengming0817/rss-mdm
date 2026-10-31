//! Configuration facts consumed by aggregate operation queries; the App supplies the actual owner.
use super::*;
use sqlx::PgConnection;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = crate::Result<T>> + Send + 'a>>;
pub struct Assignment {
    pub diagnosis: Option<String>,
    pub operations: Vec<Uuid>,
}
pub struct Declaration {
    pub registration: Uuid,
    pub generation: i64,
    pub redacted: bool,
    pub observation: records::NativeObservation,
}
pub trait ConfigurationReads: Send + Sync {
    /// Exactly-one persistent membership for every UUID, independent of current authorization.
    fn partition_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        ids: &'a [Uuid],
    ) -> Pending<'a, BTreeSet<Uuid>>;
    fn assignment_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        policy: Uuid,
        target: &'a rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    ) -> Pending<'a, Assignment>;
    fn classify_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a authorization::Snapshot,
        ids: Vec<Uuid>,
        now: i64,
    ) -> Pending<'a, BTreeMap<Uuid, crate::authorization_decision::Decision>>;
    fn detail_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a authorization::Snapshot,
        now: i64,
        device: &'a str,
        id: Uuid,
    ) -> Pending<'a, records::CommandDetail>;
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a authorization::Snapshot,
        ids: Vec<Uuid>,
    ) -> Pending<'a, BTreeMap<Uuid, records::CommandEvidence>>;
    fn declarations_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a authorization::Snapshot,
        device: &'a str,
        registration: Uuid,
        generation: i64,
        ids: Vec<Uuid>,
    ) -> Pending<'a, BTreeMap<Uuid, Declaration>>;
}
