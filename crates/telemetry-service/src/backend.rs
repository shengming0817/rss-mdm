//! Closed dispatch across the explicitly admitted RSS storage configurations.
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
/// Host monotonic clock shared by provider deadlines.
#[derive(Clone, Copy)]
pub struct SystemClock;
impl Clock for SystemClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "host monotonic clock provider selected at storage assembly"
    )]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
/// Stores have already admitted their schema, tenant and credential configuration.
/// PG includes ordinary, shared Timescale and dedicated Timescale profiles.
pub enum Backend {
    /// An explicitly configured PostgreSQL-family store.
    Postgres(rss_timeseries_postgres::PgStore<SystemClock>),
    /// A tenant-bound ClickHouse store with its PostgreSQL control plane.
    ClickHouse(Box<rss_timeseries_clickhouse::ChStore<SystemClock>>),
}
macro_rules! dispatch {
    ($self:ident,$method:ident,$($arg:expr),*) => { match $self {
        Self::Postgres(store) => store.$method($($arg),*).await,
        Self::ClickHouse(store) => store.$method($($arg),*).await,
    } };
}
impl Backend {
    /// Close adopted resources within the original host shutdown budget.
    pub async fn close(&self, deadline: Deadline) -> Result<(), Error> {
        dispatch!(self, close, deadline)
    }
    pub(crate) async fn write(
        &self,
        input: &Authorized<Batch>,
        deadline: Deadline,
    ) -> Result<Outcome<Receipt>, Error> {
        dispatch!(self, write, input, deadline)
    }
    pub(crate) async fn define(
        &self,
        input: &Authorized<DefinitionMutation>,
        deadline: Deadline,
    ) -> Result<Outcome<DefinitionRecord>, Error> {
        dispatch!(self, change, input, deadline)
    }
    pub(crate) async fn definition(
        &self,
        input: &Authorized<DefinitionId>,
        deadline: Deadline,
    ) -> Result<Lookup<DefinitionRecord>, Error> {
        dispatch!(self, read, input, deadline)
    }
    pub(crate) async fn query(
        &self,
        input: &Authorized<Query>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Page, Error> {
        dispatch!(self, query, input, after, deadline)
    }
    pub(crate) async fn aggregate(
        &self,
        input: &Authorized<AggregateQuery>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<AggregatePage, Error> {
        dispatch!(self, aggregate, input, after, deadline)
    }
    pub(crate) async fn maintain(
        &self,
        input: &Authorized<MaintenanceRequest>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Outcome<MaintenanceProgress>, Error> {
        dispatch!(self, step, input, after, deadline)
    }
}
