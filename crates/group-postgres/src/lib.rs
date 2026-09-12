//! Tenant-scoped Group persistence over one host-owned RSS [`PgRuntime`](rss_transactional_messaging_postgres::PgRuntime).
//!
//! Install [`MIGRATION_SQL`] externally after the fixed RSS messaging migration, then
//! construct [`GroupStore`] with a producer runtime and an explicit tenant/deadline.
//! [`Command`] handles static definitions/members and dynamic rules. Every effective
//! change stages its compact [`EVENT_SCHEMA`] event in the same local transaction.
//!
//! For dynamic membership: supply a core [`Rule`](rss_mdm_group::Rule), use
//! [`GroupStore::preview`] for read-only evaluation, persist complete caller input with
//! [`GroupStore::start_recalculation`], then [`GroupStore::resume`] by its original
//! operation ID. Recovery needs no caller snapshot after admission commits. The host
//! owns scheduling, authorization, asset reads, retention and runtime shutdown.
//!
//! A successful new recalculation advances [`Group::revision`] even without a delta;
//! [`Group::member_version`] advances only when membership changes. Replay returns the
//! original receipt, while reusing an identity with different input is rejected.
//! A [`Error::CommitUnknown`] or [`Error::RollbackFailed`] is not a business rejection:
//! reconnect and resolve the same identity. Before durable admission, the caller must
//! retain its original request for replay. Never assign a replacement operation ID
//! merely because a transaction acknowledgement was lost.
//!
//! The `*_in` methods borrow a trusted RSS transaction and never commit it. Check both
//! layers of [`InTransaction`], propagate database errors to the outer owner, and lock
//! groups in ascending ID order before companion reference/audit work. Authorization
//! and reference protection are supplied by N12; this crate has no HTTP or Inventory
//! dependency, fallback schema, scheduler, or historical rule interpreter.
#![warn(missing_docs, clippy::cognitive_complexity)]

mod admission;
mod codec;
mod event;
mod model;
mod runs;
mod storage;
mod store;
pub use event::EVENT_SCHEMA;
pub use model::*;
/// The same core types used in this adapter's signatures, available to one-package consumers.
pub use rss_mdm_group as core;
pub use store::GroupStore;
/// One-time owner migration; not executable by the runtime role. No legacy upgrade path.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_group.sql");
#[cfg(test)]
mod codec_tests;
