use rss_mdm_group::Rule;
use rss_mdm_group::{AssetContext, GroupId, OperationId};
use serde::{Deserialize, Serialize};

/// The sole compare-and-swap sequence for one group.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct Revision(i64);
impl Revision {
    /// Construct a positive CAS revision; zero and negative values are invalid.
    pub fn new(n: i64) -> Result<Self, Rejection> {
        if n > 0 {
            Ok(Self(n))
        } else {
            Err(Rejection::InvalidInput)
        }
    }
    /// Return the persisted positive revision.
    pub const fn get(self) -> i64 {
        self.0
    }
    pub(crate) fn next(self) -> Result<Self, Rejection> {
        self.0
            .checked_add(1)
            .ok_or(Rejection::VersionExhausted)
            .and_then(Self::new)
    }
}
impl TryFrom<i64> for Revision {
    type Error = Rejection;
    fn try_from(n: i64) -> Result<Self, Self::Error> {
        Self::new(n)
    }
}
impl From<Revision> for i64 {
    fn from(r: Revision) -> Self {
        r.0
    }
}

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Membership authority fixed at creation; commands cannot switch the kind.
pub enum GroupKind {
    /// Members are explicitly managed.
    Static,
    /// Members are derived from a frozen typed rule and supplied snapshot.
    Dynamic,
    /// Members follow authenticated endpoint lifecycle facts.
    System,
}
/// Immutable product lifecycle selection; never supplied by editable presentation.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemSelector {
    /// Every currently managed endpoint, including devices without Inventory.
    AllActive,
    /// Managed endpoints whose authenticated sources agree on Windows.
    Windows,
    /// Managed endpoints whose authenticated sources agree on macOS.
    Macos,
}
impl SystemSelector {
    /// Canonical storage value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllActive => "all_active",
            Self::Windows => "windows",
            Self::Macos => "macos",
        }
    }
}
#[derive(Clone, Debug)]
/// Initial membership authority; dynamic definitions include a validated core rule.
pub enum Definition {
    /// Create an empty manually managed group.
    Static,
    /// Create an empty dynamic group with this immutable rule version.
    Dynamic(Box<Rule>),
    /// Create a product-owned lifecycle group.
    System(SystemSelector),
}
/// Commands own business invariants. No raw member-write API is exposed.
#[derive(Clone, Debug)]
pub enum Command {
    /// Claim a fresh group ID permanently and start at revision one.
    Create {
        /// Target group identity within this store’s tenant.
        group: GroupId,
        /// Open descriptive properties; never membership or rule authority.
        presentation: serde_json::Map<String, serde_json::Value>,
        /// Immutable asset universe.
        asset_context: AssetContext,
        /// Initial authority and optional dynamic rule.
        definition: Definition,
    },
    /// Change descriptive metadata under the observed revision.
    Edit {
        /// Target group identity within this store’s tenant.
        group: GroupId,
        /// The caller-observed sole group CAS revision.
        expected: Revision,
        /// Open descriptive properties; never membership or rule authority.
        presentation: serde_json::Map<String, serde_json::Value>,
    },
    /// Select an immutable rule version for a dynamic group; reusing its version with different content is rejected.
    SetRule {
        /// Target group identity within this store’s tenant.
        group: GroupId,
        /// The caller-observed sole group CAS revision.
        expected: Revision,
        /// Validated core rule; tenant must match and version is limited to 256 UTF-8 bytes.
        rule: Rule,
    },
    /// Logically delete and clear members, preserving history. Only execute_in accepts this command.
    /// N12 must compose reference checks and audit in the same transaction.
    Delete {
        /// Target group identity within this store’s tenant.
        group: GroupId,
        /// The caller-observed sole group CAS revision.
        expected: Revision,
    },
}
impl Command {
    /// Return the group whose lock is acquired before the operation lock.
    pub fn group(&self) -> GroupId {
        match self {
            Self::Create { group, .. }
            | Self::Edit { group, .. }
            | Self::SetRule { group, .. }
            | Self::Delete { group, .. } => *group,
        }
    }
    pub(crate) fn expected(&self) -> Option<Revision> {
        match self {
            Self::Create { .. } => None,
            Self::Edit { expected, .. }
            | Self::SetRule { expected, .. }
            | Self::Delete { expected, .. } => Some(*expected),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// An observed group revision, including tombstones and immutable current rule identity.
pub struct Group {
    /// Identity of this stored record.
    pub id: GroupId,
    /// Immutable membership authority.
    pub kind: GroupKind,
    /// Immutable lifecycle selector, present exactly for system groups.
    pub system_selector: Option<SystemSelector>,
    /// Immutable input object universe.
    pub asset_context: AssetContext,
    /// Open descriptive properties; never membership or rule authority.
    pub presentation: serde_json::Map<String, serde_json::Value>,
    /// Configuration edit CAS, independent of background membership publication.
    pub revision: Revision,
    /// Successful publication sequence; fences competing fixed-input calculations.
    pub calculation_revision: i64,
    /// Semantic membership sequence; zero means initially empty.
    pub member_version: i64,
    /// Number of current members, bounded by the core object limit.
    pub member_count: usize,
    /// Immutable rule identity; present only for dynamic groups.
    pub rule_version: Option<String>,
    /// Logical tombstone; history remains readable.
    pub deleted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Durable result of one committed command or successful recalculation; replay returns this value.
pub struct Receipt {
    /// Original durable operation identity.
    pub operation: OperationId,
    /// Target group identity within this store’s tenant.
    pub group: Group,
    /// Number of members added by this operation.
    pub added: usize,
    /// Number of members removed by this operation.
    pub removed: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[error("Group request rejected: {self:?}")]
/// Business/input rejection. Correct the input or refresh state; do not blindly retry a stale CAS.
pub enum Rejection {
    /// Input violates a shape, text or resource budget.
    InvalidInput,
    /// Current device capacity would exceed one million.
    CapacityExceeded,
    /// This page exceeds a byte or evaluation budget; a smaller page may fit.
    PageBudgetExceeded,
    /// Deletion requires the host-owned transaction for reference checks and audit; use execute_in.
    CompanionTransactionRequired,
    /// Request or borrowed transaction tenant differs from the store.
    TenantMismatch,
    /// No visible target exists in this tenant.
    NotFound,
    /// The target is a tombstone; IDs cannot be reused.
    Deleted,
    /// Manual and computed membership authorities cannot be mixed.
    KindMismatch,
    /// CAS/rule version changed; refresh and make an explicit new decision.
    VersionConflict,
    /// Operation or immutable rule identity was reused with different input.
    IdentityConflict,
    /// The supplied snapshot cannot support a complete membership replacement.
    IncompleteSnapshot,
    /// A persisted time cannot be decoded; investigate storage integrity.
    InvalidStoredDocument,
    /// The revision reached the signed 64-bit limit; it never wraps.
    VersionExhausted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// One bytewise object-ID ordered page of a completed operation’s actual membership changes.
pub struct DeltaPage {
    /// Object IDs added in this page, in bytewise order.
    pub added: Vec<String>,
    /// Object IDs removed in this page, in bytewise order.
    pub removed: Vec<String>,
    /// Exclusive object-ID cursor for the next page; None when exhausted.
    pub next: Option<String>,
}

/// Successful SQL can still reject a command before effects; caller must handle both layers.
pub type CommandOutcome<T> = Result<T, Rejection>;
/// Borrowed result: handle the inner rejection and propagate the outer database error to roll back.
pub type InTransaction<T> =
    Result<CommandOutcome<T>, rss_transactional_messaging_postgres::PgError>;
#[derive(Debug, thiserror::Error)]
/// Transaction outcome remains distinct from business rejection and safe storage diagnostics.
pub enum Error {
    #[error(transparent)]
    /// No accepted business outcome; inspect the reason.
    Rejected(#[from] Rejection),
    #[error("Group transaction not started: {0}")]
    /// No transaction began; retry subject to the underlying RSS error policy.
    NotStarted(rss_transactional_messaging_postgres::PgError),
    #[error("Group transaction rolled back: {0}")]
    /// The transaction is confirmed rolled back; preserve the original operation identity when retrying.
    RolledBack(rss_transactional_messaging_postgres::PgError),
    #[error("Group rollback is unconfirmed: {0}")]
    /// Rollback acknowledgement is absent; resolve the original identity after reconnecting.
    RollbackFailed(rss_transactional_messaging_postgres::PgError),
    #[error("Group commit is unconfirmed for {operation:?}: {source}")]
    /// Commit acknowledgement is absent; resolve this identity before deciding further action.
    CommitUnknown {
        /// Original durable operation identity.
        operation: Option<OperationId>,
        /// RSS cause, preserving safe diagnostic identity and transaction classification.
        source: rss_transactional_messaging_postgres::PgError,
    },
    #[error("Group transaction fenced: {0}")]
    /// RSS fenced the transaction; restore the execution/storage binding before retrying.
    Fenced(rss_transactional_messaging_postgres::PgError),
}
pub(crate) fn settle<T>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        CommandOutcome<T>,
        rss_transactional_messaging_postgres::PgError,
    >,
    operation: Option<OperationId>,
) -> Result<T, Error> {
    attempt.fold(
        |v| v.map_err(Error::from),
        |e| Err(Error::NotStarted(e)),
        |e| Err(Error::RolledBack(e)),
        |e| Err(Error::RollbackFailed(e)),
        |source| Err(Error::CommitUnknown { operation, source }),
        |e| Err(Error::Fenced(e)),
    )
}

impl From<rss_mdm_group::IdentityError> for Rejection {
    fn from(_: rss_mdm_group::IdentityError) -> Self {
        Self::InvalidInput
    }
}
