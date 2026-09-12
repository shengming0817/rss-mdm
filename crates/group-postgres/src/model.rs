use rss_contract::Timepoint;
use rss_mdm_group::{Rule, Snapshot};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(Uuid);
        impl $name {
            pub fn parse(s: &str) -> Result<Self, Rejection> {
                let value = Uuid::parse_str(s).map_err(|_| Rejection::InvalidInput)?;
                if value.is_nil() {
                    return Err(Rejection::InvalidInput);
                }
                Ok(Self(value))
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl TryFrom<String> for $name {
            type Error = Rejection;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::parse(&s)
            }
        }
        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.to_string()
            }
        }
    };
}
id!(GroupId);
id!(OperationId);

/// The sole compare-and-swap sequence for one group.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct Revision(i64);
impl Revision {
    pub fn new(n: i64) -> Result<Self, Rejection> {
        if n > 0 {
            Ok(Self(n))
        } else {
            Err(Rejection::InvalidInput)
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Static,
    Dynamic,
}
#[derive(Clone, Debug)]
pub enum Definition {
    Static,
    Dynamic(Box<Rule>),
}
/// Commands own business invariants. No raw member-write API is exposed.
#[derive(Clone, Debug)]
pub enum Command {
    Create {
        group: GroupId,
        name: String,
        description: String,
        definition: Definition,
    },
    Edit {
        group: GroupId,
        expected: Revision,
        name: String,
        description: String,
    },
    SetRule {
        group: GroupId,
        expected: Revision,
        rule: Rule,
    },
    Members {
        group: GroupId,
        expected: Revision,
        add: Vec<String>,
        remove: Vec<String>,
    },
    Delete {
        group: GroupId,
        expected: Revision,
    },
}
impl Command {
    pub fn group(&self) -> GroupId {
        match self {
            Self::Create { group, .. }
            | Self::Edit { group, .. }
            | Self::SetRule { group, .. }
            | Self::Members { group, .. }
            | Self::Delete { group, .. } => *group,
        }
    }
    pub(crate) fn expected(&self) -> Option<Revision> {
        match self {
            Self::Create { .. } => None,
            Self::Edit { expected, .. }
            | Self::SetRule { expected, .. }
            | Self::Members { expected, .. }
            | Self::Delete { expected, .. } => Some(*expected),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: GroupId,
    pub kind: GroupKind,
    pub name: String,
    pub description: String,
    pub revision: Revision,
    /// Last group revision at which the member set changed; zero means initially empty.
    pub member_version: i64,
    pub member_count: usize,
    pub rule_version: Option<String>,
    pub deleted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: OperationId,
    pub group: Group,
    pub added: usize,
    pub removed: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Trigger {
    Manual,
    Periodic { slot: String },
    Change { source: String, event: String },
}
#[derive(Clone, Debug)]
pub struct RecalculationRequest {
    pub id: OperationId,
    pub group: GroupId,
    pub expected: Revision,
    pub rule_version: String,
    pub trigger: Trigger,
    pub snapshot: Snapshot,
    pub as_of: Timepoint,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[error("Group request rejected: {self:?}")]
pub enum Rejection {
    InvalidInput,
    TenantMismatch,
    NotFound,
    Deleted,
    KindMismatch,
    VersionConflict,
    IdentityConflict,
    IncompleteSnapshot,
    InvalidStoredDocument,
    VersionExhausted,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RunState {
    Pending,
    Completed(Receipt),
    Rejected(Rejection),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub id: OperationId,
    pub group: GroupId,
    pub state: RunState,
    pub trigger: Trigger,
    pub as_of: Timepoint,
    pub duration_micros: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaPage {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub next: Option<String>,
}

/// Successful SQL can still reject a command before effects; caller must handle both layers.
pub type CommandOutcome<T> = Result<T, Rejection>;
pub type InTransaction<T> =
    Result<CommandOutcome<T>, rss_transactional_messaging_postgres::PgError>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Rejected(#[from] Rejection),
    #[error("Group transaction not started: {0}")]
    NotStarted(rss_transactional_messaging_postgres::PgError),
    #[error("Group transaction rolled back: {0}")]
    RolledBack(rss_transactional_messaging_postgres::PgError),
    #[error("Group rollback is unconfirmed: {0}")]
    RollbackFailed(rss_transactional_messaging_postgres::PgError),
    #[error("Group commit is unconfirmed for {operation:?}: {source}")]
    CommitUnknown {
        operation: Option<OperationId>,
        source: rss_transactional_messaging_postgres::PgError,
    },
    #[error("Group transaction fenced: {0}")]
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
