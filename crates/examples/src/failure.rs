//! Stage diagnostics contain only static classifications, never provider messages or values.
use anyhow::Result;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
struct Problem {
    pub stage: &'static str,
    pub component: &'static str,
    kind: ProblemKind,
}
#[derive(Debug, Serialize)]
struct Failure {
    problems: Vec<Problem>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "operation or cleanup failed: {} stage(s)",
            self.problems.len()
        )
    }
}
impl std::error::Error for Failure {}
fn problems(stage: &'static str, error: anyhow::Error) -> Vec<Problem> {
    if let Some(failure) = error.downcast_ref::<Failure>() {
        return failure.problems.clone();
    }
    let (component, kind) = if let Some(e) = error.downcast_ref::<rss_observation::Error>() {
        ("observation", observation_kind(e.kind()))
    } else if let Some(e) = error.downcast_ref::<rss_projection::Error>() {
        ("projection", projection_kind(e.kind()))
    } else if error.downcast_ref::<sqlx::Error>().is_some() {
        ("database", ProblemKind::UnavailableOrRejected)
    } else if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        ("runtime", ProblemKind::Deadline)
    } else {
        ("product", ProblemKind::Failed)
    };
    vec![Problem {
        stage,
        component,
        kind,
    }]
}
pub fn at(stage: &'static str, error: impl Into<anyhow::Error>) -> anyhow::Error {
    Failure {
        problems: problems(stage, error.into()),
    }
    .into()
}
pub fn finish<T>(
    result: Result<T>,
    cleanup: impl IntoIterator<Item = (&'static str, Result<()>)>,
) -> Result<T> {
    let mut issues = Vec::new();
    let value = match result {
        Ok(value) => Some(value),
        Err(error) => {
            issues.extend(problems("operation", error));
            None
        }
    };
    for (stage, result) in cleanup {
        if let Err(error) = result {
            issues.extend(problems(stage, error));
        }
    }
    if issues.is_empty() {
        Ok(value.expect("successful operation"))
    } else {
        Err(Failure { problems: issues }.into())
    }
}
/// Only closed classifications can reach the serialized report.
/// ```compile_fail
/// let e = rss_mdm_examples::failure::classified("read", "db", String::from("secret"));
/// ```
pub fn report(error: anyhow::Error) -> serde_json::Value {
    let problems = problems("operation", error);
    let hint = match problems[0].stage {
        "usage" => "usage: rss-mdm-fixture ingest-fixture FILE | project | inspect BATCH_ID",
        "config" => "provide DATABASE_URL and PG_CA_FILE via trusted local configuration",
        "scope" => "provide MDM_SCOPE_FILE containing the trusted operator scope",
        "fixture_read" | "decode" => "check the fixture file, size and versioned report encoding",
        "migration" => {
            "check owner privileges and migration ledger; restore interrupted installation before retry"
        }
        "cancelled" => {
            "operation cancelled; inspect durable state before retry; inspect cleanup stages"
        }
        _ => {
            "inspect durable state before retry; failure does not prove rollback; inspect all cleanup stages"
        }
    };
    serde_json::json!({"problems":problems,"hint":hint})
}

pub(crate) fn classified(
    stage: &'static str,
    component: &'static str,
    kind: ProblemKind,
) -> anyhow::Error {
    Failure {
        problems: vec![Problem {
            stage,
            component,
            kind,
        }],
    }
    .into()
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum ProblemKind {
    InvalidInput,
    Unauthorized,
    Conflict,
    LifecycleConflict,
    StaleEpoch,
    UnknownStream,
    Storage,
    Invariant,
    CommitUnknown,
    RollbackFailed,
    Deadline,
    Closed,
    ScopeMismatch,
    OutOfOrder,
    SourceContract,
    Fenced,
    Unavailable,
    Rejected,
    Cancelled,
    StorageContract,
    UnavailableOrRejected,
    Failed,
    SignalUnavailable,
}
fn observation_kind(kind: rss_observation::ErrorKind) -> ProblemKind {
    match kind {
        rss_observation::ErrorKind::InvalidInput => ProblemKind::InvalidInput,
        rss_observation::ErrorKind::Unauthorized => ProblemKind::Unauthorized,
        rss_observation::ErrorKind::Conflict => ProblemKind::Conflict,
        rss_observation::ErrorKind::LifecycleConflict => ProblemKind::LifecycleConflict,
        rss_observation::ErrorKind::StaleEpoch => ProblemKind::StaleEpoch,
        rss_observation::ErrorKind::UnknownStream => ProblemKind::UnknownStream,
        rss_observation::ErrorKind::Storage => ProblemKind::Storage,
        rss_observation::ErrorKind::Invariant => ProblemKind::Invariant,
        rss_observation::ErrorKind::CommitUnknown => ProblemKind::CommitUnknown,
        rss_observation::ErrorKind::RollbackFailed => ProblemKind::RollbackFailed,
        rss_observation::ErrorKind::Deadline => ProblemKind::Deadline,
        rss_observation::ErrorKind::Closed => ProblemKind::Closed,
    }
}
fn projection_kind(kind: rss_projection::ErrorKind) -> ProblemKind {
    match kind {
        rss_projection::ErrorKind::InvalidInput => ProblemKind::InvalidInput,
        rss_projection::ErrorKind::ScopeMismatch => ProblemKind::ScopeMismatch,
        rss_projection::ErrorKind::OutOfOrder => ProblemKind::OutOfOrder,
        rss_projection::ErrorKind::SourceContract => ProblemKind::SourceContract,
        rss_projection::ErrorKind::Conflict => ProblemKind::Conflict,
        rss_projection::ErrorKind::Fenced => ProblemKind::Fenced,
        rss_projection::ErrorKind::Unavailable => ProblemKind::Unavailable,
        rss_projection::ErrorKind::Rejected => ProblemKind::Rejected,
        rss_projection::ErrorKind::Cancelled => ProblemKind::Cancelled,
        rss_projection::ErrorKind::Deadline => ProblemKind::Deadline,
        rss_projection::ErrorKind::CommitUnknown => ProblemKind::CommitUnknown,
        rss_projection::ErrorKind::RollbackFailed => ProblemKind::RollbackFailed,
        rss_projection::ErrorKind::StorageContract => ProblemKind::StorageContract,
    }
}

/// Distinguish operator cancellation from failure to install/listen for a signal.
pub fn signal(result: std::io::Result<()>) -> anyhow::Error {
    match result {
        Ok(()) => classified("cancelled", "runtime", ProblemKind::Cancelled),
        Err(_) => classified("signal", "runtime", ProblemKind::SignalUnavailable),
    }
}
