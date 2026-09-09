//! Process diagnostics contain controlled categories, never provider error text or input values.
use crate::Error;
use std::path::PathBuf;
#[derive(Clone, Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("configuration file unavailable or unsafe: {0:?}")]
    ConfigFile(PathBuf),
    #[error("configuration JSON rejected at line {line}, column {column}: {path:?}")]
    ConfigJson {
        path: PathBuf,
        line: usize,
        column: usize,
    },
    #[error("{stage}: {kind}")]
    Stage {
        stage: &'static str,
        kind: &'static str,
    },
    #[error("{stage}: {kind:?}")]
    Io {
        stage: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error(transparent)]
    Migration(#[from] crate::migration::MigrationError),
}
impl ProcessError {
    pub fn at(stage: &'static str, error: Error) -> Self {
        Self::Stage {
            stage,
            kind: match error {
                Error::Configuration => "configuration rejected",
                Error::Unavailable => "dependency unavailable",
                _ => "operation rejected",
            },
        }
    }
}
