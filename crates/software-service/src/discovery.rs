//! Classification of this owner's read-only work discovery failures.
//! ref: sqlx v0.9.0 sqlx-core/src/error.rs; PostgreSQL errcodes-appendix.
use rss_reconcile::ErrorKind;
pub(crate) fn classify(error: &sqlx::Error) -> ErrorKind {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => ErrorKind::Transient,
        sqlx::Error::Database(error) => match error.code().as_deref() {
            Some("57014") => ErrorKind::Deadline,
            Some(
                "08000" | "08001" | "08003" | "08006" | "40001" | "40P01" | "55P03" | "53300"
                | "57P01" | "57P02" | "57P03",
            ) => ErrorKind::Transient,
            _ => ErrorKind::StorageContract,
        },
        _ => ErrorKind::StorageContract,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_infrastructure_failures_allow_retry() {
        assert_eq!(classify(&sqlx::Error::PoolTimedOut), ErrorKind::Transient);
        assert_eq!(
            classify(&sqlx::Error::Io(std::io::ErrorKind::ConnectionReset.into())),
            ErrorKind::Transient
        );
        for error in [
            sqlx::Error::PoolClosed,
            sqlx::Error::Protocol("invalid frame".into()),
            sqlx::Error::InvalidArgument("invalid binding".into()),
        ] {
            assert_eq!(classify(&error), ErrorKind::StorageContract);
        }
    }
}
