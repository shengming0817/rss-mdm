pub(crate) fn db(_: sqlx::Error) -> crate::installation::Error {
    crate::installation::Error::Unavailable(crate::installation::Failure::Database)
}
