pub(crate) fn db(_: sqlx::Error) -> crate::deployment::Error {
    crate::deployment::Error::Unavailable(crate::deployment::Failure::Database)
}
