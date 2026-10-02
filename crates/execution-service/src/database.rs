pub(crate) fn db(_: sqlx::Error) -> crate::Error {
    crate::Error::Unavailable(crate::Failure::Database)
}
