pub(crate) fn db(_: sqlx::Error) -> crate::control::Error {
    crate::control::Error::Unavailable(crate::control::Failure::Database)
}
