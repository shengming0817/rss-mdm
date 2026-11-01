pub(crate) fn db(_: sqlx::Error) -> crate::native::Error {
    crate::native::Error::Unavailable(crate::native::Failure::Database)
}
