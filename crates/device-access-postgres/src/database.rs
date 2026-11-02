pub(crate) fn db(_: sqlx::Error) -> crate::Error {
    crate::Error::Storage
}
