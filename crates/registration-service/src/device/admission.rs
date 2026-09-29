//! Least-privilege checks for this capability in the shared product access role.
pub async fn verify(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT true
 AND has_column_privilege(current_user,'mdm_access.registrations','state','UPDATE')
 AND has_column_privilege(current_user,'mdm_access.credentials','state','UPDATE')
 AND has_column_privilege(current_user,'mdm_access.report_sources','enabled','UPDATE')
"#,
    )
    .fetch_one(connection)
    .await
}
