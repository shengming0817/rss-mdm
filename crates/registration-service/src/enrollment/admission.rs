//! Least-privilege checks for this capability in the shared product access role.
pub async fn verify(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT true
 AND NOT has_column_privilege(current_user,'mdm_access.grants','state','UPDATE')
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.requests',col,'UPDATE')) FROM unnest(ARRAY['state','password_digest','password_version','credential_ref','expires_at']) col)
 AND has_column_privilege(current_user,'mdm_access.enrollment_certificates','server_nonce','UPDATE')
"#).fetch_one(connection).await
}
