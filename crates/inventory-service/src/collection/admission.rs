//! Least-privilege checks for this capability in the shared product access role.
pub async fn verify(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT true
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.report_sources',col,'UPDATE')) FROM unnest(ARRAY['next_command','next_sequence']) col)
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.collection_runs',col,'UPDATE')) FROM unnest(ARRAY['attempts','result','reason','batch','digest','sealed_at','delivery_pending']) col)
"#).fetch_one(connection).await
}
