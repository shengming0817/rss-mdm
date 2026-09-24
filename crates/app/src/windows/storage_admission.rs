//! Least-privilege checks for this capability in the shared product access role.
pub(crate) async fn verify(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT true
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.management_sessions',col,'UPDATE')) FROM unnest(ARRAY['state','last_message','correlation','nonce','client_authenticated','run_id']) col)
"#).fetch_one(connection).await
}
