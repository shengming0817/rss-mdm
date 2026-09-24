//! Least-privilege checks for this capability in the shared product access role.
pub(crate) async fn verify(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT true
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.'||t,col,'UPDATE')) FROM unnest(ARRAY['authorization_rules','user_groups']) t CROSS JOIN unnest(ARRAY['revision','document']) col)
"#).fetch_one(connection).await
}
