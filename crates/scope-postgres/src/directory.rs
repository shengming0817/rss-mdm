use crate::*;
use rss_mdm_query::directory::Query;
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "revision" => "revision",
        "deleted" => "deleted",
        "calculationRevision" => "calculation_revision",
        "resolutionRevision" => "resolution_revision",
        "ready" => "(mdm_scope.scope_admission(id,NULL)->>'state'='fresh')",
        _ => unreachable!("checked Scope field"),
    }
}

impl ScopeBinding {
    pub async fn directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        q: &Query,
        after: Option<&rss_mdm_query::directory::Position>,
    ) -> Result<Vec<serde_json::Value>, BindingError> {
        self.validate_in(tx)?;
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT jsonb_build_object('id',id,'revision',revision,'deleted',deleted,'calculationRevision',calculation_revision,'resolution',resolution,'resolutionRevision',resolution_revision) FROM mdm_scope.scopes WHERE tenant_id=",
        );
        sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
        rss_mdm_query_postgres::append(&mut sql, q, after, column)
            .map_err(|_| BindingError::Invalid)?;
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
            })
            .await?)
    }
}
