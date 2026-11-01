use crate::*;
use rss_mdm_query::directory::Query;
fn column(profile: rss_mdm_install_support::StorageProfile, name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "revision" => "revision",
        "deleted" => "deleted",
        "calculationRevision" => "calculation_revision",
        "resolutionRevision" => "resolution_revision",
        "ready" => crate::storage_profile::sql(profile).directory_column_1,
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
        let profile = self.profile();

        self.validate_in(tx)?;
        let mut sql =
            sqlx::QueryBuilder::new(crate::storage_profile::sql(profile).directory_directory_in_1);
        sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
        rss_mdm_query_postgres::append(
            &mut sql,
            q,
            after,
            match profile {
                rss_mdm_install_support::StorageProfile::Mdm => {
                    |name| column(rss_mdm_install_support::StorageProfile::Mdm, name)
                }
                rss_mdm_install_support::StorageProfile::Da => {
                    |name| column(rss_mdm_install_support::StorageProfile::Da, name)
                }
            },
        )
        .map_err(|_| BindingError::Invalid)?;
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
            })
            .await?)
    }
}
