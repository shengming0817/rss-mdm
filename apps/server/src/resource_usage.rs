//! Composition of reference facts; archive decisions belong to Resource.
/// Stateless archive participant; each store projects its own references.
pub(crate) struct StoredReferences {
    pub(crate) policies: rss_mdm_policy_postgres::PolicyReader,
}
impl rss_mdm_resource_service::UsageReader for StoredReferences {
    type Error = rss_mdm_resource_service::transaction::Fault;
    fn count_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = rss_mdm_resource_service::transaction::Result<u64>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let assignments = rss_mdm_resource_service::transaction::checked(
                self.policies
                    .resource_usage_in(tx, resource, version)
                    .await?,
            )?;
            let publications =
                rss_mdm_software_service::publication::references::count_in(tx, resource, version)
                    .await?;
            let approvals =
                rss_mdm_software_service::catalog::reference_count_in(tx, resource, version)
                    .await
                    .map_err(|_| {
                        rss_mdm_resource_service::Error::Unavailable(
                            rss_mdm_resource_service::Failure::ResourceStorage,
                        )
                    })?;
            let profiles =
                rss_mdm_resource_postgres::profile_references_in(tx, resource, version).await?;
            assignments
                .checked_add(profiles)
                .and_then(|n| n.checked_add(publications))
                .and_then(|n| n.checked_add(approvals))
                .ok_or_else(|| {
                    rss_mdm_resource_service::Error::Unavailable(
                        rss_mdm_resource_service::Failure::ResourceStorage,
                    )
                    .into()
                })
        })
    }
}
