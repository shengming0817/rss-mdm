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
    ) -> rss_mdm_resource_service::inputs::Pending<'a, u64, Self::Error> {
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
    fn page_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
        after: Option<&'a rss_mdm_resource_service::references::Position>,
        limit: usize,
    ) -> rss_mdm_resource_service::inputs::Pending<
        'a,
        Vec<rss_mdm_resource_service::references::Entry>,
        Self::Error,
    > {
        Box::pin(async move {
            use rss_mdm_resource_service::references::{Entry, Kind, Release, Retention, Role};
            use sqlx::Row;
            if !(1..=1001).contains(&limit) {
                return Err(rss_mdm_resource_service::Error::Malformed.into());
            }
            let sources = [
                (
                    Kind::PolicyVersion,
                    Role::PolicyAction,
                    format!(
                        "SELECT id,version,current FROM ({}) facts",
                        rss_mdm_policy_postgres::resource_reference_facts_sql(
                            rss_mdm_install_support::StorageProfile::Mdm
                        )
                    ),
                ),
                (
                    Kind::SoftwarePublication,
                    Role::PublicationSubject,
                    format!(
                        "SELECT id,''::text AS version,false AS current FROM ({}) facts",
                        rss_mdm_software_service::publication::references::FACTS_SQL
                    ),
                ),
                (
                    Kind::SoftwareCatalog,
                    Role::CatalogVersion,
                    format!(
                        "SELECT id,version,false AS current FROM ({}) facts",
                        rss_mdm_software_service::catalog::RESOURCE_REFERENCE_FACTS_SQL
                    ),
                ),
                (
                    Kind::CollectionProfile,
                    Role::CollectionTemplate,
                    format!(
                        "SELECT id,version,false AS current FROM ({}) facts",
                        rss_mdm_resource_postgres::PROFILE_REFERENCE_FACTS_SQL
                    ),
                ),
            ];
            let mut items = Vec::new();
            for (kind, role, facts) in sources {
                if after.is_some_and(|p| kind < p.0) {
                    continue;
                }
                let key = after
                    .filter(|p| p.0 == kind)
                    .map(|p| (p.1.clone(), p.2.clone()));
                let sql = format!(
                    "SELECT * FROM ({facts}) facts WHERE ($4::text IS NULL OR (id COLLATE \"C\",version COLLATE \"C\")>($4,$5)) ORDER BY id COLLATE \"C\",version COLLATE \"C\" LIMIT $6"
                );
                let tenant = tx.tenant_id().to_string();
                let resource = resource.to_owned();
                let version = version.to_owned();
                let rows = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                                .bind(tenant)
                                .bind(resource)
                                .bind(version)
                                .bind(key.as_ref().map(|p| &p.0))
                                .bind(key.as_ref().map(|p| &p.1))
                                .bind(limit as i64)
                                .fetch_all(c)
                                .await
                        })
                    })
                    .await?;
                for row in rows {
                    items.push(Entry {
                        kind,
                        role,
                        id: row.try_get("id")?,
                        version: if kind == Kind::SoftwarePublication {
                            None
                        } else {
                            Some(row.try_get("version")?)
                        },
                        retention: match kind {
                            Kind::PolicyVersion if row.try_get("current")? => {
                                Retention::CurrentVersion
                            }
                            Kind::PolicyVersion => Retention::HistoricalVersion,
                            Kind::CollectionProfile => Retention::UnarchivedVersion,
                            _ => Retention::RetainedRecord,
                        },
                        release: if kind == Kind::CollectionProfile {
                            Release::ArchiveReferencingVersion
                        } else {
                            Release::RetainedImmutable
                        },
                    });
                }
            }
            items.sort_by_key(Entry::position);
            items.truncate(limit);
            Ok(items)
        })
    }
}
