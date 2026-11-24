//! Hydration uses the owner already verified in the directory's fact snapshot.
use super::super::task_ownership::Owner as Run;
use super::*;
use sources::Owner;

impl Operations {
    pub(super) async fn hydrate(
        &self,
        c: &mut sqlx::PgConnection,
        authority: (&AuthorizedPrincipal, &Grant),
        q: &Query,
        now: i64,
        page: rss_mdm_query::Page<Value>,
    ) -> Result<Page, Error> {
        let (p, grant) = authority;
        let evidence_requested = q.selects("evidence");
        let mut summaries = BTreeMap::new();
        if evidence_requested {
            let (mut device, mut software, mut script, mut collection) =
                (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for row in &page.items {
                let group = match sources::owner(row)? {
                    Owner::Run(Run::Device) => &mut device,
                    Owner::Run(Run::Software) => &mut software,
                    Owner::Run(Run::Script) => &mut script,
                    Owner::Run(Run::Collection) => &mut collection,
                    _ => continue,
                };
                group.push(selection::id(row)?);
            }
            let tenant = p.binding().tenant();
            summaries.extend(
                rss_mdm_device_service::control::directory::run_summaries_on(c, tenant, device)
                    .await
                    .map_err(execution_fault)?
                    .into_iter()
                    .map(|(id, v)| (id, Evidence::Device(v))),
            );
            summaries.extend(
                rss_mdm_software_service::deployment::directory::run_summaries_on(
                    c, tenant, software,
                )
                .await
                .map_err(software_fault)?
                .into_iter()
                .map(|(id, v)| (id, Evidence::Software(v))),
            );
            summaries.extend(
                rss_mdm_script_service::queries::run_summaries_on(c, tenant, script)
                    .await
                    .map_err(super::super::task_reads::script_fault)?
                    .into_iter()
                    .map(|(id, v)| (id, Evidence::Script(Box::new(v)))),
            );
            summaries.extend(
                rss_mdm_inventory_service::collection::execution::queries::run_summaries_on(
                    c, tenant, collection,
                )
                .await?
                .into_iter()
                .map(|(id, v)| (id, Evidence::Collection(Box::new(v)))),
            );
        }

        let tenant = p.tenant_id();
        let mut items = Vec::with_capacity(page.items.len());
        for row in page.items {
            let owner = sources::owner(&row)?;
            let authorization = row
                .get("authorization")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
            let reauthorization = row
                .get("reauthorization")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
            let metadata: Metadata = serde_json::from_value(row)
                .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
            let id = metadata.id;
            let policy = || {
                metadata
                    .policy
                    .ok_or(Error::Unavailable(Failure::CommandInvariant))
            };
            let evidence = if evidence_requested {
                let value = match owner {
                    Owner::Command(owner) => Evidence::Native {
                        detail: Box::new(
                            self.detail_owned_on(
                                c,
                                p,
                                grant,
                                now,
                                &metadata.device,
                                id,
                                true,
                                owner,
                            )
                            .await?,
                        ),
                    },
                    Owner::Run(Run::Device | Run::Software | Run::Script | Run::Collection) => {
                        summaries
                            .remove(&id)
                            .ok_or(Error::Unavailable(Failure::CommandInvariant))?
                    }
                    Owner::Run(Run::Access) => {
                        use rss_mdm_device_access_postgres::device_access::execution::queries;
                        Evidence::Access(
                            queries::detail_on(c, tenant, policy()?, id, p, grant)
                                .await
                                .map_err(super::super::task_reads::access_fault)?,
                        )
                    }
                    Owner::Run(Run::Credential(profile)) => {
                        use rss_mdm_recovery_credentials::tasks::queries;
                        Evidence::Credential(
                            queries::detail_on(profile, c, tenant, policy()?, id, p, grant)
                                .await
                                .map_err(super::super::task_reads::credential_fault)?,
                        )
                    }
                    Owner::Run(Run::Registration) => {
                        use rss_mdm_registration_service::enrollment::tasks::queries;
                        Evidence::Enrollment(
                            queries::detail_on(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                tenant,
                                policy()?,
                                id,
                                p,
                                grant,
                            )
                            .await
                            .map_err(super::super::task_reads::enrollment_fault)?,
                        )
                    }
                };
                Some(value)
            } else {
                None
            };
            let detail_url = match metadata.kind {
                KindOfOperation::Command => format!(
                    "/api/v1/tenants/{tenant}/devices/{}/operations/{id}",
                    metadata.device
                ),
                KindOfOperation::ActionRun => {
                    format!("/api/v1/tenants/{tenant}/policies/{}/runs/{id}", policy()?)
                }
            };
            items.push(
                q.project_typed(Item {
                    metadata,
                    evidence,
                    authorization,
                    reauthorization,
                    detail_url,
                })
                .map_err(query_error)?,
            );
        }
        Ok(Page {
            items,
            next_cursor: page.next_cursor,
        })
    }
}
