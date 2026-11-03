//! Explicit Policy transaction bindings and foreign-owner adapters.
use rss_mdm_policy_service::{application::Application, events::Events};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub(crate) async fn application(
    owner: &crate::owner_storage::OwnerRuntime,
    tenant: TenantId,
    key: &[u8],
    clock: Arc<dyn crate::clock::Clock>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
) -> Result<Arc<Application>, crate::Error> {
    let configuration = configuration(
        owner.runtime.clone(),
        owner.audit.clone(),
        tenant,
        protection,
        content,
    )
    .await?;
    let changes = changes(owner.runtime.clone(), tenant).await?;
    Ok(Arc::new(
        Application::new(rss_mdm_policy_service::application::Dependencies {
            profile: rss_mdm_install_support::StorageProfile::Mdm,
            audit_store: owner.audit.clone(),
            runtime: owner.runtime.clone(),
            tenant,
            clock: Arc::new(crate::clock::PolicyClock(clock)),
            cursor_key: key,
            objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
            changes,
            configuration: Some(configuration),
        })
        .await?,
    ))
}
pub(crate) async fn events(
    application: Arc<Application>,
    materials: Arc<EventInputs>,
    software_materials: Arc<rss_mdm_software_service::deployment::Materials>,
    enrollment_materials: Arc<rss_mdm_registration_service::enrollment::tasks::Materials>,
    credential_materials: Vec<Arc<rss_mdm_recovery_credentials::tasks::Materials>>,
) -> Result<Arc<Events>, crate::Error> {
    let scripts = Arc::new(
        rss_mdm_script_service::Transactions::bind(
            application.runtime.clone(),
            application.tenant,
            application.audit_store.clone(),
            Arc::new(rss_mdm_script_service::Materials {
                agent_store: Arc::new(super::agent_facts::AgentFacts),
                source: materials.source.clone(),
                capacity: Arc::new(super::capacity::Capacity),
                instance: materials.instance.clone(),
            }),
        )
        .await
        .map_err(|_| crate::Error::Configuration(crate::ConfigIssue::CommandStorage))?,
    );
    let collections = Arc::new(
        rss_mdm_inventory_service::collection::execution::Transactions::bind(
            application.runtime.clone(),
            application.tenant,
            application.audit_store.clone(),
            Arc::new(
                rss_mdm_inventory_service::collection::execution::Materials {
                    agent_store: Arc::new(super::agent_facts::AgentFacts),
                    source: Arc::new(super::collection_ports::Source(materials.source.clone())),
                    capacity: Arc::new(super::capacity::Capacity),
                    native: Arc::new(super::collection_ports::Delivery {
                        protection: materials.protection.clone(),
                    }),
                },
            ),
        )
        .await?,
    );
    let software = Arc::new(
        rss_mdm_software_service::deployment::Transactions::bind(
            application.runtime.clone(),
            application.tenant,
            application.audit_store.clone(),
            software_materials,
        )
        .await
        .map_err(super::owner_errors::software)?,
    );
    let enrollment = Arc::new(
        rss_mdm_registration_service::enrollment::tasks::Transactions::bind(
            rss_mdm_install_support::StorageProfile::Mdm,
            application.runtime.clone(),
            application.tenant,
            application.audit_store.clone(),
            enrollment_materials,
        )
        .await
        .map_err(super::owner_errors::enrollment)?,
    );
    let mut credentials = Vec::new();
    for materials in credential_materials {
        let profile = if materials.product.is_some() {
            rss_mdm_install_support::StorageProfile::Da
        } else {
            rss_mdm_install_support::StorageProfile::Mdm
        };
        credentials.push(Arc::new(
            rss_mdm_recovery_credentials::tasks::Transactions::bind(
                profile,
                application.runtime.clone(),
                application.tenant,
                application.audit_store.clone(),
                materials,
            )
            .await
            .map_err(super::owner_errors::credential)?,
        ));
    }
    let participants = Arc::new(super::policy_ports::Events {
        software,
        enrollment,
        credentials,
        scripts,
        collections,
        configuration: application
            .configuration
            .clone()
            .ok_or(crate::Error::Unsupported)?,
    });
    Ok(Arc::new(Events {
        application,
        execution: participants.clone(),
        progress: participants,
    }))
}
#[expect(
    clippy::too_many_arguments,
    reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
)]
pub(crate) async fn management(
    application: &Arc<Application>,
    software_inputs: Arc<rss_mdm_software_service::deployment::Inputs>,
    enrollment_entries: rss_mdm_registration_service::enrollment::task::Entries,
    key: &[u8],
    content: Option<Arc<rss_mdm_content_service::Store>>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    mdm_software_enabled: bool,
    signing_enabled: bool,
    recovery_enabled: bool,
) -> Result<Arc<rss_mdm_policy_service::management::Policies>, crate::Error> {
    let store = Arc::new(
        rss_mdm_policy_postgres::PolicyStore::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            application.runtime.clone(),
            application.tenant,
            rss_mdm_policy_service::transaction::deadline(),
        )
        .await
        .map_err(|_| crate::Error::Unavailable(crate::Failure::PlanningStorage))?,
    );
    Ok(Arc::new(rss_mdm_policy_service::management::Policies::new(
        rss_mdm_policy_service::management::Dependencies {
            profile_validator: Arc::new(
                rss_mdm_telemetry_service::profile_validation::ProfileValidator,
            ),
            cursor_key: key.to_vec(),
            runtime: application.runtime.clone(),
            audit_store: application.audit_store.clone(),
            tenant: application.tenant,
            policy_store: store,
            inputs: Arc::new(super::policy_ports::Publication {
                software: software_inputs,
                enrollment_entries,
                signing_enabled,
            }),
            credentials: Some(Arc::new(
                rss_mdm_recovery_credentials::tasks::publication::Inputs::bind(
                    application.runtime.clone(),
                    application.tenant,
                    signing_enabled && recovery_enabled,
                ),
            )),
            script: Some(Arc::new(rss_mdm_script_service::inputs::Inputs::bind(
                application.runtime.clone(),
                application.tenant,
                content.clone(),
                signing_enabled,
            ))),
            collections: Some(Arc::new(
                rss_mdm_inventory_service::collection::execution::inputs::Inputs::bind(
                    application.runtime.clone(),
                    application.tenant,
                    content.clone(),
                    Arc::new(super::collection_ports::Delivery {
                        protection: protection.clone(),
                    }),
                ),
            )),
            configuration: Some(Arc::new(
                rss_mdm_policy_service::configuration::publication::Publications {
                    runtime: application.runtime.clone(),
                    tenant: application.tenant,
                    content,
                    protection,
                },
            )),
            changes: application.changes.clone(),
            mdm_software_enabled,
        },
    )))
}
pub(crate) struct ScopeDependents(
    pub rss_mdm_policy_service::management::scope_changes::ScopeChanges,
);
fn scope_error(
    e: rss_mdm_policy_service::transaction::Fault,
) -> rss_mdm_scope_service::transaction::Fault {
    use rss_mdm_policy_service::{Error as E, transaction::Fault as F};
    use rss_mdm_scope_service::{Error as S, Failure, transaction::Fault};
    match e {
        F::Storage(e) => Fault::Storage(e),
        F::Sql(e) => Fault::Sql(e),
        F::Request(e) => match e {
            E::Conflict => S::Conflict.into(),
            E::Malformed => S::Malformed.into(),
            E::Forbidden | E::Unauthorized => S::Forbidden.into(),
            E::NotFound | E::ResourceMissing => S::NotFound.into(),
            E::CommitUnknown => S::CommitUnknown.into(),
            E::RollbackFailed => S::RollbackFailed.into(),
            _ => S::Unavailable(Failure::Storage).into(),
        },
    }
}
impl rss_mdm_scope_service::sources::ScopeDependents for ScopeDependents {
    fn used_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
    ) -> rss_mdm_scope_service::sources::Pending<'a, bool, rss_mdm_scope_service::transaction::Fault>
    {
        Box::pin(async move { self.0.used_in(tx, scope).await.map_err(scope_error) })
    }
    fn references_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
        after: Option<uuid::Uuid>,
        limit: usize,
    ) -> rss_mdm_scope_service::sources::Pending<
        'a,
        Vec<rss_mdm_scope_service::references::Entry>,
        rss_mdm_scope_service::transaction::Fault,
    > {
        Box::pin(async move {
            use rss_mdm_scope_service::references::{Entry, Kind, Release};
            self.0
                .references_in(tx, scope, after, limit)
                .await
                .map_err(scope_error)?
                .into_iter()
                .map(|r| {
                    Ok(Entry {
                        kind: Kind::Policy,
                        id: r.id,
                        version: r.version,
                        revision: r.revision,
                        roles: rss_mdm_scope_service::transaction::stored(serde_json::from_value(
                            serde_json::json!(r.roles),
                        ))?,
                        release: if r.archived {
                            Release::RetainedArchivedPolicy
                        } else {
                            Release::EditReferencingPolicy
                        },
                    })
                })
                .collect()
        })
    }
    fn publication_recorded_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
        run: uuid::Uuid,
    ) -> rss_mdm_scope_service::sources::Pending<'a, (), rss_mdm_scope_service::transaction::Fault>
    {
        Box::pin(async move {
            self.0
                .publication_recorded_in(tx, scope, run)
                .await
                .map_err(scope_error)
        })
    }
}

pub(crate) async fn changes(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: TenantId,
) -> Result<Arc<dyn rss_mdm_policy_service::inputs::ExecutionChanges>, crate::Error> {
    let messaging = rss_reconcile_postgres::PgMessagingStore::new(
        runtime.clone(),
        tenant,
        rss_mdm_policy_service::transaction::deadline(),
    )
    .await
    .map_err(|_| crate::Error::Unavailable(crate::Failure::PlanningStorage))?;
    Ok(Arc::new(super::policy_ports::Changes {
        reader: rss_mdm_policy_postgres::PolicyReader::bind(
            rss_mdm_install_support::StorageProfile::Mdm,
            runtime,
            tenant,
        ),
        messaging,
        targets: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
        )),
    }))
}
pub(crate) async fn configuration(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: TenantId,
    protection: Arc<rss_mdm_native_protection::Protector>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
) -> Result<Arc<rss_mdm_policy_service::configuration::Transactions>, crate::Error> {
    let changes = changes(runtime.clone(), tenant).await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
    let audit = Arc::new(
        audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    Ok(Arc::new(
        rss_mdm_policy_service::configuration::Transactions::bind(
            rss_mdm_policy_service::configuration::Dependencies {
                runtime,
                tenant,
                audit_store: audit,
                source: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
                )),
                protection: protection.clone(),
                content,
                channels: Arc::new(super::configuration_channels::ConfigurationChannels {
                    protection,
                }),
                changes,
            },
        )
        .await?,
    ))
}

pub(crate) struct EventInputs {
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub instance: String,
}
