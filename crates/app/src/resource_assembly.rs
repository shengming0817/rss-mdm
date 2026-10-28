//! Resource assembly and foreign owner adapters, without business decisions.
use crate::{Error, clock::Clock};
use rss_mdm_resource_service::{self as service, transaction::Fault};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
pub(crate) async fn catalog(
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn Clock>,
) -> std::result::Result<Arc<service::ResourceCatalog>, Error> {
    let key = crate::cursor_keys::load(&runtime, tenant).await?;
    Ok(Arc::new(
        service::ResourceCatalog::new(service::Dependencies {
            audit_store: audit,
            runtime: runtime.clone(),
            tenant,
            clock: Arc::new(ResourceClock(clock)),
            cursor_key: key,
            references: Arc::new(crate::resource_usage::StoredReferences {
                policies: rss_mdm_policy_postgres::PolicyReader::bind(runtime, tenant),
            }),
            collections: Arc::new(Validators),
            telemetry: Arc::new(Validators),
            software: Arc::new(Validators),
        })
        .await?,
    ))
}
struct ResourceClock(Arc<dyn Clock>);
impl service::clock::Clock for ResourceClock {
    fn unix_seconds(&self) -> Option<i64> {
        self.0.unix_seconds().ok()
    }
}
struct Validators;
fn inventory(error: rss_mdm_inventory_service::transaction::Fault) -> Fault {
    use rss_mdm_inventory_service::{Error as E, transaction::Fault as F};
    match error {
        F::Storage(e) => Fault::Storage(e),
        F::Sql(e) => Fault::Sql(e),
        F::Request(e) => Fault::Request(match e {
            E::Malformed => service::Error::Malformed,
            E::Conflict => service::Error::Conflict,
            E::Forbidden => service::Error::Forbidden,
            E::Unauthorized => service::Error::Unauthorized,
            _ => service::Error::Unavailable(service::Failure::ResourceStorage),
        }),
    }
}
impl service::inputs::CollectionValidator for Validators {
    fn fence_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> service::inputs::Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_inventory_service::collection::resource_authoring::fence_in(tx)
                .await
                .map_err(inventory)
        })
    }
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: &'a rss_mdm_resource::Version,
    ) -> service::inputs::Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_inventory_service::collection::resource_authoring::validate_in(tx, version)
                .await
                .map_err(inventory)
        })
    }
}
impl service::inputs::TelemetryProfileValidator for Validators {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        template: &'a rss_mdm_resource::Version,
        profile: &'a rss_mdm_resource::TelemetryProfile,
    ) -> service::inputs::Pending<'a, ()> {
        Box::pin(async move {
            use rss_mdm_policy_service::inputs::{ProfileValidationError as E, ProfileValidator};
            rss_mdm_telemetry_service::profile_validation::ProfileValidator
                .validate_in(tx, template, profile)
                .await
                .map(|_| ())
                .map_err(|e| {
                    Fault::Request(match e {
                        E::Invalid => service::Error::Malformed,
                        E::Conflict => service::Error::Conflict,
                        E::Unavailable => {
                            service::Error::Unavailable(service::Failure::ResourceStorage)
                        }
                    })
                })
        })
    }
}
impl service::inputs::SoftwareAuthoringValidator for Validators {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: &'a rss_mdm_resource::Version,
    ) -> service::inputs::Pending<'a, ()> {
        Box::pin(async move {
            use rss_mdm_software_service::catalog::Error as E;
            rss_mdm_software_service::catalog::Reader::new(tx.tenant_id())
                .private_authoring_in(tx, version)
                .await
                .map_err(|e| match e {
                    E::Storage(e) => Fault::Storage(e),
                    E::Sql(e) => Fault::Sql(e),
                    E::Audit(e) => e.into(),
                    E::Fact(e) => e.into(),
                    E::Input => service::Error::Malformed.into(),
                    E::Conflict => service::Error::Conflict.into(),
                    E::Dependency | E::NotAdmitted => service::Error::Forbidden.into(),
                    E::Unsupported => service::Error::Unsupported.into(),
                    E::Missing => {
                        service::Error::Resource(service::error::ResourceError::Missing).into()
                    }
                    E::Capacity | E::Integrity | E::Content => {
                        service::Error::Unavailable(service::Failure::ResourceSoftwareIntegrity)
                            .into()
                    }
                })
        })
    }
}

pub(crate) struct SoftwareResources(pub(crate) rss_mdm_resource_service::software::SoftwareWriter);
fn resource_write_error(
    error: rss_mdm_resource_service::transaction::Fault,
) -> rss_mdm_software_service::catalog::Error {
    use rss_mdm_resource_service::{Error as E, transaction::Fault as F};
    use rss_mdm_software_service::catalog::Error as S;
    match error {
        F::Storage(e) => S::Storage(e),
        F::Sql(e) => S::Sql(e),
        F::Request(E::Conflict) => S::Conflict,
        F::Request(E::Malformed) => S::Input,
        F::Request(_) => S::Integrity,
    }
}
impl rss_mdm_software_service::management::resource::ResourceWriter for SoftwareResources {
    fn partition(
        &self,
        resource: &str,
    ) -> rss_mdm_software_service::catalog::Result<
        rss_transactional_messaging::message::PartitionIdentity,
    > {
        self.0.partition(resource).map_err(resource_write_error)
    }
    fn import_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        operation: uuid::Uuid,
        expected: u64,
        version: &'a rss_mdm_resource::Version,
        at: rss_contract::Timepoint,
    ) -> rss_mdm_software_service::management::resource::Pending<'a, u64> {
        Box::pin(async move {
            self.0
                .import_in(tx, operation, expected, version, at)
                .await
                .map_err(resource_write_error)
        })
    }
    fn installer_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        operation: uuid::Uuid,
        version: &'a rss_mdm_resource::Version,
        filename: &'a str,
        at: rss_contract::Timepoint,
    ) -> rss_mdm_software_service::management::resource::Pending<'a, u64> {
        Box::pin(async move {
            self.0
                .installer_in(tx, operation, version, filename, at)
                .await
                .map_err(resource_write_error)
        })
    }
}
