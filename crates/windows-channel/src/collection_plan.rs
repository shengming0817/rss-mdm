//! Executable Windows native collection plans belong to the protocol owner.
use crate::Error;
use rss_mdm_resource as resource;
pub fn permissions(
    definition: &resource::NativeCollectionDefinition,
) -> Result<Vec<rss_mdm_authorization_service::Permission>, Error> {
    use rss_mdm_authorization_service::{
        Permission,
        native::{self, Request},
    };
    let plan = compile_plan(definition)?;
    let mut permissions = vec![Permission::InventoryCollect];
    for request in plan.requests().map_err(|_| Error::Malformed)? {
        permissions.extend(
            native::required(Request::Windows(
                &rss_mdm_windows_mdm::native::Execution::SyncMl { request },
            ))
            .map_err(|_| Error::Unsupported)?,
        );
    }
    if permissions.contains(&Permission::Credentials) {
        return Err(Error::Unsupported);
    }
    permissions.sort();
    permissions.dedup();
    Ok(permissions)
}
pub async fn eligible_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    registration: uuid::Uuid,
    generation: i64,
    template: &resource::NativeCollectionDefinition,
) -> Result<bool, Error> {
    let facts:Option<(String,i32,String)>=sqlx::query_as("SELECT c.os_version,c.edition,r.purpose FROM mdm_windows.capabilities c JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(c.tenant_id,c.registration,c.generation) WHERE c.tenant_id=$1::uuid AND c.registration=$2 AND c.generation=$3 AND r.state='active'")
        .bind(tenant.to_string()).bind(registration).bind(generation).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
    let Some((version, edition, purpose)) = facts else {
        return Ok(false);
    };
    let enrollment = match purpose.as_str() {
        "primary" => rss_mdm_windows_mdm::native::Enrollment::Primary,
        "windows_declared" => rss_mdm_windows_mdm::native::Enrollment::LinkedCertificate,
        _ => return Ok(false),
    };
    let context = rss_mdm_windows_mdm::native::Context::from_capabilities(
        &version,
        edition
            .try_into()
            .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?,
        rss_mdm_windows_mdm::native::Scope::Device,
        enrollment,
    )
    .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    if compile_plan(template)?.applicable(context).is_err() {
        return Ok(false);
    }
    let environment = resource::CollectionEnvironment {
        build: version.split('.').nth(2).and_then(|v| v.parse().ok()),
        os_version: Some(version),
        edition: Some(edition.to_string()),
        ..Default::default()
    };
    Ok(template.spec().applicability.allows(
        &environment,
        &purpose,
        &[template.spec().adapter.capability().into()].into(),
    ))
}
/// Compile the only executable Windows collection representation.
pub fn compile_plan(
    definition: &resource::NativeCollectionDefinition,
) -> Result<rss_mdm_windows_mdm::native::collection::Plan, Error> {
    use resource::{NativeQuery, WindowsInventory as W, WindowsRead};
    use rss_mdm_windows_mdm::native::collection::{Inventory, Read};
    let reads: std::collections::BTreeMap<String, Read> = definition
        .spec()
        .mappings
        .iter()
        .map(|(field, mapping)| {
            let NativeQuery::Windows(read) = &mapping.query else {
                return Err(Error::Malformed);
            };
            let read = match read {
                WindowsRead::EnrollmentId => Read::EnrollmentId,
                WindowsRead::EnrollmentType => Read::EnrollmentType,
                WindowsRead::Scalar { uri } => Read::Scalar { uri: uri.clone() },
                WindowsRead::Inventory { inventory } => Read::Inventory {
                    inventory: match inventory {
                        W::Win32 => Inventory::Win32,
                        W::Store => Inventory::Store,
                        W::NonStore => Inventory::NonStore,
                        W::System => Inventory::System,
                        W::Network => Inventory::Network,
                        W::InstalledUpdates => Inventory::InstalledUpdates,
                        W::InstallableUpdates => Inventory::InstallableUpdates,
                        W::FailedUpdates => Inventory::FailedUpdates,
                        W::PendingRebootUpdates => Inventory::PendingRebootUpdates,
                    },
                },
            };
            Ok((field.clone(), read))
        })
        .collect::<std::result::Result<_, Error>>()?;
    rss_mdm_windows_mdm::native::collection::Plan::try_from(reads).map_err(|_| Error::Unsupported)
}
