//! Admission permits Apple prerequisite refresh; execution uses the new run context.
use crate::{Error, Target};
use rss_mdm_resource::{CollectionEnvironment, NativeAdapter, NativeCollectionDefinition};
use rss_request_context::TenantId;
use sqlx::PgConnection;
/// Apple admission checks current authority, never historical endpoint evidence.
pub async fn native_on(
    c: &mut PgConnection,
    tenant: TenantId,
    target: &Target,
    template: &NativeCollectionDefinition,
) -> Result<bool, Error> {
    let mut environment = CollectionEnvironment::default();
    let adapter = template.spec().adapter;
    if adapter == NativeAdapter::WindowsRead {
        let facts: Option<(String, i32)> = sqlx::query_as("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
            .bind(tenant.to_string()).bind(target.registration).bind(target.generation).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
        if let Some((version, edition)) = facts {
            environment.build = version.split('.').nth(2).and_then(|v| v.parse().ok());
            environment.os_version = Some(version);
            environment.edition = Some(edition.to_string());
        }
    }
    let enrollment: Option<String> = sqlx::query_scalar("SELECT purpose FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active'")
        .bind(tenant.to_string()).bind(target.registration).bind(target.generation).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
    let Some(enrollment) = enrollment else {
        return Ok(false);
    };
    if adapter == NativeAdapter::WindowsRead {
        let purpose = match enrollment.as_str() {
            "primary" => rss_mdm_registration_service::Purpose::Primary,
            "windows_declared" => rss_mdm_registration_service::Purpose::WindowsDeclared,
            _ => return Ok(false),
        };
        let (Some(version), Some(edition)) = (&environment.os_version, &environment.edition) else {
            return Ok(false);
        };
        let context = crate::native::context(
            version,
            edition.parse().map_err(|_| Error::Malformed)?,
            rss_mdm_windows_mdm::native::Scope::Device,
            purpose,
        )?;
        let plan = crate::input_preparation::windows_collection_plan(template)
            .map_err(|_| Error::Unsupported)?;
        if plan.applicable(context).is_err() {
            return Ok(false);
        }
    } else {
        let rights: Option<i32> = sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant.to_string()).bind(target.registration).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
        let required = adapter.apple_rights().ok_or(Error::Unsupported)? | 1040;
        if rights.is_none_or(|rights| rights & required != required) {
            return Ok(false);
        }
        let user = match &template.spec().scope {
            rss_mdm_resource::TemplateScope::Device => "",
            rss_mdm_resource::TemplateScope::User { identity } => identity,
            _ => return Ok(false),
        };
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND state='active')")
            .bind(tenant.to_string()).bind(target.registration).bind(target.generation).bind(user).fetch_one(&mut *c).await.map_err(crate::database::db)?;
        if !active {
            return Ok(false);
        }
        // Only the device's response for this run may decide its OS version.
        // Keep all control-plane constraints; defer this endpoint constraint until
        // apple-channel compiles the business command with the resolved Context.
        let mut prerequisites = template.spec().applicability.clone();
        prerequisites.minimum_os_version = None;
        return Ok(prerequisites.allows(
            &environment,
            &enrollment,
            &[adapter.capability().into()].into(),
        ));
    }
    let capability = adapter.capability();
    Ok(template
        .spec()
        .applicability
        .allows(&environment, &enrollment, &[capability.into()].into()))
}
