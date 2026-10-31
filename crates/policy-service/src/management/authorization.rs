use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
};
use rss_mdm_policy::Action;
pub fn authorize_action(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    action: &rss_mdm_policy::Action,
) -> std::result::Result<(), crate::Error> {
    if matches!(action, Action::EnsureAgentInstalled { .. }) {
        snapshot.require_all_devices(proof, Permission::Enrollment)?;
    }
    snapshot.require_all_devices(proof, action_permission(action))?;
    Ok(())
}

pub fn action_permission(action: &Action) -> Permission {
    match *action {
        Action::Credential { ref operation, .. } => match operation {
            rss_mdm_policy::CredentialOperation::RotateRssLogin { .. }
            | rss_mdm_policy::CredentialOperation::VerifyRssLogin { .. }
            | rss_mdm_policy::CredentialOperation::RotateLocalAdministrator { .. }
            | rss_mdm_policy::CredentialOperation::VerifyLocalAdministrator { .. } => {
                Permission::AccountWrite
            }
            _ => Permission::SecurityOperate,
        },
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. }
        | Action::AgentCollection { .. }
        | Action::TelemetryProfile { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,
        Action::Software { .. } | Action::EnsureAgentInstalled { .. } => Permission::SoftwareDeploy,
        Action::RequestMdmEnrollment { .. } => Permission::Enrollment,
        Action::DeviceAccess { .. } => Permission::AccountWrite,
        Action::UnmanageDevice { .. } => Permission::DeviceUnmanage,
    }
}

use crate::authorization::Subject;
use crate::transaction::*;
use rss_mdm_policy::{SelfServiceAccess as Access, SelfServiceSelector as Selector};
pub fn selectors(
    config: &rss_mdm_policy::SelfService,
    tenant: &str,
    instance: &str,
) -> Result<Vec<Subject>> {
    let Some(Access::Users { selectors }) = &config.access else {
        return Ok(Vec::new());
    };
    let subjects: Vec<_> = selectors
        .iter()
        .map(|selector| match selector {
            Selector::User {
                instance_id,
                tenant_id,
                principal_id,
            } => Subject::User {
                user: crate::authorization::User {
                    instance_id: instance_id.to_string(),
                    tenant_id: tenant_id.to_string(),
                    principal_id: principal_id.to_string(),
                },
            },
            Selector::UserGroup { id } => Subject::UserGroup { id: *id },
            Selector::IdpGroup { source, id } => Subject::IdpGroup {
                source: source_coordinates(source),
                id: id.clone(),
            },
            Selector::Department {
                source,
                id,
                matching,
            } => Subject::Department {
                source: source_coordinates(source),
                id: id.clone(),
                matching: match matching {
                    rss_mdm_policy::SelfServiceDepartmentMatch::Exact => {
                        crate::authorization::DepartmentMatch::Exact
                    }
                    rss_mdm_policy::SelfServiceDepartmentMatch::Subtree => {
                        crate::authorization::DepartmentMatch::Subtree
                    }
                },
            },
        })
        .collect();
    for subject in &subjects {
        checked_input(subject.validate(tenant, instance))?;
    }
    Ok(subjects)
}
fn source_coordinates(source: &rss_mdm_policy::SelfServiceSource) -> crate::authorization::Source {
    crate::authorization::Source {
        provider_id: source.provider_id,
        issuer: source.issuer.clone(),
        configuration_version: source.configuration_version,
    }
}

pub fn validate_access(
    config: &rss_mdm_policy::SelfService,
    tenant: &str,
    instance: &str,
) -> std::result::Result<(), Error> {
    selectors(config, tenant, instance)
        .map(|_| ())
        .map_err(|e| match e {
            Fault::Request(e) => e,
            _ => Error::Malformed,
        })
}
