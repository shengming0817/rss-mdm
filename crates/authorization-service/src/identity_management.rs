//! Identity management consumes the same persisted product grants as business authorization.
use crate::{Error, Permission, context::AuthorizedPrincipal};
use serde::Serialize;

pub struct IdentityManagementPolicy {
    instance: String,
}
impl IdentityManagementPolicy {
    pub fn new(instance: &str) -> Result<Self, Error> {
        crate::canonical_uuid(instance).map_err(|_| Error::Configuration)?;
        Ok(Self {
            instance: instance.into(),
        })
    }
    pub fn identity_navigation(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<IdentityNavigation, Error> {
        proof.check_live()?;
        if proof.instance_id() != self.instance {
            return Err(Error::Unauthorized);
        }
        // Require the loaded snapshot even when neither capability is granted.
        proof.authorization()?;
        Ok(IdentityNavigation {
            manage_accounts: proof
                .require(Permission::IdentityAccountsManage, None)
                .is_ok(),
            manage_providers: proof
                .require(Permission::IdentityProvidersManage, None)
                .is_ok(),
        })
    }
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityNavigation {
    pub manage_accounts: bool,
    pub manage_providers: bool,
}
impl rss_identity_postgres::ManagementPolicy for IdentityManagementPolicy {
    fn authorize<'a>(
        &'a self,
        context: &'a rss_identity_postgres::ManagementContext<'a>,
        connection: &'a mut sqlx::PgConnection,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        rss_identity_postgres::ReauthenticationRequirement,
                        rss_identity_postgres::ManagementDenied,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            use rss_identity_postgres::{
                ManagementDenied, ManagementOperation as Op, ReauthenticationRequirement as Auth,
            };
            context.check_live()?;
            if context.instance().to_string() != self.instance
                || context
                    .target()
                    .is_some_and(|target| target.tenant != context.actor().tenant)
            {
                return Err(ManagementDenied);
            }
            // Identity verifies freshness and consumes operation-bound proofs for self-service.
            // HostRecovery is not an administrator-selected bypass of that ceremony.
            if context.operation() == Op::AuthorizeWebauthnRecovery {
                return Err(ManagementDenied);
            }
            if matches!(
                context.operation(),
                Op::RegisterWebauthn | Op::RemoveWebauthn | Op::RecoverWebauthn
            ) {
                return if context.target() == Some(context.actor()) {
                    Ok(Auth::None)
                } else {
                    Err(ManagementDenied)
                };
            }
            if context.operation() == Op::ChangeOwnPassword {
                return if context.target() == Some(context.actor()) {
                    Ok(Auth::Recent(std::time::Duration::from_secs(300)))
                } else {
                    Err(ManagementDenied)
                };
            }
            let tenant = context.actor().tenant.to_string();
            crate::store::lock(connection, &tenant, &self.instance)
                .await
                .map_err(|_| ManagementDenied)?;
            let snapshot = crate::snapshot_on(connection, &tenant, &self.instance)
                .await
                .map_err(|_| ManagementDenied)?;
            if context.operation() == Op::ReadLatestProfile
                && context.target() == Some(context.actor())
            {
                return Ok(Auth::None);
            }
            let permission = match context.operation() {
                Op::ReadProfileSources => Permission::UserAttributeDefinitionsRead,
                Op::ReadLatestProfile => Permission::UserProfilesRead,
                Op::ReadLocalProfile | Op::UpdateLocalProfile => Permission::IdentityAccountsManage,

                Op::ProvisionAccount(target) => {
                    let installation = snapshot.installation.as_ref().ok_or(ManagementDenied)?;
                    if installation.is_management(&target.to_string()) {
                        return Err(ManagementDenied);
                    }
                    Permission::TenantAdministratorCreate
                }
                Op::ListProviders
                | Op::CreateProvider
                | Op::UpdateProvider(_)
                | Op::SetProviderEnabled(_, _)
                | Op::TestProvider(_) => Permission::IdentityProvidersManage,
                _ => Permission::IdentityAccountsManage,
            };
            snapshot
                .require_management(context, permission)
                .map_err(|_| ManagementDenied)?;
            if matches!(
                context.operation(),
                Op::SetAccountEnabled(false) | Op::SetMembership(false)
            ) && snapshot
                .installation
                .as_ref()
                .ok_or(ManagementDenied)?
                .is_management(&tenant)
                && let Some(target) = context.target()
            {
                let protected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.authorization_initializations WHERE tenant_id=$1::uuid AND instance=$2::uuid AND principal=$3::uuid)")
                        .bind(&tenant).bind(&self.instance).bind(target.principal.as_uuid().to_string())
                        .fetch_one(connection).await.map_err(|_| ManagementDenied)?;
                if protected {
                    return Err(ManagementDenied);
                }
            }
            context.check_live()?;
            Ok(match context.operation() {
                Op::ListAccounts
                | Op::ListProviders
                | Op::ReadProfileSources
                | Op::ReadLatestProfile
                | Op::ReadLocalProfile => Auth::None,
                _ => Auth::Recent(std::time::Duration::from_secs(300)),
            })
        })
    }
}
