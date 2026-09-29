//! One-time authorization bootstrap verifies the installed Identity account before seeding a rule.
use crate::{Error, Receipt, User};
use rss_identity_core::{
    account::{LoginKey, Password},
    session::SessionSecret,
};
use rss_identity_postgres::{AttemptSource, Authority, AuthorityError};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_request_context::TenantId;
pub struct Initialization {
    pub expected: User,
    pub login: LoginKey,
    pub password: Password,
    pub operation_id: uuid::Uuid,
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
}
fn identity_failure(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Storage,
    }
}
pub async fn initialize(
    authority: &Authority,
    store: &AuditStore,
    input: Initialization,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    let Initialization {
        expected,
        login,
        password,
        operation_id,
    } = input;
    expected.validate(&expected.tenant_id, &expected.instance_id)?;
    crate::canonical_uuid(&expected.tenant_id)?;
    crate::canonical_uuid(&expected.instance_id)?;
    if operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    let tenant = TenantId::parse(&expected.tenant_id).map_err(|_| Error::Malformed)?;
    let issued = authority
        .login_local(
            tenant,
            login,
            password,
            AttemptSource::parse("authorization-initialization")
                .map_err(|_| Error::Configuration)?,
            None,
            deadline(),
        )
        .await
        .map_err(identity_failure)?;
    let session = authority
        .inspect_session(
            tenant,
            SessionSecret::parse(issued.secret().expose().into()).map_err(|_| Error::Corrupt)?,
            deadline(),
        )
        .await
        .map_err(identity_failure)?;
    let user = User {
        instance_id: session.instance().to_string(),
        tenant_id: session.account().tenant.to_string(),
        principal_id: session.account().principal.as_uuid().to_string(),
    };
    // Never leave a transferable bootstrap credential behind, including a target mismatch.
    authority
        .revoke_current_session(session, deadline())
        .await
        .map_err(identity_failure)?;
    if user != expected {
        return Err(Error::Forbidden);
    }
    crate::store::initialize_verified_user(store, user, operation_id, audit).await
}
