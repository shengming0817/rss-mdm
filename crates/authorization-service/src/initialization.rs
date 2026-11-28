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
fn identity_failure(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Storage,
    }
}
pub async fn initialize(
    profile: rss_mdm_install_support::StorageProfile,
    authority: &Authority,
    store: &AuditStore,
    input: Initialization,
    audit: &RequestAudit,
    cutoff: rss_request_context::Deadline,
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
    let user = verify_local(
        authority,
        audit.binding()?,
        expected,
        login,
        password,
        cutoff,
    )
    .await?
    .0;
    crate::store::initialize_verified_user(profile, store, user, operation_id, audit, cutoff).await
}

/// 原凭据的真实认证与精确主体核对；不创建账户、不恢复密码，也不新增授权。
pub async fn verify_local(
    authority: &Authority,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    expected: User,
    login: LoginKey,
    password: Password,
    cutoff: rss_request_context::Deadline,
) -> Result<VerifiedLocal, Error> {
    expected.validate(&expected.tenant_id, &expected.instance_id)?;
    crate::canonical_uuid(&expected.tenant_id)?;
    crate::canonical_uuid(&expected.instance_id)?;
    let tenant = TenantId::parse(&expected.tenant_id).map_err(|_| Error::Malformed)?;
    if tenant != binding.tenant() {
        return Err(Error::Forbidden);
    }
    let issued = authority
        .login_local(
            binding,
            login,
            password,
            AttemptSource::parse("authorization-initialization")
                .map_err(|_| Error::Configuration)?,
            None,
            cutoff,
        )
        .await
        .map_err(identity_failure)?;
    let session = authority
        .inspect_session(
            binding,
            SessionSecret::parse(issued.secret().expose().into()).map_err(|_| Error::Corrupt)?,
            cutoff,
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
        .revoke_current_session(session, cutoff)
        .await
        .map_err(identity_failure)?;
    if user != expected {
        return Err(Error::Forbidden);
    }
    Ok(VerifiedLocal(user))
}

/// 离线转交复用原管理员身份补齐所属租户的完整授权；调用者先完成 verify_local。
/// 原主体必须仍有直接租户授权管理权，审计和授权在同一事务提交。
pub async fn complete_verified_administrator(
    profile: rss_mdm_install_support::StorageProfile,
    store: &AuditStore,
    verified: VerifiedLocal,
    operation: uuid::Uuid,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    let user = verified.0;
    if operation.is_nil() {
        return Err(Error::Malformed);
    }
    user.validate(&audit.binding()?.tenant().to_string(), &user.instance_id)?;
    audit.set_principal(&user.principal_id, &user.instance_id);
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::Authorization,
        operation,
        "authorization_transfer",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.require_final_request();

    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        rss_mdm_audit_integration::operation::OperationOwner::Authorization,
        &format!("authorization-transfer:{operation}"),
        200,
        "success",
        None,
    )?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
    let result=store.write(
            audit.binding()?,&budget.source_control(),(profile,store,&user,operation,audit,fact),|(profile,store,user,operation,audit,fact),tx|Box::pin(async move {
        let mut context=(*profile,*user,*operation);
        let (receipt,replay)=tx.with_connection_context(&mut context,|(profile,user,operation),c|Box::pin(async move {
            crate::lock_on(*profile, c,&user.tenant_id,&user.instance_id).await?;
            let installation=crate::tenancy::InstallationTenants::load(*profile, c).await?;
            let desired=crate::store::administrator_rule((*user).clone(),installation.is_management(&user.tenant_id));
            let rules=crate::snapshot_on(*profile, c,&user.tenant_id,&user.instance_id).await?;
            if let Some(existing)=rules.rules.iter().find(|r|r.id==*operation) {
                if existing.value.as_ref()!=Some(&desired) {return Err(Error::Conflict)}
                return Ok((Receipt{id:existing.id,revision:existing.revision,deleted:false},true));
            }
            let authorized=rules.rules.iter().filter_map(|r|r.value.as_ref()).any(|r|matches!(&r.subject,crate::Subject::User{user:subject} if subject==*user) && r.grants.iter().any(|g|g.covers(crate::Permission::AuthorizationWrite,None)));
            if !authorized {return Err(Error::Forbidden)}
            let receipt=crate::store::grant_verified_administrator_on(*profile, c,(*user).clone(),*operation).await?;
            Ok::<_,Error>((receipt,false))
        })).await?;
        (if replay { Ok(()) } else { store.append(tx, fact).await })?;
        audit.mark_commit_started();
        Ok(receipt)
    })).await;
    crate::operations::settle(result, audit)
}

/// 只有精确主体的真实本地认证才能构造；不携带可转移的会话秘密。
pub struct VerifiedLocal(User);
impl VerifiedLocal {
    pub fn user(&self) -> &User {
        &self.0
    }
}

/// Authenticate the exact installer subject, initialize its real rule, and freeze baseline evidence.
pub async fn initialize_baseline(
    profile: rss_mdm_install_support::StorageProfile,
    authority: &Authority,
    store: &AuditStore,
    input: Initialization,
    audit: &RequestAudit,
    targets: std::collections::BTreeSet<String>,
    cutoff: rss_request_context::Deadline,
) -> Result<(Receipt, crate::baseline::Authority), Error> {
    let verified = verify_local(
        authority,
        audit.binding()?,
        input.expected,
        input.login,
        input.password,
        cutoff,
    )
    .await?;
    let user = verified.user().clone();
    let receipt = crate::store::initialize_verified_user(
        profile,
        store,
        user.clone(),
        input.operation_id,
        audit,
        cutoff,
    )
    .await?;
    let frozen =
        crate::baseline::Authority::new(audit.binding()?, profile, user, receipt.clone(), targets)?;
    Ok((receipt, frozen))
}
