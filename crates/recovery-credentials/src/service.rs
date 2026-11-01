use crate::*;
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use sqlx::{PgConnection, PgPool, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Credentials {
    profile: rss_mdm_install_support::StorageProfile,
    pool: PgPool,
    audit: Arc<AuditStore>,
    keys: Arc<KeyRing>,
    access_audit: Option<Arc<AuditStore>>,
    eligibility: Option<Arc<dyn crate::eligibility::Eligibility>>,
}
impl Credentials {
    pub fn custody(&self) -> crate::Custody<'_> {
        crate::Custody::new(self.profile, self.eligibility.as_deref())
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        pool: PgPool,
        audit: Arc<AuditStore>,
        keys: Arc<KeyRing>,
        access_audit: Option<Arc<AuditStore>>,
        eligibility: Option<Arc<dyn crate::eligibility::Eligibility>>,
    ) -> Self {
        Self {
            profile,
            pool,
            audit,
            keys,
            access_audit,
            eligibility,
        }
    }
    pub fn keys(&self) -> &Arc<KeyRing> {
        &self.keys
    }

    pub async fn list(
        &self,
        principal: &AuthorizedPrincipal,
        device: &str,
        query: &rss_mdm_query::directory::Query,
        codec: &rss_mdm_query::cursor::CursorCodec,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<crate::Material>>, Error>
    {
        let profile = self.profile();

        principal.require(Permission::InventoryRead, Some(device))?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        configure(profile, &mut tx, principal.tenant_id()).await?;
        let snapshot = rss_mdm_authorization_service::snapshot_on(
            profile,
            &mut tx,
            principal.tenant_id(),
            principal.instance_id(),
        )
        .await?;
        snapshot
            .require(principal, Permission::InventoryRead, Some(device))
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let grant = snapshot.query_binding(principal)?;
        let page =
            crate::directory::read(profile, &mut tx, principal, device, &grant, query, codec)
                .await?;
        tx.rollback().await?;
        let mut current = self.pool.begin().await?;
        configure(profile, &mut current, principal.tenant_id()).await?;
        authorize(
            profile,
            &mut current,
            principal,
            device,
            Permission::InventoryRead,
        )
        .await?;
        let snapshot = rss_mdm_authorization_service::snapshot_on(
            profile,
            &mut current,
            principal.tenant_id(),
            principal.instance_id(),
        )
        .await?;
        if snapshot.query_binding(principal)? != grant {
            return Err(Error::ReadConflict);
        }
        current.rollback().await?;
        principal.check_live()?;
        Ok(page)
    }

    /// Ordinary platform recovery disclosure. DA factor materials require the dedicated step-up path.
    pub async fn disclose(
        &self,
        principal: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
        audit: &RequestAudit,
    ) -> Result<Disclosure, Error> {
        self.disclose_inner(principal, device, id, version, None, false, audit)
            .await
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Exact material version, actor, one-use proof and audit are separate disclosure coordinates"
    )]
    async fn disclose_inner(
        &self,
        principal: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
        access: Option<&DisclosureRequest>,
        replay: bool,
        audit: &RequestAudit,
    ) -> Result<Disclosure, Error> {
        let profile = self.profile();

        audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
            rss_mdm_audit_integration::SensitiveAction::CredentialReveal,
        ));
        principal.credentials(device)?;
        principal.bind_audit(audit)?;
        audit.set_action(
            "recovery_credential_read",
            rss_mdm_audit_integration::AuditIntent::Sensitive(
                rss_mdm_audit_integration::SensitiveAction::CredentialReveal,
            ),
        );
        audit.target_device(device);

        let fact = Fact::business(
            audit,
            &format!(
                "recovery:read:{}",
                access.map(|v| v.operation_id).unwrap_or(audit.request_id())
            ),
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Audit)?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
        let source = if access.is_some() {
            self.access_audit.as_ref().ok_or(Error::Unsupported)?
        } else {
            &self.audit
        };
        let attempt = source
            .write(
                rss_request_context::TenantId::parse(principal.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &budget.source_control(),
                (self, principal, device, id, version, audit, fact, access, replay, source),
                |context, tx| {
                    Box::pin(async move {
                        let response = tx
                            .with_connection_context(context, |context, c| {
                                Box::pin(async move {
                                    let (service, principal, device, id, version, _, _, access, replay, _) = context;
                                    if let Some(input)=access {
                                        if *replay {rss_identity_postgres::recheck_authenticated_session_on(c,principal.session()?).await.map_err(|_|Error::Unauthorized)?;} else {rss_identity_postgres::consume_step_up_on(c,principal.session()?,&input.context(principal,device,*id,*version)?,input.proof.as_ref().ok_or(Error::Unauthorized)?.expose()).await.map_err(|e|match e.kind(){rss_transactional_messaging::error::MessagingErrorKind::Conflict=>Error::Unauthorized,_=>Error::Storage})?;}
                                    }
                                    authorize(profile, c, principal, device, Permission::Credentials)
                                        .await?;
                                    if let Some(input)=access {
                                        let exists=disclosure_receipt(profile, c,principal,device,*id,*version,input.operation_id).await?;
                                        if exists!=*replay{return Err(Error::Conflict);}
                                    }
                                    let (material, key, sealed) = read_locked(service.custody(),
                                        c,
                                        principal.tenant_id(),
                                        device,
                                        *id,
                                        *version,
                                    )
                                    .await?;
                                    if !material.validity.readable() {
                                        return Err(Error::NotFound);
                                    }
                                    if matches!(material.binding.subject,Subject::RssLogin{..})!=access.is_some(){return Err(Error::Forbidden);}
                                    if matches!(material.binding.subject, Subject::RssLogin { .. }) {
                                        let eligibility=service.eligibility.as_ref().ok_or(Error::Unsupported)?;
                                        if eligibility.storage_profile()!=profile { return Err(Error::Forbidden.into()); }
                                        eligibility.disclose(c, principal, &material.binding).await?;
                                    }
                                    let coordinates = Coordinates { profile,
                                        tenant: Uuid::parse_str(principal.tenant_id())
                                            .map_err(|_| Error::Malformed)?,
                                        material: *id,
                                        binding: material.binding.clone(),
                                        version: *version,
                                    };
                                    let secret = service.keys.open(
                                        &key.ok_or(Error::NotFound)?,
                                        &coordinates,
                                        &sealed.ok_or(Error::NotFound)?,
                                    )?;
                                    let value = std::str::from_utf8(secret.expose())
                                        .map_err(|_| Error::Integrity)?;
                                    principal.check_live()?;
                                    if let Some(input)=access && !*replay {
                                        sqlx::query(crate::storage_profile::sql(profile).service_disclose_inner_1).bind(principal.tenant_id()).bind(principal.principal_id()).bind(input.operation_id).bind(*device).bind(*id).bind(*version).execute(c).await?;
                                    }
                                    Ok::<_, Error>(Disclosure {
                                        material,
                                        secret: Zeroizing::new(value.to_owned()),
                                    })
                                })
                            })
                            .await?;
                        (if context.8 { Ok(()) } else { context.9.append(tx, &context.6).await })?;
                        context.1.check_live()?;
                        context.5.mark_commit_started();
                        Ok::<_, Error>(response)
                    })
                },
            )
            .await;
        finish(attempt, audit)
    }

    /// Revoke access to a stored version. Endpoint password removal is a separate platform operation.
    pub async fn revoke(
        &self,
        principal: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
        audit: &RequestAudit,
    ) -> Result<Material, Error> {
        let profile = self.profile();

        principal.bind_audit(audit)?;
        audit.set_action(
            "recovery_credential_revoke",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);

        let fact = Fact::business(
            audit,
            &format!("recovery:revoke:{}", audit.request_id()),
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Audit)?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
        let attempt = self
            .audit
            .write(
                rss_request_context::TenantId::parse(principal.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &budget.source_control(),
                (self, principal, device, id, version, audit, fact),
                |context, tx| {
                    Box::pin(async move {
                        let material = tx
                            .with_connection_context(context, |context, c| {
                                Box::pin(async move {
                                    let (service, principal, device, id, version, _, _) = context;
                                    // Read metadata first, then acquire authorization and registration before material locks.
                                    let row = sqlx::query(
                                        crate::storage_profile::sql(profile).service_revoke_1,
                                    )
                                    .bind(principal.tenant_id())
                                    .bind(*device)
                                    .bind(*id)
                                    .bind(*version)
                                    .fetch_optional(&mut *c)
                                    .await?
                                    .ok_or(Error::NotFound)?;
                                    let material = storage::decode(&row)?;
                                    authorize(
                                        profile,
                                        c,
                                        principal,
                                        device,
                                        material.binding.subject.permission(),
                                    )
                                    .await?;
                                    read_locked(
                                        service.custody(),
                                        c,
                                        principal.tenant_id(),
                                        device,
                                        *id,
                                        *version,
                                    )
                                    .await?;
                                    sqlx::query(
                                        crate::storage_profile::sql(profile).service_revoke_2,
                                    )
                                    .bind(principal.tenant_id())
                                    .bind(*id)
                                    .bind(*version)
                                    .execute(&mut *c)
                                    .await?;
                                    sqlx::query(
                                        crate::storage_profile::sql(profile).service_revoke_3,
                                    )
                                    .bind(principal.tenant_id())
                                    .bind(*id)
                                    .bind(*version)
                                    .execute(&mut *c)
                                    .await?;
                                    let row = sqlx::query(
                                        crate::storage_profile::sql(profile).service_revoke_4,
                                    )
                                    .bind(principal.tenant_id())
                                    .bind(*id)
                                    .bind(*version)
                                    .fetch_one(c)
                                    .await?;
                                    storage::decode(&row)
                                })
                            })
                            .await?;
                        context.0.audit.append(tx, &context.6).await?;
                        context.5.mark_commit_started();
                        Ok::<_, Error>(material)
                    })
                },
            )
            .await;
        finish(attempt, audit)
    }
}

async fn configure(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
) -> Result<(), Error> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','4000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(c).await?;
    Ok(())
}
pub(crate) async fn authorize(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
    permission: Permission,
) -> Result<(), Error> {
    p.check_live()?;
    rss_mdm_authorization_service::lock_on(profile, c, p.tenant_id(), p.instance_id()).await?;
    rss_mdm_authorization_service::snapshot_on(profile, c, p.tenant_id(), p.instance_id())
        .await?
        .require(p, permission, Some(device))
        .map_err(|_| Error::Forbidden)?;
    Ok(())
}
async fn read_locked(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
    id: Uuid,
    version: i64,
) -> Result<(Material, Option<String>, Option<Vec<u8>>), Error> {
    let profile = custody.profile();
    if id.is_nil() || version < 1 {
        return Err(Error::Malformed);
    }
    let statement = crate::storage_profile::sql(profile).service_read_locked_1;
    let row = sqlx::query(statement)
        .bind(tenant)
        .bind(device)
        .bind(id)
        .bind(version)
        .fetch_optional(&mut *c)
        .await?
        .ok_or(Error::NotFound)?;
    let material = storage::decode(&row)?;
    storage::active_in(
        custody,
        c,
        Uuid::parse_str(tenant).map_err(|_| Error::Malformed)?,
        &material.binding,
    )
    .await?;
    let row = sqlx::query(crate::storage_profile::sql(profile).service_read_locked_2)
        .bind(tenant)
        .bind(device)
        .bind(id)
        .bind(version)
        .fetch_optional(c)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((
        storage::decode(&row)?,
        row.try_get("key_id")?,
        row.try_get("sealed")?,
    ))
}

pub(crate) fn finish<R>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        R,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
) -> Result<R, Error> {
    attempt.fold(
        |v| {
            audit.mark_committed();
            Ok(v)
        },
        |e| Err(tx_error(e)),
        |e| {
            audit.mark_rolled_back();
            Err(tx_error(e))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |e| Err(tx_error(e)),
    )
}
fn tx_error(value: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match value {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(_) => Error::Audit,
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}

/// One explicitly authorized DA material disclosure. Proof handles never enter its business digest.
pub struct DisclosureRequest {
    pub operation_id: Uuid,
    pub proof: Option<rss_mdm_agent_wire::runtime::Secret>,
}
impl DisclosureRequest {
    pub fn context(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
    ) -> Result<rss_identity_core::step_up::StepUpContext, Error> {
        use sha2::{Digest, Sha256};
        if self.operation_id.is_nil() || id.is_nil() || version < 1 {
            return Err(Error::Malformed);
        }
        p.credentials(device)?;
        p.session()?;
        let bytes = serde_json::to_vec(&(
            "mdm.device_access.disclose.v1",
            p.tenant_id(),
            p.instance_id(),
            p.principal_id(),
            device,
            id,
            version,
            self.operation_id,
        ))
        .map_err(|_| Error::Malformed)?;
        rss_identity_core::step_up::StepUpContext::new(
            "mdm.device_access.disclose".into(),
            Sha256::digest(bytes).into(),
        )
        .map_err(|_| Error::Malformed)
    }
}
async fn disclosure_receipt(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
    id: Uuid,
    version: i64,
    operation: Uuid,
) -> Result<bool, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).service_disclosure_receipt_1)
        .bind(p.tenant_id())
        .bind(p.principal_id())
        .bind(operation)
        .fetch_optional(c)
        .await?;
    if let Some(row) = row {
        if row.try_get::<String, _>("device")? != device
            || row.try_get::<Uuid, _>("entry")? != id
            || row.try_get::<i64, _>("version")? != version
        {
            return Err(Error::Conflict);
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
impl Credentials {
    async fn disclosure_committed(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
        operation: Uuid,
    ) -> Result<bool, Error> {
        let profile = self.profile();

        p.credentials(device)?;
        let mut tx = self.pool.begin().await?;
        configure(profile, &mut tx, p.tenant_id()).await?;
        authorize(profile, &mut tx, p, device, Permission::Credentials).await?;
        let found = disclosure_receipt(profile, &mut tx, p, device, id, version, operation).await?;
        tx.rollback().await?;
        p.check_live()?;
        Ok(found)
    }
    pub async fn disclose_device_access(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
        input: &DisclosureRequest,
        audit: &RequestAudit,
    ) -> Result<Disclosure, Error> {
        audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
            rss_mdm_audit_integration::SensitiveAction::CredentialReveal,
        ));
        input.context(p, device, id, version)?;
        audit.operation(
            input.operation_id,
            "device_access_material_read",
            rss_mdm_audit_integration::AuditIntent::Sensitive(
                rss_mdm_audit_integration::SensitiveAction::CredentialReveal,
            ),
        );
        let replay = self
            .disclosure_committed(p, device, id, version, input.operation_id)
            .await?;
        let result = self
            .disclose_inner(p, device, id, version, Some(input), replay, audit)
            .await;
        match result {
            Ok(value) => Ok(value),
            Err(error) if !replay => {
                // Includes proof races and unknown commit: recover only this committed operation.
                if self
                    .disclosure_committed(p, device, id, version, input.operation_id)
                    .await?
                {
                    self.disclose_inner(p, device, id, version, Some(input), true, audit)
                        .await
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
}
