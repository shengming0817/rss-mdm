use crate::*;
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use sqlx::{PgConnection, PgPool, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Credentials {
    pool: PgPool,
    audit: Arc<AuditStore>,
    keys: Arc<KeyRing>,
    login_admission: Arc<dyn rss_mdm_registration_service::device_access::Admission>,
}
impl Credentials {
    pub fn new(
        pool: PgPool,
        audit: Arc<AuditStore>,
        keys: Arc<KeyRing>,
        login_admission: Arc<dyn rss_mdm_registration_service::device_access::Admission>,
    ) -> Self {
        Self {
            pool,
            audit,
            keys,
            login_admission,
        }
    }
    pub fn keys(&self) -> &Arc<KeyRing> {
        &self.keys
    }

    pub async fn list(
        &self,
        principal: &AuthorizedPrincipal,
        device: &str,
        after: Option<(Uuid, i64)>,
    ) -> Result<Vec<Material>, Error> {
        principal.require(Permission::InventoryRead, Some(device))?;
        let mut tx = self.pool.begin().await?;
        configure(&mut tx, principal.tenant_id()).await?;
        authorize(&mut tx, principal, device, Permission::InventoryRead).await?;
        let (id, version) = after.unwrap_or((Uuid::nil(), 0));
        let rows=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1::uuid AND e.device=$2 AND (e.id,v.version)>($3,$4) ORDER BY e.id,v.version LIMIT 100"))
            .bind(principal.tenant_id()).bind(device).bind(id).bind(version).fetch_all(&mut *tx).await?;
        let values = rows
            .iter()
            .map(storage::decode)
            .collect::<Result<Vec<_>, _>>()?;
        tx.rollback().await?;
        principal.check_live()?;
        Ok(values)
    }

    /// Login plus the existing device Credentials grant is the entire disclosure policy.
    /// No reauthentication window, MFA gate, reason, approval or unlock token is added.
    pub async fn disclose(
        &self,
        principal: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        version: i64,
        audit: &RequestAudit,
    ) -> Result<Disclosure, Error> {
        principal.credentials(device)?;
        principal.bind_audit(audit)?;
        audit.set_action("recovery_credential_read");
        audit.target_device(device);
        let identity = serde_json::to_vec(&(id, version)).map_err(|_| Error::Malformed)?;
        let fact = Fact::business(
            audit,
            &format!("recovery:read:{}", audit.request_id()),
            &identity,
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
                        let response = tx
                            .with_connection_context(context, |context, c| {
                                Box::pin(async move {
                                    let (service, principal, device, id, version, _, _) = context;
                                    lock_publication(c, principal.tenant_id()).await?;
                                    authorize(c, principal, device, Permission::Credentials)
                                        .await?;
                                    let (material, key, sealed) = read_locked(
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
                                    if let Subject::RssLogin{binding,binding_generation,..}=&material.binding.subject {
                                        let tenant=Uuid::parse_str(principal.tenant_id()).map_err(|_|Error::Malformed)?;
                                        let current=rss_mdm_registration_service::device_access::storage::locked_in(c,tenant,*binding).await?;
                                        let selection=service.login_admission.policy(c,tenant,device,current.policy).await?;
                                        if current.generation!=*binding_generation || !selection.configuration.enabled || selection.version!=current.policy_version {return Err(Error::Forbidden);}
                                    }
                                    let coordinates = Coordinates {
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
                                    Ok::<_, Error>(Disclosure {
                                        material,
                                        secret: Zeroizing::new(value.to_owned()),
                                    })
                                })
                            })
                            .await?;
                        context.0.audit.append(tx, &context.6, false).await?;
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
        principal.bind_audit(audit)?;
        audit.set_action("recovery_credential_revoke");
        audit.target_device(device);
        let identity = serde_json::to_vec(&(id, version)).map_err(|_| Error::Malformed)?;
        let fact = Fact::business(
            audit,
            &format!("recovery:revoke:{}", audit.request_id()),
            &identity,
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Audit)?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
        let attempt=self.audit.write(rss_request_context::TenantId::parse(principal.tenant_id()).map_err(|_|Error::Malformed)?,
            &budget.source_control(),(self,principal,device,id,version,audit,fact),|context,tx|Box::pin(async move {
            let material=tx.with_connection_context(context,|context,c|Box::pin(async move {
                let (_,principal,device,id,version,_,_)=context;
                lock_publication(c, principal.tenant_id()).await?;
                // Read metadata first, then acquire authorization and registration before material locks.
                let row=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1::uuid AND e.device=$2 AND e.id=$3 AND v.version=$4")).bind(principal.tenant_id()).bind(*device).bind(*id).bind(*version).fetch_optional(&mut *c).await?.ok_or(Error::NotFound)?;
                let material=storage::decode(&row)?;
                authorize(c,principal,device,material.binding.subject.permission()).await?;
                read_locked(c,principal.tenant_id(),device,*id,*version).await?;
                sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND entry=$2 AND version=$3").bind(principal.tenant_id()).bind(*id).bind(*version).execute(&mut *c).await?;
                sqlx::query("UPDATE mdm_recovery.entries SET current_version=NULL WHERE tenant_id=$1::uuid AND id=$2 AND current_version=$3").bind(principal.tenant_id()).bind(*id).bind(*version).execute(&mut *c).await?;
                let row=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1::uuid AND e.id=$2 AND v.version=$3")).bind(principal.tenant_id()).bind(*id).bind(*version).fetch_one(c).await?;
                storage::decode(&row)
            })).await?;
            context.0.audit.append(tx,&context.6,false).await?;
            context.5.mark_commit_started();
            Ok::<_,Error>(material)
        })).await;
        finish(attempt, audit)
    }
}

async fn configure(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','4000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(c).await?;
    Ok(())
}
// Registration revalidation later takes this publication fence. It must precede
// authorization, matching the background recovery owner and enrollment paths.
async fn lock_publication(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)")
        .bind(tenant)
        .execute(c)
        .await?;
    Ok(())
}

async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
    permission: Permission,
) -> Result<(), Error> {
    p.check_live()?;
    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id()).await?;
    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await?
        .require(p, permission, Some(device))
        .map_err(|_| Error::Forbidden)?;
    Ok(())
}
async fn read_locked(
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
    id: Uuid,
    version: i64,
) -> Result<(Material, Option<String>, Option<Vec<u8>>), Error> {
    if id.is_nil() || version < 1 {
        return Err(Error::Malformed);
    }
    let statement = storage::select_material!(
        " WHERE e.tenant_id=$1::uuid AND e.device=$2 AND e.id=$3 AND v.version=$4 AND NOT e.retired"
    );
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
        c,
        Uuid::parse_str(tenant).map_err(|_| Error::Malformed)?,
        &material.binding,
    )
    .await?;
    let row=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1::uuid AND e.device=$2 AND e.id=$3 AND v.version=$4 AND NOT e.retired FOR UPDATE OF e,v")).bind(tenant).bind(device).bind(id).bind(version).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    Ok((
        storage::decode(&row)?,
        row.try_get("key_id")?,
        row.try_get("sealed")?,
    ))
}

fn finish<R>(
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
