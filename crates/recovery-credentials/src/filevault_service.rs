//! Transport-independent FileVault operations on the existing recovery/audit owners.
use crate::{Error, Protection, filevault as owner};
use owner::Source;
use rss_mdm_agent_wire::filevault as w;
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub struct FilevaultService {
    pool: PgPool,
    audit: Arc<AuditStore>,
    protection: Arc<Protection>,
}
impl FilevaultService {
    pub fn new(pool: PgPool, audit: Arc<AuditStore>, protection: Arc<Protection>) -> Self {
        Self {
            pool,
            audit,
            protection,
        }
    }
    pub async fn configuration(&self, p: &DevicePrincipal) -> Result<w::Configuration, Error> {
        let source = Source::agent(p)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(source.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        rss_mdm_registration_service::device::store::revalidate_management(&mut tx, p).await?;
        let value = owner::configuration(&mut tx, &source, &self.protection).await?;
        tx.rollback().await?;
        Ok(value)
    }
    pub async fn receipt(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
    ) -> Result<Option<w::Receipt>, Error> {
        let source = Source::agent(p)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(source.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        rss_mdm_registration_service::device::store::revalidate_management(&mut tx, p).await?;
        let value = owner::receipt(&mut tx, &source, id).await?;
        tx.rollback().await?;
        Ok(value)
    }
    pub async fn receive(
        &self,
        p: &DevicePrincipal,
        input: &w::Upload,
        audit: &RequestAudit,
    ) -> Result<w::Receipt, Error> {
        let source = Source::agent(p)?;
        audit.set_action(
            "filevault_escrow",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(&source.device);
        let identity = serde_json::to_vec(&(
            source.registration,
            source.generation,
            input.operation_id,
            &input.cms_digest,
            input.custody_id,
            input.custody_epoch,
        ))
        .map_err(|_| Error::Malformed)?;
        let fact = Fact::business(
            audit,
            &format!(
                "filevault:{}:{}:{}",
                source.registration, source.generation, input.operation_id
            ),
            &identity,
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Audit)?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
        let result = self
            .audit
            .write(
                p.tenant(),
                &budget.source_control(),
                (self, p, &source, input, audit, fact),
                |ctx, tx| {
                    Box::pin(async move {
                        let (value,replayed)=tx.with_connection_context(ctx,|ctx,c|Box::pin(async move {
                rss_mdm_registration_service::device::store::revalidate_management(c,ctx.1).await?;
                owner::fence(c,ctx.2.tenant).await?;
                let replayed=owner::receipt(c,ctx.2,ctx.3.operation_id).await?.is_some();
                let value=owner::receive(c,ctx.2,ctx.3,&ctx.0.protection).await?;
                Ok::<_,Error>((value,replayed))
            })).await?;
                        ctx.0.audit.append(tx, &ctx.5, replayed).await?;
                        ctx.4.mark_commit_started();
                        Ok::<_, Error>(value)
                    })
                },
            )
            .await;
        crate::service::finish(result, audit)
    }
    pub async fn configure(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        input: &owner::Configure,
        audit: &RequestAudit,
    ) -> Result<w::Configuration, Error> {
        p.require(Permission::SecurityOperate, Some(device))?;
        p.bind_audit(audit)?;
        audit.set_action(
            "filevault_collection_configure",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);
        let source = Source {
            tenant: Uuid::parse_str(p.tenant_id()).map_err(|_| Error::Malformed)?,
            device: device.into(),
            registration: input.registration,
            generation: input.generation,
        };
        let bytes = serde_json::to_vec(input).map_err(|_| Error::Malformed)?;
        let fact = Fact::business(
            audit,
            &format!(
                "filevault:configure:{}:{}:{}",
                source.registration, source.generation, input.operation_id
            ),
            &bytes,
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Audit)?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
        let result = self
            .audit
            .write(
                rss_request_context::TenantId::parse(p.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &budget.source_control(),
                (self, p, &source, input, audit, fact),
                |ctx, tx| {
                    Box::pin(async move {
                        let (value,replayed) = tx
                            .with_connection_context(ctx, |ctx, c| {
                                Box::pin(async move {
                                    crate::service::authorize(
                                        c,
                                        ctx.1,
                                        &ctx.2.device,
                                        Permission::SecurityOperate,
                                    )
                                    .await?;
                                    owner::fence(c,ctx.2.tenant).await?;
                                    let replayed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_recovery.filevault_receipts WHERE tenant_id=$1 AND registration=$2 AND generation=$3 AND operation=$4)")
                                        .bind(ctx.2.tenant).bind(ctx.2.registration).bind(ctx.2.generation).bind(ctx.3.operation_id).fetch_one(&mut *c).await?;
                                    let value=owner::configure(c, ctx.2, ctx.3, &ctx.0.protection).await?;
                                    Ok::<_,Error>((value,replayed))
                                })
                            })
                            .await?;
                        ctx.0.audit.append(tx, &ctx.5, replayed).await?;
                        ctx.1.check_live()?;
                        ctx.4.mark_commit_started();
                        Ok::<_, Error>(value)
                    })
                },
            )
            .await;
        crate::service::finish(result, audit)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Link {
    pub operation_id: Uuid,
    pub other_device: String,
}
impl FilevaultService {
    /// Device owner validates the association on the same transaction as custody reassignment.
    pub async fn link(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        input: &Link,
        audit: &RequestAudit,
    ) -> Result<w::Configuration, Error> {
        if input.operation_id.is_nil()
            || input.other_device == device
            || input.other_device.is_empty()
            || input.other_device.len() > 256
            || input.other_device.chars().any(char::is_control)
        {
            return Err(Error::Malformed);
        }
        p.require(Permission::SecurityOperate, Some(device))?;
        p.require(Permission::SecurityOperate, Some(&input.other_device))?;
        p.bind_audit(audit)?;
        audit.set_action(
            "filevault_custody_link",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);
        let bytes = serde_json::to_vec(&(device, input)).map_err(|_| Error::Malformed)?;
        let fact = Fact::business(
            audit,
            &format!("filevault:link:{device}:{}", input.operation_id),
            &bytes,
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Audit)?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
        let result=self.audit.write(rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_|Error::Malformed)?,&budget.source_control(),(self,p,device,input,audit,fact),|ctx,tx|Box::pin(async move {
            let (value,replayed)=tx.with_connection_context(ctx,|ctx,c|Box::pin(async move {
                use sha2::{Digest,Sha256};
                use sqlx::Row;
                crate::service::authorize(c,ctx.1,ctx.2,Permission::SecurityOperate).await?;
                crate::service::authorize(c,ctx.1,&ctx.3.other_device,Permission::SecurityOperate).await?;
                let tenant=rss_request_context::TenantId::parse(ctx.1.tenant_id()).map_err(|_|Error::Malformed)?;
                let object=rss_mdm_device_service::planning::PlanningObjects::paired_in(c,tenant,ctx.2).await?;
                let members=object.members.iter().filter(|m|m.device==ctx.2 || m.device==ctx.3.other_device).collect::<Vec<_>>();
                if members.len()!=2 {return Err(Error::Forbidden);}
                let t=Uuid::parse_str(ctx.1.tenant_id()).map_err(|_|Error::Malformed)?;
                let sources=members.iter().map(|m|Source{tenant:t,device:m.device.clone(),registration:m.registration_id,generation:m.generation}).collect::<Vec<_>>();
                let left=sources.iter().find(|s|s.device==ctx.2).ok_or(Error::Forbidden)?;
                let right=sources.iter().find(|s|s.device==ctx.3.other_device).ok_or(Error::Forbidden)?;
                let digest=Sha256::digest(serde_json::to_vec(&(ctx.2,ctx.3)).map_err(|_|Error::Malformed)?).to_vec();
                if let Some(row)=sqlx::query("SELECT purpose,digest,receipt FROM mdm_recovery.filevault_receipts WHERE tenant_id=$1 AND registration=$2 AND generation=$3 AND operation=$4")
                    .bind(t).bind(left.registration).bind(left.generation).bind(ctx.3.operation_id).fetch_optional(&mut *c).await? {
                    if row.try_get::<String,_>("purpose")?!="link" || row.try_get::<Vec<u8>,_>("digest")?!=digest {return Err(Error::Conflict);}
                    return serde_json::from_value(row.try_get("receipt")?).map(|value|(value,true)).map_err(|_|Error::Integrity);
                }
                let rss_mdm_inventory_service::objects::ObjectRef::Association(association)=object.object else {return Err(Error::Forbidden);};
                owner::merge(c,&ctx.0.protection,left,right,association,object.association_version.ok_or(Error::Forbidden)?).await?;
                let result=owner::configuration(c,left,&ctx.0.protection).await?;
                sqlx::query("INSERT INTO mdm_recovery.filevault_receipts(tenant_id,registration,generation,operation,purpose,digest,receipt) VALUES($1,$2,$3,$4,'link',$5,$6)")
                    .bind(t).bind(left.registration).bind(left.generation).bind(ctx.3.operation_id).bind(digest)
                    .bind(serde_json::to_value(&result).map_err(|_|Error::Malformed)?).execute(c).await?;
                Ok((result,false))
            })).await?;
            ctx.0.audit.append(tx,&ctx.5,replayed).await?;
            ctx.1.check_live()?;ctx.4.mark_commit_started();Ok::<_,Error>(value)
        })).await;
        crate::service::finish(result, audit)
    }
}

#[derive(Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilevaultSelection {
    pub registration: Option<Uuid>,
    pub generation: Option<i64>,
}
impl FilevaultService {
    /// Management readers use their own resource authority, never a device credential or cached revision.
    pub async fn management_configuration(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        selection: &FilevaultSelection,
    ) -> Result<w::Configuration, Error> {
        use sqlx::Row;
        if selection.registration.is_some() != selection.generation.is_some() {
            return Err(Error::Malformed);
        }
        p.require(Permission::SecurityOperate, Some(device))?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(p.tenant_id())
            .execute(&mut *tx)
            .await?;
        crate::service::authorize(&mut tx, p, device, Permission::SecurityOperate).await?;
        let rows=sqlx::query("SELECT id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active' AND purpose='primary' AND channel IN('agent','mdm') AND ($3::uuid IS NULL OR id=$3) AND ($4::bigint IS NULL OR generation=$4) ORDER BY id LIMIT 2")
            .bind(p.tenant_id()).bind(device).bind(selection.registration).bind(selection.generation).fetch_all(&mut *tx).await?;
        if rows.len() != 1 {
            return Err(Error::Conflict);
        }
        let source = Source {
            tenant: Uuid::parse_str(p.tenant_id()).map_err(|_| Error::Malformed)?,
            device: device.into(),
            registration: rows[0].try_get("id")?,
            generation: rows[0].try_get("generation")?,
        };
        let value = owner::configuration(&mut tx, &source, &self.protection).await?;
        tx.rollback().await?;
        p.check_live()?;
        Ok(value)
    }
}
